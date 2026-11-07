// Package limits holds the budgets a policy puts on a server: how many
// tools/call per window, how many bytes of arguments, how many bytes out
// to the network. A budget is a token bucket: the window's worth of tokens
// is available at once and refills continuously, so a burst up to the
// limit passes and a steady drip above it does not. A budget that cannot
// be met (a single call larger than the whole window) is a deny.
package limits

import (
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Rate is "<count>[unit]/<window>": 60/1m, 10MB/1h, 500KB/30s, 100/1d.
// Units KB, MB, GB are 1024-based; a bare number is a count (or bytes).
type Rate struct {
	N     int64
	Per   time.Duration
	Bytes bool // rendered with a unit
}

// Zero reports an unset rate (no limit).
func (r Rate) Zero() bool { return r.N == 0 || r.Per == 0 }

func (r Rate) String() string {
	if r.Zero() {
		return "none"
	}
	n := strconv.FormatInt(r.N, 10)
	if r.Bytes {
		n = bytesString(r.N)
	}
	return n + "/" + durString(r.Per)
}

var rateRe = regexp.MustCompile(`^(\d+)\s*([KMG]i?B|B)?\s*/\s*(\d+)\s*(ms|s|m|h|d)$`)

// ParseRate reads a Rate; "" is the zero Rate.
func ParseRate(s string) (Rate, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "none" || s == "0" {
		return Rate{}, nil
	}
	m := rateRe.FindStringSubmatch(s)
	if m == nil {
		return Rate{}, fmt.Errorf("%q is not <count>[KB|MB|GB]/<window>, e.g. 60/1m or 10MB/1h", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n <= 0 {
		return Rate{}, fmt.Errorf("%q: count must be a positive integer", s)
	}
	r := Rate{N: n, Bytes: m[2] != ""}
	switch strings.TrimSuffix(strings.TrimSuffix(m[2], "B"), "i") {
	case "K":
		r.N = n << 10
	case "M":
		r.N = n << 20
	case "G":
		r.N = n << 30
	}
	w, _ := strconv.ParseInt(m[3], 10, 64)
	if w <= 0 {
		return Rate{}, fmt.Errorf("%q: window must be positive", s)
	}
	switch m[4] {
	case "ms":
		r.Per = time.Duration(w) * time.Millisecond
	case "s":
		r.Per = time.Duration(w) * time.Second
	case "m":
		r.Per = time.Duration(w) * time.Minute
	case "h":
		r.Per = time.Duration(w) * time.Hour
	case "d":
		r.Per = time.Duration(w) * 24 * time.Hour
	}
	if r.Per > 30*24*time.Hour {
		return Rate{}, fmt.Errorf("%q: window must be at most 30d", s)
	}
	return r, nil
}

// UnmarshalYAML accepts the string form.
func (r *Rate) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseRate(s)
	if err != nil {
		return err
	}
	*r = v
	return nil
}

func bytesString(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return strconv.FormatInt(n>>30, 10) + "GB"
	case n >= 1<<20 && n%(1<<20) == 0:
		return strconv.FormatInt(n>>20, 10) + "MB"
	case n >= 1<<10 && n%(1<<10) == 0:
		return strconv.FormatInt(n>>10, 10) + "KB"
	}
	return strconv.FormatInt(n, 10) + "B"
}

func durString(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	}
	return d.String()
}

// bucket is a token bucket refilled continuously at rate.N per rate.Per.
type bucket struct {
	mu     sync.Mutex
	rate   Rate
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(r Rate, now func() time.Time) *bucket {
	return &bucket{rate: r, tokens: float64(r.N), last: now(), now: now}
}

// take consumes n tokens if they are all there; n == 0 asks whether at
// least one token is left.
func (b *bucket) take(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	if d := t.Sub(b.last); d > 0 {
		b.tokens += float64(b.rate.N) * (float64(d) / float64(b.rate.Per))
		if b.tokens > float64(b.rate.N) {
			b.tokens = float64(b.rate.N)
		}
	}
	b.last = t
	if n == 0 {
		return b.tokens >= 1
	}
	if float64(n) > b.tokens {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Limiter enforces the budgets of one jail. A nil *Limiter allows all.
type Limiter struct {
	calls, args, egress *bucket
	tools               map[string]*bucket // by rule pattern
	// OnEgress is told once per refused connection or write (host and why).
	OnEgress func(host, why string)
	egressR  Rate
}

// New builds a Limiter; a zero Rate means no limit on that budget. tools
// maps rule patterns (exact tool names or globs) to their rates; the
// caller resolves which pattern governs a call.
func New(calls, args, egress Rate, tools map[string]Rate, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	l := &Limiter{tools: map[string]*bucket{}, egressR: egress}
	if !calls.Zero() {
		l.calls = newBucket(calls, now)
	}
	if !args.Zero() {
		l.args = newBucket(args, now)
	}
	if !egress.Zero() {
		l.egress = newBucket(egress, now)
	}
	for pat, r := range tools {
		if !r.Zero() {
			l.tools[pat] = newBucket(r, now)
		}
	}
	return l
}

// Call charges one tools/call of argBytes bytes under the per-tool pattern
// (or "" for none). It returns "" when every budget had room, otherwise
// the one that did not. Nothing is charged on a refusal.
func (l *Limiter) Call(pattern string, argBytes int) string {
	if l == nil {
		return ""
	}
	var charged []*bucket
	undo := func() {
		for _, b := range charged {
			b.mu.Lock()
			b.tokens += 1
			b.mu.Unlock()
		}
	}
	if l.calls != nil {
		if !l.calls.take(1) {
			return "limit: calls " + l.calls.rate.String() + " exceeded"
		}
		charged = append(charged, l.calls)
	}
	if b := l.tools[pattern]; b != nil {
		if !b.take(1) {
			undo()
			return "limit: tools[" + pattern + "] " + b.rate.String() + " exceeded"
		}
		charged = append(charged, b)
	}
	if l.args != nil && !l.args.take(int64(argBytes)) {
		undo()
		return "limit: args_bytes " + l.args.rate.String() + " exceeded"
	}
	return ""
}

// ErrBudget is what a metered writer returns once the egress budget is
// spent; the connection it sits on ends.
var ErrBudget = errors.New("egress budget exceeded")

// Egress charges n bytes leaving towards host; n == 0 asks whether a new
// connection may start at all. A refusal is reported to OnEgress.
func (l *Limiter) Egress(host string, n int64) bool {
	if l == nil || l.egress == nil {
		return true
	}
	if l.egress.take(n) {
		return true
	}
	if l.OnEgress != nil {
		l.OnEgress(host, "egress_bytes "+l.egressR.String()+" exceeded")
	}
	return false
}

// Wrap meters what is written to c (bytes leaving towards host): a write
// past the budget fails with ErrBudget. c is returned as is when there is
// no egress budget.
func (l *Limiter) Wrap(c net.Conn, host string) net.Conn {
	if l == nil || l.egress == nil {
		return c
	}
	return &conn{Conn: c, l: l, host: host}
}

type conn struct {
	net.Conn
	l    *Limiter
	host string
}

func (c *conn) Write(p []byte) (int, error) {
	if !c.l.Egress(c.host, int64(len(p))) {
		return 0, ErrBudget
	}
	return c.Conn.Write(p)
}

// CloseWrite half-closes when the underlying connection can.
func (c *conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// Reader meters what is read from r (a request body on its way out).
func (l *Limiter) Reader(r io.Reader, host string) io.Reader {
	if l == nil || l.egress == nil {
		return r
	}
	return &reader{Reader: r, l: l, host: host}
}

type reader struct {
	io.Reader
	l    *Limiter
	host string
}

func (r *reader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 && !r.l.Egress(r.host, int64(n)) {
		return 0, ErrBudget
	}
	return n, err
}
