// Package control is the per-jail control channel: a Unix socket next to
// the registry entry over which the dashboard sees the `ask` decisions a
// jail is waiting for and answers them.
//
// The socket is owned by the user (0600 in a 0700 directory), so only
// processes of the same user can connect. The proxy keeps enforcing the
// policy: an answer here is one of the inputs to a decision, a missing
// answer is a deny.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Pending is one `ask` waiting for a decision.
type Pending struct {
	ID        string          `json:"id"`
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Since     time.Time       `json:"since"`
	Deadline  time.Time       `json:"deadline"`
	done      chan Decision
}

// Decision is an answer to a Pending.
type Decision struct {
	Allow bool   `json:"allow"`
	By    string `json:"by"` // who answered, e.g. "dashboard"
}

// attachedWindow is how recent a poll must be for a dashboard to count as
// attached; while one is, the proxy waits for it instead of denying at once.
const attachedWindow = 5 * time.Second

// Broker holds the pending asks of one jail.
type Broker struct {
	Server   string
	mu       sync.Mutex
	pending  map[string]*Pending
	seq      uint64
	lastPoll atomic.Int64 // unix nanos of the last List()
}

// NewBroker returns an empty broker for server.
func NewBroker(server string) *Broker {
	return &Broker{Server: server, pending: map[string]*Pending{}}
}

// Submit registers an ask. Wait on it with Wait; remove it with Remove.
func (b *Broker) Submit(tool string, args json.RawMessage, deadline time.Time) *Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	p := &Pending{ID: strconv.FormatUint(b.seq, 10), Server: b.Server, Tool: tool, Arguments: args,
		Since: time.Now().UTC(), Deadline: deadline.UTC(), done: make(chan Decision, 1)}
	b.pending[p.ID] = p
	return p
}

// Wait blocks until the ask is answered or ctx ends.
func (p *Pending) Wait(ctx context.Context) (Decision, bool) {
	select {
	case d := <-p.done:
		return d, true
	case <-ctx.Done():
		return Decision{}, false
	}
}

// Remove forgets an ask (answered, timed out or otherwise settled).
func (b *Broker) Remove(id string) {
	b.mu.Lock()
	delete(b.pending, id)
	b.mu.Unlock()
}

// List returns the pending asks, oldest first, and marks a dashboard as
// attached.
func (b *Broker) List() []Pending {
	b.lastPoll.Store(time.Now().UnixNano())
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}

// Attached reports whether a dashboard polled recently.
func (b *Broker) Attached() bool {
	return time.Since(time.Unix(0, b.lastPoll.Load())) < attachedWindow
}

// ErrUnknown is returned by Answer for an id that is not pending.
var ErrUnknown = errors.New("no such pending ask")

// Answer resolves an ask. The first answer wins; later ones are ignored.
func (b *Broker) Answer(id string, d Decision) error {
	b.mu.Lock()
	p, ok := b.pending[id]
	b.mu.Unlock()
	if !ok {
		return ErrUnknown
	}
	select {
	case p.done <- d:
	default: // already answered
	}
	return nil
}

// Server serves a Broker over a Unix socket.
type Server struct {
	Broker *Broker
	l      net.Listener
	srv    *http.Server
	path   string
}

// SocketPath is where the control socket of a jail lives.
func SocketPath(dir, name string, pid int) string {
	return filepath.Join(dir, fmt.Sprintf("%s.%d.sock", safe(name), pid))
}

func safe(name string) string {
	var sb strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	if sb.Len() == 0 {
		return "server"
	}
	return sb.String()
}

// maxSocketPath is the portable limit for a Unix socket path (104 bytes on
// macOS and the BSDs, 108 on Linux, minus the terminator).
const maxSocketPath = 100

// Listen creates the socket at path (replacing a stale one) and serves b.
// A path too long for a Unix socket is replaced by one of the same name in
// a per-user directory under the temp dir; Path reports what was used.
func Listen(path string, b *Broker) (*Server, error) {
	if len(path) > maxSocketPath {
		path = filepath.Join(os.TempDir(), fmt.Sprintf("mcp-jail-%d", os.Getuid()), filepath.Base(path))
		if len(path) > maxSocketPath {
			return nil, fmt.Errorf("control: socket path too long even under %s", os.TempDir())
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("control: %w", err)
	}
	s := &Server{Broker: b, l: l, path: path}
	s.srv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(l) }()
	return s, nil
}

// Path is the socket path.
func (s *Server) Path() string { return s.path }

// Close stops serving and removes the socket file.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	_ = os.Remove(s.path)
	return err
}

// Handler exposes the broker for tests and for serving over other listeners.
func (s *Server) handler() http.Handler {
	return Handler(s.Broker)
}

// Handler serves a broker: GET /asks lists, POST /asks/{id} answers with a
// JSON body {"decision":"allow"|"deny","by":"…"}.
func Handler(b *Broker) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /asks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b.List())
	})
	mux.HandleFunc("POST /asks/{id}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Decision string `json:"decision"`
			By       string `json:"by"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		var d Decision
		switch body.Decision {
		case "allow":
			d.Allow = true
		case "deny":
		default:
			http.Error(w, `decision must be "allow" or "deny"`, http.StatusBadRequest)
			return
		}
		d.By = oneWord(body.By)
		if d.By == "" {
			d.By = "control"
		}
		if err := b.Answer(r.PathValue("id"), d); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}` + "\n"))
	})
	return mux
}

func oneWord(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 32 {
		s = s[:32]
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}

// Client talks to one jail's control socket.
type Client struct {
	hc   *http.Client
	path string
}

// Dial returns a client for the socket at path. Requests time out quickly:
// a jail that does not answer is treated as having no asks.
func Dial(path string) *Client {
	return &Client{path: path, hc: &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}},
	}}
}

// List returns the jail's pending asks.
func (c *Client) List(ctx context.Context) ([]Pending, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://jail/asks", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control: status %d", resp.StatusCode)
	}
	var out []Pending
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Answer resolves ask id on the jail.
func (c *Client) Answer(ctx context.Context, id string, allow bool, by string) error {
	dec := "deny"
	if allow {
		dec = "allow"
	}
	body, _ := json.Marshal(map[string]string{"decision": dec, "by": by})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://jail/asks/"+id, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrUnknown
	default:
		return fmt.Errorf("control: status %d", resp.StatusCode)
	}
}
