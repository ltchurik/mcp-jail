// Package remote connects the proxy to an MCP server over Streamable HTTP.
// The proxy keeps talking line-delimited JSON-RPC: every line written to
// the connection becomes a POST, and whatever the server answers (a JSON
// body or a text/event-stream) comes back as lines, so policy, lock and
// audit apply exactly as they do to a local server.
package remote

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/netguard"
)

const (
	maxBody         = 64 << 20 // one JSON-RPC message, like the proxy's line limit
	defaultProtocol = "2025-03-26"
	maxSessionID    = 256
)

// Options describe the remote server.
type Options struct {
	URL     string
	Headers map[string]string
	Logf    func(format string, args ...any)
	// Observe is told about protocol trouble (an HTTP error, an unusable
	// body, a lost session) so it can be audited. May be nil.
	Observe func(reason string)
	// Egress, when set, is asked before each POST whether n more bytes may
	// leave; a no fails the message as over budget.
	Egress func(n int) bool
}

// Conn is one connection to a remote server: a writer for the proxy's
// server-bound lines and a reader for what comes back.
type Conn struct {
	url     *url.URL
	headers map[string]string
	client  *http.Client
	logf    func(string, ...any)
	observe func(string)
	egress  func(int) bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// initc closes once the first initialize exchange is over, so requests
	// the client sends right behind initialize wait for the session id
	// instead of reaching the server without one.
	initc    chan struct{}
	initOnce sync.Once

	outR *io.PipeReader
	outW *io.PipeWriter
	wmu  sync.Mutex // one line at a time into outW

	mu        sync.Mutex
	inbuf     []byte // partial line from Write
	session   string
	protocol  string
	lastEvent string
	lost      bool // the server said the session is gone
	listening bool
	closed    bool
}

// Dial prepares a connection. Nothing is sent until the proxy writes.
func Dial(o Options) (*Conn, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("remote: %q is not an http(s) URL", o.URL)
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Observe == nil {
		o.Observe = func(string) {}
	}
	dialer := netguard.Dialer(10*time.Second, allowedFor(u.Hostname()))
	tr := &http.Transport{
		Proxy:                 nil, // the host's HTTP_PROXY does not apply to the jail
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{url: u, headers: o.Headers, logf: o.Logf, observe: o.Observe, egress: o.Egress, ctx: ctx, cancel: cancel, initc: make(chan struct{})}
	c.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		// A redirect would carry the headers to another host. Refuse.
		return http.ErrUseLastResponse
	}}
	c.outR, c.outW = io.Pipe()
	return c, nil
}

// allowedFor builds the netguard exception for the server's own host: a
// literal address is dialled as given (loopback and private ranges
// included, the user typed it), "localhost" may resolve to loopback, and
// a public name must not resolve into a special range.
func allowedFor(host string) func(ip string) bool {
	lit := net.ParseIP(host)
	loop := isLoopbackName(host)
	return func(ip string) bool {
		pip := net.ParseIP(ip)
		switch {
		case pip == nil:
			return false
		case lit != nil:
			return lit.Equal(pip)
		case loop:
			return pip.IsLoopback()
		}
		return false
	}
}

func isLoopbackName(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ServerIn is where the proxy writes lines for the server.
func (c *Conn) ServerIn() io.Writer { return c }

// ServerOut is where the proxy reads the server's lines.
func (c *Conn) ServerOut() io.Reader { return c.outR }

// Write accepts line-delimited JSON-RPC and POSTs each complete line.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.inbuf = append(c.inbuf, p...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(c.inbuf, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimSpace(c.inbuf[:i])
		c.inbuf = c.inbuf[i+1:]
		if len(line) > 0 {
			lines = append(lines, append([]byte(nil), line...))
		}
	}
	c.mu.Unlock()
	for _, line := range lines {
		c.wg.Add(1)
		go func(line []byte) {
			defer c.wg.Done()
			c.post(line)
		}(line)
	}
	return len(p), nil
}

// Close stops everything, ends the session on the server (best effort) and
// closes the reader the proxy is draining.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	session := c.session
	c.mu.Unlock()
	c.cancel()
	_ = c.outW.Close()
	c.wg.Wait()
	if session != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url.String(), nil)
		if err == nil {
			c.setHeaders(req, session, "")
			if resp, err := c.client.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
	c.client.CloseIdleConnections()
	return nil
}

func (c *Conn) setHeaders(req *http.Request, session, protocol string) {
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	if protocol != "" {
		req.Header.Set("MCP-Protocol-Version", protocol)
	}
}

func (c *Conn) state() (session, protocol string, lost bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session, c.protocol, c.lost
}

// post sends one line and turns the answer into lines for the proxy.
func (c *Conn) post(line []byte) {
	m, _ := jsonrpc.Parse(line) // the proxy already validated it; nil only for odd input
	isReq := m != nil && m.IsRequest()
	isInit := m != nil && m.Method == "initialize"
	if isInit {
		defer c.initOnce.Do(func() { close(c.initc) })
	} else {
		c.awaitInit()
	}
	session, protocol, lost := c.state()
	if lost && !isInit {
		c.fail(m, "remote session expired; restart the client")
		return
	}
	if c.egress != nil && !c.egress(len(line)) {
		c.fail(m, "egress budget exceeded (limits.egress_bytes)")
		return
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url.String(), bytes.NewReader(line))
	if err != nil {
		c.fail(m, "remote: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if isInit {
		session = "" // a new session starts without one
	}
	c.setHeaders(req, session, protocol)
	resp, err := c.client.Do(req)
	if err != nil {
		if c.ctx.Err() == nil {
			c.fail(m, "remote: "+err.Error())
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		if isReq {
			c.fail(m, fmt.Sprintf("remote answered a request with HTTP %d and no body", resp.StatusCode))
		}
		return
	case resp.StatusCode == http.StatusNotFound && session != "":
		c.sessionLost()
		c.fail(m, "remote session expired (HTTP 404); restart the client")
		return
	case resp.StatusCode/100 != 2:
		c.fail(m, fmt.Sprintf("remote returned HTTP %d", resp.StatusCode))
		return
	}
	if isInit {
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			if validSession(sid) {
				c.mu.Lock()
				c.session, c.lost = sid, false
				c.mu.Unlock()
			} else {
				c.observe("remote sent an unusable Mcp-Session-Id; ignored")
				c.logf("remote: unusable session id ignored")
			}
		}
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	answered := false
	switch ct {
	case "application/json":
		body, err := readAll(resp.Body)
		if err != nil {
			c.fail(m, "remote: "+err.Error())
			return
		}
		answered = c.deliver(body, m)
	case "text/event-stream":
		answered = c.readStream(resp.Body, m)
	default:
		c.fail(m, "remote answered with content type "+strings.TrimSpace(resp.Header.Get("Content-Type")))
		return
	}
	if isReq && !answered && c.ctx.Err() == nil {
		c.fail(m, "remote closed the stream before answering "+m.Method)
	}
}

// deliver pushes one body (a message or a batch) to the proxy; it reports
// whether the request m was answered by it. The initialize answer also
// fixes the protocol version and starts the server-initiated stream.
func (c *Conn) deliver(body []byte, m *jsonrpc.Message) (answered bool) {
	body = bytes.TrimSpace(body)
	var msgs [][]byte
	if len(body) > 0 && body[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(body, &batch); err != nil {
			c.observe("remote: unparsable batch: " + err.Error())
			c.logf("remote: unparsable batch dropped")
			return false
		}
		for _, b := range batch {
			msgs = append(msgs, b)
		}
	} else {
		msgs = [][]byte{body}
	}
	for _, raw := range msgs {
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			c.observe("remote: unparsable message: " + err.Error())
			c.logf("remote: unparsable message dropped")
			continue
		}
		line := compact.Bytes()
		var initResp *jsonrpc.Message
		if r, err := jsonrpc.Parse(line); err == nil && m != nil && r.IsResponse() && r.IDKey() == m.IDKey() {
			answered = true
			if m.Method == "initialize" {
				initResp = r
			}
		}
		c.push(line)
		if initResp != nil {
			// only after the answer is on its way: a notification from the
			// server stream must not reach the client before it
			c.initialized(initResp)
		}
	}
	return answered
}

// initialized records the negotiated protocol version and opens the
// server-initiated stream once a session exists.
func (c *Conn) initialized(r *jsonrpc.Message) {
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(r.Result, &res)
	proto := defaultProtocol
	if v := res.ProtocolVersion; v != "" && len(v) <= 32 && !hasControl(v) {
		proto = v
	}
	c.mu.Lock()
	c.protocol = proto
	start := !c.listening && !c.closed
	c.listening = true
	c.mu.Unlock()
	if start {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.listen()
		}()
	}
}

// listen keeps a GET stream open for messages the server sends on its own
// (list_changed notifications, sampling requests). A server without one
// answers 405 and is left alone.
func (c *Conn) listen() {
	backoff := time.Second
	for c.ctx.Err() == nil {
		session, protocol, lost := c.state()
		if lost {
			return
		}
		req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.url.String(), nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		c.setHeaders(req, session, protocol)
		c.mu.Lock()
		if c.lastEvent != "" {
			req.Header.Set("Last-Event-ID", c.lastEvent)
		}
		c.mu.Unlock()
		resp, err := c.client.Do(req)
		if err != nil {
			if !c.sleep(backoff) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		switch {
		case resp.StatusCode == http.StatusNotFound && session != "":
			_ = resp.Body.Close()
			c.sessionLost()
			return
		case resp.StatusCode != http.StatusOK || ct != "text/event-stream":
			_ = resp.Body.Close()
			return // no server-initiated stream here
		}
		c.readStream(resp.Body, nil)
		_ = resp.Body.Close()
		backoff = time.Second
		if !c.sleep(backoff) {
			return
		}
	}
}

// awaitInit holds a message until the initialize exchange is over. A client
// that never initializes is let through after a while; the server will
// refuse it, and that refusal reaches the client as an error.
func (c *Conn) awaitInit() {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	select {
	case <-c.initc:
	case <-c.ctx.Done():
	case <-t.C:
	}
}

func (c *Conn) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// readStream parses a text/event-stream and delivers every data payload.
// It reports whether m (may be nil) was answered on this stream.
func (c *Conn) readStream(r io.Reader, m *jsonrpc.Message) (answered bool) {
	br := bufio.NewReaderSize(r, 64<<10)
	var data []byte
	var id string
	size := 0
	dispatch := func() {
		if len(data) > 0 {
			if c.deliver(data, m) {
				answered = true
			}
		}
		if id != "" {
			c.mu.Lock()
			c.lastEvent = id
			c.mu.Unlock()
		}
		data, id, size = nil, "", 0
	}
	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			dispatch()
			return answered
		}
		line = bytes.TrimRight(line, "\r\n")
		switch {
		case len(line) == 0:
			dispatch()
		case line[0] == ':':
			// comment / keep-alive
		default:
			field, value, _ := bytes.Cut(line, []byte(":"))
			value = bytes.TrimPrefix(value, []byte(" "))
			switch string(field) {
			case "data":
				size += len(value) + 1
				if size > maxBody {
					c.observe("remote: event larger than 64 MiB dropped")
					c.logf("remote: oversized event dropped")
					return answered
				}
				if data != nil {
					data = append(data, '\n')
				}
				data = append(data, value...)
			case "id":
				if validSession(string(value)) { // same alphabet and bound
					id = string(value)
				}
			}
		}
		if err != nil {
			dispatch()
			return answered
		}
	}
}

// fail tells the proxy that the request m (if it was one) will not be
// answered by the server, and records why.
func (c *Conn) fail(m *jsonrpc.Message, why string) {
	c.observe(why)
	c.logf("%s", why)
	if m != nil && m.IsRequest() {
		c.push(jsonrpc.NewErrorResponse(m.ID, jsonrpc.CodeRemote, "mcp-jail: "+why))
	}
}

func (c *Conn) sessionLost() {
	c.mu.Lock()
	first := !c.lost
	c.lost = true
	c.mu.Unlock()
	if first {
		c.observe("remote session expired (HTTP 404)")
		c.logf("remote: the server no longer knows this session; restart the client to start a new one")
	}
}

func (c *Conn) push(line []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, _ = c.outW.Write(append(line, '\n'))
}

func readAll(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("response larger than 64 MiB")
	}
	return b, nil
}

// validSession accepts what the spec allows for Mcp-Session-Id: visible
// ASCII, bounded.
func validSession(s string) bool {
	if s == "" || len(s) > maxSessionID {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
