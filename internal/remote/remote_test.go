package remote

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
)

// fake is a Streamable HTTP server: initialize answers JSON with a session
// id, tools/list answers on an SSE stream (a notification, then the
// response), tools/call checks the headers and answers JSON, ping fails,
// notifications get 202. GET serves one notification, then 405.
type fake struct {
	t       *testing.T
	mu      sync.Mutex
	seen    []string // "METHOD session proto auth"
	gets    atomic.Int32
	deletes atomic.Int32
	expire  atomic.Bool // answer 404 to any request carrying a session
}

func (f *fake) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, fmt.Sprintf("%s %s %s %s", r.Method, r.Header.Get("Mcp-Session-Id"), r.Header.Get("MCP-Protocol-Version"), r.Header.Get("Authorization")))
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.expire.Load() && r.Header.Get("Mcp-Session-Id") != "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		f.deletes.Add(1)
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet:
		if f.gets.Add(1) > 1 {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, ": hello\nid: 7\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		return
	}
	body, _ := io.ReadAll(r.Body)
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &m)
	if len(m.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	id := string(m.ID)
	if m.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != "sess-1" {
		w.WriteHeader(http.StatusNotFound) // no session: the spec's answer
		return
	}
	switch m.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "{\n  \"jsonrpc\": \"2.0\", \"id\": %s, \"result\": {\"protocolVersion\": \"2025-06-18\"}\n}", id)
	case "tools/list":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\n")
		_, _ = fmt.Fprint(w, "data:  \"params\":{\"level\":\"info\"}}\n\n")
		_, _ = fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n\n", id)
	case "tools/call":
		if r.Header.Get("Mcp-Session-Id") != "sess-1" || r.Header.Get("MCP-Protocol-Version") != "2025-06-18" || r.Header.Get("Authorization") != "Bearer t" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "[{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}]", id) // a batch of one
	case "ping":
		w.WriteHeader(http.StatusInternalServerError)
	case "redirect":
		http.Redirect(w, r, "https://evil.example/mcp", http.StatusFound)
	case "silent":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, ": nothing\n\n")
	case "html":
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<h1>nope</h1>")
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}", id)
	}
}

type harness struct {
	t    *testing.T
	f    *fake
	c    *Conn
	out  *bufio.Reader
	obs  []string
	omu  sync.Mutex
	done chan struct{}
}

func start(t *testing.T) *harness {
	t.Helper()
	f := &fake{t: t}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	h := &harness{t: t, f: f, done: make(chan struct{})}
	c, err := Dial(Options{URL: srv.URL + "/mcp", Headers: map[string]string{"Authorization": "Bearer t"}, Logf: t.Logf,
		Observe: func(r string) { h.omu.Lock(); h.obs = append(h.obs, r); h.omu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	h.c, h.out = c, bufio.NewReader(c.ServerOut())
	t.Cleanup(func() { _ = c.Close() })
	return h
}

func (h *harness) send(line string) {
	h.t.Helper()
	if _, err := io.WriteString(h.c.ServerIn(), line+"\n"); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) next() *jsonrpc.Message {
	h.t.Helper()
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() { l, err := h.out.ReadString('\n'); ch <- res{l, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatal(r.err)
		}
		m, err := jsonrpc.Parse([]byte(strings.TrimSpace(r.line)))
		if err != nil {
			h.t.Fatalf("%v: %s", err, r.line)
		}
		return m
	case <-time.After(5 * time.Second):
		h.t.Fatal("no line from the remote connection")
		return nil
	}
}

func TestRoundTrip(t *testing.T) {
	h := start(t)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	m := h.next()
	if !m.IsResponse() || m.IDKey() != "1" || !strings.Contains(string(m.Result), "2025-06-18") {
		t.Fatalf("initialize: %s", m.Raw)
	}
	h.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`) // 202, nothing back
	// the GET stream delivers the server's own notification
	if m := h.next(); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("expected the GET stream notification, got %s", m.Raw)
	}
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if m := h.next(); m.Method != "notifications/message" || !strings.Contains(string(m.Params), `"info"`) {
		t.Fatalf("expected the multi-line SSE notification, got %s", m.Raw)
	}
	if m := h.next(); m.IDKey() != "2" || !strings.Contains(string(m.Result), `"a"`) {
		t.Fatalf("tools/list: %s", m.Raw)
	}
	h.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"a"}}`)
	if m := h.next(); m.IDKey() != "3" || m.Error != nil {
		t.Fatalf("tools/call (headers, batch): %s", m.Raw)
	}
	if err := h.c.Close(); err != nil {
		t.Fatal(err)
	}
	if h.f.deletes.Load() != 1 {
		t.Fatalf("expected one DELETE, got %d", h.f.deletes.Load())
	}
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	for _, s := range h.f.seen {
		if strings.HasPrefix(s, "POST") && !strings.Contains(s, "Bearer t") {
			t.Errorf("request without the policy header: %s", s)
		}
	}
	if !strings.HasPrefix(h.f.seen[0], "POST   Bearer t") {
		t.Errorf("initialize must carry no session and no protocol header: %q", h.f.seen[0])
	}
}

func TestBurstAfterInitializeWaitsForSession(t *testing.T) {
	h := start(t)
	// a client that does not wait for the initialize response before listing
	h.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	h.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	got := map[string]bool{}
	for i := 0; i < 4; i++ {
		m := h.next()
		if m.Error != nil {
			t.Fatalf("unexpected error: %s", m.Raw)
		}
		if m.IsResponse() {
			got[m.IDKey()] = true
		}
	}
	if !got["1"] || !got["2"] {
		t.Fatalf("expected answers to 1 and 2, got %v", got)
	}
}

func TestFailuresBecomeErrorResponses(t *testing.T) {
	h := start(t)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	h.next()
	h.next() // GET notification
	cases := map[string]string{
		"ping":     "HTTP 500",
		"redirect": "HTTP 302",
		"silent":   "closed the stream before answering",
		"html":     "content type text/html",
	}
	id := 10
	for method, want := range cases {
		id++
		h.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"%s"}`, id, method))
		m := h.next()
		if m.Error == nil || m.Error.Code != jsonrpc.CodeRemote || !strings.Contains(m.Error.Message, want) || m.IDKey() != fmt.Sprint(id) {
			t.Errorf("%s: %s", method, m.Raw)
		}
	}
	h.omu.Lock()
	n := len(h.obs)
	h.omu.Unlock()
	if n < len(cases) {
		t.Errorf("expected every failure observed, got %d", n)
	}
}

func TestSessionExpiry(t *testing.T) {
	h := start(t)
	h.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	h.next()
	h.next()
	h.f.expire.Store(true)
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	m := h.next()
	if m.Error == nil || !strings.Contains(m.Error.Message, "session expired") {
		t.Fatalf("expired: %s", m.Raw)
	}
	// later requests fail without touching the server; initialize starts over
	before := len(h.f.seen)
	h.send(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if m := h.next(); m.Error == nil || !strings.Contains(m.Error.Message, "session expired") {
		t.Fatalf("after expiry: %s", m.Raw)
	}
	h.f.mu.Lock()
	after := len(h.f.seen)
	h.f.mu.Unlock()
	if after != before {
		t.Fatalf("a dead session must not be retried on the wire (%d requests)", after-before)
	}
	h.f.expire.Store(false)
	h.send(`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`)
	if m := h.next(); m.Error != nil {
		t.Fatalf("re-initialize: %s", m.Raw)
	}
}

func TestAllowedFor(t *testing.T) {
	cases := []struct {
		host, ip string
		want     bool
	}{
		{"localhost", "127.0.0.1", true}, {"localhost", "::1", true}, {"localhost", "10.0.0.1", false},
		{"127.0.0.1", "127.0.0.1", true}, {"10.1.2.3", "10.1.2.3", true}, {"10.1.2.3", "10.1.2.4", false},
		{"mcp.example.com", "10.0.0.1", false}, {"mcp.example.com", "127.0.0.1", false}, {"mcp.example.com", "93.184.216.34", false},
	}
	for _, c := range cases {
		if got := allowedFor(c.host)(c.ip); got != c.want {
			t.Errorf("allowedFor(%s)(%s) = %v", c.host, c.ip, got)
		}
	}
	// a public name may resolve anywhere public: netguard only consults the
	// exception for special ranges, so false here means "no exception"
}

func TestValidSession(t *testing.T) {
	if !validSession("abc-123") || validSession("") || validSession("a b") || validSession(strings.Repeat("x", 257)) || validSession("é") {
		t.Fatal("validSession")
	}
}
