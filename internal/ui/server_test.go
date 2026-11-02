package ui

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/registry"
)

const tok = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T, extra ...string) *httptest.Server {
	t.Helper()
	t.Setenv("MCP_JAIL_HOME", filepath.Join(t.TempDir(), "locks"))
	s, err := New(tok, "test", extra)
	if err != nil {
		t.Fatal(err)
	}
	s.PollInterval = 20 * time.Millisecond
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, url string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Body.Close() })
	return r
}

// getJSON fetches url and decodes the JSON body into v.
func getJSON(t *testing.T, url string, hdr map[string]string, v any) {
	t.Helper()
	r := get(t, url, hdr)
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d", url, r.StatusCode)
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// status fetches url and returns only the status code.
func status(t *testing.T, url string, hdr map[string]string) int {
	t.Helper()
	r := get(t, url, hdr)
	_ = r.Body.Close()
	return r.StatusCode
}

func TestAuth(t *testing.T) {
	ts := newTestServer(t)
	bearer := map[string]string{"Authorization": "Bearer " + tok}

	for _, p := range []string{"/", "/api/state", "/api/events", "/api/stream", "/static/app.js"} {
		if c := status(t, ts.URL+p, nil); c != http.StatusUnauthorized {
			t.Errorf("%s without token: %d", p, c)
		}
		if c := status(t, ts.URL+p, map[string]string{"Authorization": "Bearer wrong"}); c != http.StatusUnauthorized {
			t.Errorf("%s wrong bearer: %d", p, c)
		}
	}
	if c := status(t, ts.URL+"/?token=wrong", nil); c != http.StatusUnauthorized {
		t.Errorf("wrong ?token: %d", c)
	}
	// ?token= exchanges for a cookie and redirects to /
	r := get(t, ts.URL+"/?token="+tok, nil)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("token exchange: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	var ck *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == cookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Value != tok {
		t.Fatalf("cookie: %+v", ck)
	}
	r = get(t, ts.URL+"/", map[string]string{"Cookie": cookieName + "=" + tok})
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK || !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("index with cookie: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing: %q", csp)
	}
	r = get(t, ts.URL+"/api/state", bearer)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("bearer: %d %q", r.StatusCode, r.Header.Get("Cache-Control"))
	}
	// cross-site fetch is refused even with a valid credential
	if c := status(t, ts.URL+"/api/state", map[string]string{"Authorization": "Bearer " + tok, "Sec-Fetch-Site": "cross-site"}); c != http.StatusForbidden {
		t.Errorf("cross-site: %d", c)
	}
	if c := status(t, ts.URL+"/api/state", map[string]string{"Authorization": "Bearer " + tok, "Sec-Fetch-Site": "same-origin"}); c != http.StatusOK {
		t.Errorf("same-origin: %d", c)
	}
	// DNS rebinding: a foreign Host header is refused before auth
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/state", nil)
	req.Host = "evil.example"
	req.Header.Set("Authorization", "Bearer "+tok)
	fr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = fr.Body.Close()
	if fr.StatusCode != http.StatusForbidden {
		t.Errorf("foreign host: %d", fr.StatusCode)
	}
	r = get(t, ts.URL+"/static/app.js", bearer)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK || !strings.Contains(r.Header.Get("Content-Type"), "javascript") {
		t.Errorf("static: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if _, err := New("short", "v", nil); err == nil {
		t.Error("short token accepted")
	}
}

func TestListenLoopbackOnly(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:0", ":0", "192.168.1.10:0", "nonsense"} {
		if l, err := Listen(bad); err == nil {
			_ = l.Close()
			t.Errorf("Listen(%q) accepted", bad)
		}
	}
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	s, _ := New(tok, "v", nil)
	u := s.URL(l)
	if !strings.HasPrefix(u, "http://127.0.0.1:") || !strings.HasSuffix(u, "/?token="+tok) {
		t.Fatalf("URL: %s", u)
	}
	if l6, err := Listen("[::1]:0"); err == nil {
		if u := s.URL(l6); !strings.HasPrefix(u, "http://[::1]:") {
			t.Errorf("v6 URL: %s", u)
		}
		_ = l6.Close()
	}
}

func TestStateAndEvents(t *testing.T) {
	ts := newTestServer(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "demo.jsonl")
	l, _ := audit.Open(auditPath, "demo")
	l.Log(audit.Event{Kind: "start", Reason: "no sandbox"})
	l.Log(audit.Event{Kind: "tool_call", Tool: "read_file", Decision: "allow"})
	l.Log(audit.Event{Kind: "tool_call", Tool: "rm", Decision: "deny", Reason: "policy"})
	l.Log(audit.Event{Kind: "net", Host: "evil.example", Decision: "blocked"})
	_ = l.Close()

	unreg, err := registry.Register(registry.Entry{Name: "demo", Policy: "/p.yml", Audit: auditPath, Command: []string{"python3", "srv.py"}, How: "no sandbox", Network: "none", Default: "deny", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	sec, _ := lock.Compute(lock.Tools, []json.RawMessage{json.RawMessage(`{"name":"read_file"}`), json.RawMessage(`{"name":"rm"}`)})
	if _, err := lock.Record("demo", lock.Tools, sec); err != nil {
		t.Fatal(err)
	}
	pend, _ := lock.Compute(lock.Tools, []json.RawMessage{json.RawMessage(`{"name":"read_file","description":"x"}`), json.RawMessage(`{"name":"exfil"}`)})
	if err := lock.SavePending("demo", lock.Tools, pend); err != nil {
		t.Fatal(err)
	}
	// a lock without a registry entry (pre-dashboard run) still shows up
	other, _ := lock.Compute(lock.Prompts, []json.RawMessage{json.RawMessage(`{"name":"p"}`)})
	if _, err := lock.Record("legacy", lock.Prompts, other); err != nil {
		t.Fatal(err)
	}

	bearer := map[string]string{"Authorization": "Bearer " + tok}
	var st State
	getJSON(t, ts.URL+"/api/state", bearer, &st)
	if len(st.Servers) != 2 || st.Servers[0].Name != "demo" || !st.Servers[0].Running || st.Servers[1].Name != "legacy" || st.Servers[1].Running {
		t.Fatalf("servers: %+v", st.Servers)
	}
	d := st.Servers[0]
	if d.PID != os.Getpid() || d.How != "no sandbox" || !d.LockOn || d.Audit != auditPath || len(d.Command) != 2 {
		t.Fatalf("demo: %+v", d)
	}
	if len(d.Lock) != 1 || d.Lock[0].Kind != "tools" || d.Lock[0].Count != 2 || d.Lock[0].Hash == "" {
		t.Fatalf("lock: %+v", d.Lock)
	}
	if d.Pending == nil || len(d.Pending.Sections["tools"].Added) != 1 || d.Pending.Sections["tools"].Added[0] != "exfil" ||
		len(d.Pending.Sections["tools"].Removed) != 1 || len(d.Pending.Sections["tools"].Changed) != 1 {
		t.Fatalf("pending: %+v", d.Pending)
	}
	if d.Counts["allow"] != 1 || d.Counts["deny"] != 1 || d.Counts["blocked"] != 1 || d.LastEvent == nil {
		t.Fatalf("counts: %+v", d.Counts)
	}
	if len(st.Servers[1].Lock) != 1 || st.Servers[1].Lock[0].Kind != "prompts" {
		t.Fatalf("legacy lock: %+v", st.Servers[1].Lock)
	}

	var ev EventsResponse
	getJSON(t, ts.URL+"/api/events?decision=deny", bearer, &ev)
	if len(ev.Events) != 1 || ev.Events[0].Tool != "rm" || len(ev.Files) != 1 || ev.Limit != 500 {
		t.Fatalf("events: %+v", ev)
	}
	getJSON(t, ts.URL+"/api/events?since=1h&limit=2", bearer, &ev)
	if len(ev.Events) != 2 || ev.Limit != 2 || ev.Events[0].Kind != "net" {
		t.Fatalf("limit/since: %+v", ev.Events)
	}
	for _, bad := range []string{"since=yesterday", "limit=0", "limit=x", "until=-5m"} {
		if c := status(t, ts.URL+"/api/events?"+bad, bearer); c != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, c)
		}
	}
	if c := status(t, ts.URL+"/api/events?limit=99999", bearer); c != http.StatusOK {
		t.Errorf("limit clamps, not rejects: %d", c)
	}
}

func TestStream(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "live.jsonl")
	l, _ := audit.Open(auditPath, "live")
	l.Log(audit.Event{Kind: "start"})
	ts := newTestServer(t, auditPath)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	rd := bufio.NewReader(r.Body)
	line, _ := rd.ReadString('\n')
	if line != ": connected\n" {
		t.Fatalf("first line %q", line)
	}
	time.Sleep(50 * time.Millisecond) // tailer must start at the current end
	l.Log(audit.Event{Kind: "tool_call", Tool: "zap", Decision: "deny"})
	_ = l.Close()
	deadline := time.After(3 * time.Second)
	got := make(chan audit.Event, 1)
	go func() {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "data: ") {
				var e audit.Event
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e) == nil {
					got <- e
					return
				}
			}
		}
	}()
	select {
	case e := <-got:
		if e.Tool != "zap" || e.Decision != "deny" {
			t.Fatalf("event: %+v", e)
		}
	case <-deadline:
		t.Fatal("no event streamed")
	}
}

func TestParseTime(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got, _ := parseTime("", now); !got.IsZero() {
		t.Fatal("empty")
	}
	if got, _ := parseTime("2h", now); !got.Equal(now.Add(-2 * time.Hour)) {
		t.Fatalf("duration: %v", got)
	}
	if got, _ := parseTime("2026-01-01T00:00:00Z", now); got.Year() != 2026 || got.Day() != 1 {
		t.Fatalf("rfc3339: %v", got)
	}
	for _, bad := range []string{"-1h", "0s", "soon"} {
		if _, err := parseTime(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
