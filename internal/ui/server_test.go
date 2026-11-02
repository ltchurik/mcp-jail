package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/control"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
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

	// a first-contact review (lock.first: review) has a pending record and no lock yet
	first, _ := lock.Compute(lock.Tools, []json.RawMessage{json.RawMessage(`{"name":"new_tool"}`)})
	if err := lock.SavePending("fresh", lock.Tools, first); err != nil {
		t.Fatal(err)
	}

	bearer := map[string]string{"Authorization": "Bearer " + tok}
	var st State
	getJSON(t, ts.URL+"/api/state", bearer, &st)
	if len(st.Servers) != 3 || st.Servers[0].Name != "demo" || !st.Servers[0].Running || st.Servers[1].Name != "fresh" || st.Servers[2].Name != "legacy" || st.Servers[2].Running {
		t.Fatalf("servers: %+v", st.Servers)
	}
	if f := st.Servers[1]; len(f.Lock) != 0 || f.Pending == nil || !f.Pending.Sections["tools"].First || len(f.Pending.Sections["tools"].Added) != 1 {
		t.Fatalf("first contact: %+v", f.Pending)
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
	if len(st.Servers[2].Lock) != 1 || st.Servers[2].Lock[0].Kind != "prompts" {
		t.Fatalf("legacy lock: %+v", st.Servers[2].Lock)
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

func TestReportEndpoint(t *testing.T) {
	ts := newTestServer(t, sampleLog(t))
	bearer := map[string]string{"Authorization": "Bearer " + tok}
	var rep Report
	getJSON(t, ts.URL+"/api/report?since=1h", bearer, &rep)
	if rep.Total != 17 || len(rep.Tools) != 3 || rep.Bucket != "5m0s" || len(rep.Files) != 1 {
		t.Fatalf("report: total=%d tools=%d bucket=%s files=%v", rep.Total, len(rep.Tools), rep.Bucket, rep.Files)
	}
	getJSON(t, ts.URL+"/api/report?server=nope", bearer, &rep)
	if rep.Total != 0 || rep.Tools == nil {
		t.Fatalf("filtered report: %+v", rep)
	}
	r := get(t, ts.URL+"/api/report?format=csv", bearer)
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") || !strings.HasPrefix(string(body), "server,tool,total") {
		t.Fatalf("csv: %d %q %q", r.StatusCode, r.Header.Get("Content-Type"), body[:min(len(body), 40)])
	}
	r = get(t, ts.URL+"/api/report?format=text", bearer)
	body, _ = io.ReadAll(r.Body)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK || !strings.Contains(string(body), "mcp-jail report") {
		t.Fatalf("text: %d %s", r.StatusCode, body)
	}
	for _, bad := range []string{"format=xml", "since=soon"} {
		if c := status(t, ts.URL+"/api/report?"+bad, bearer); c != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, c)
		}
	}
	if c := status(t, ts.URL+"/api/report", nil); c != http.StatusUnauthorized {
		t.Errorf("no auth: %d", c)
	}
}

func post(t *testing.T, url string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader("{}"))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func TestApprove(t *testing.T) {
	ts := newTestServer(t)
	sec, _ := lock.Compute(lock.Tools, []json.RawMessage{json.RawMessage(`{"name":"a"}`)})
	if _, err := lock.Record("demo", lock.Tools, sec); err != nil {
		t.Fatal(err)
	}
	pend, _ := lock.Compute(lock.Tools, []json.RawMessage{json.RawMessage(`{"name":"a"}`), json.RawMessage(`{"name":"b"}`)})
	if err := lock.SavePending("demo", lock.Tools, pend); err != nil {
		t.Fatal(err)
	}
	ok := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1"}

	// every refusal leaves the pending record in place
	for name, hdr := range map[string]map[string]string{
		"no auth":        {mutationHeader: "1"},
		"no header":      {"Authorization": "Bearer " + tok},
		"cross-site":     {"Authorization": "Bearer " + tok, mutationHeader: "1", "Sec-Fetch-Site": "cross-site"},
		"foreign origin": {"Authorization": "Bearer " + tok, mutationHeader: "1", "Origin": "http://evil.example"},
	} {
		code, _ := post(t, ts.URL+"/api/servers/demo/approve", hdr)
		if code != http.StatusForbidden && code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
		if p, _ := lock.LoadPending("demo"); p == nil {
			t.Fatalf("%s: pending record consumed", name)
		}
	}
	if code, _ := post(t, ts.URL+"/api/servers/nope/approve", ok); code != http.StatusNotFound {
		t.Errorf("unknown server: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/servers/..%2Fx/approve", ok); code != http.StatusBadRequest && code != http.StatusNotFound {
		t.Errorf("traversal name: %d", code)
	}
	if c := status(t, ts.URL+"/api/servers/demo/approve", ok); c != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", c)
	}

	same := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1", "Sec-Fetch-Site": "same-origin", "Origin": "http://" + strings.TrimPrefix(ts.URL, "http://")}
	code, body := post(t, ts.URL+"/api/servers/demo/approve", same)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	var resp ApproveResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil || resp.Name != "demo" || len(resp.Lock) != 1 || resp.Lock[0].Count != 2 {
		t.Fatalf("response: %v %s", err, body)
	}
	if p, _ := lock.LoadPending("demo"); p != nil {
		t.Fatal("pending record not consumed")
	}
	f, _ := lock.Load("demo")
	if f.Section(lock.Tools).Hash != pend.Hash {
		t.Fatal("lock not updated")
	}
	if code, _ := post(t, ts.URL+"/api/servers/demo/approve", ok); code != http.StatusNotFound {
		t.Errorf("second approve: %d", code)
	}
	var st State
	getJSON(t, ts.URL+"/api/state", map[string]string{"Authorization": "Bearer " + tok}, &st)
	if len(st.Servers) != 1 || st.Servers[0].Pending != nil || st.Servers[0].Lock[0].Count != 2 {
		t.Fatalf("state after approve: %+v", st.Servers)
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
	if got, _ := ParseTime("", now); !got.IsZero() {
		t.Fatal("empty")
	}
	if got, _ := ParseTime("2h", now); !got.Equal(now.Add(-2 * time.Hour)) {
		t.Fatalf("duration: %v", got)
	}
	if got, _ := ParseTime("2026-01-01T00:00:00Z", now); got.Year() != 2026 || got.Day() != 1 {
		t.Fatalf("rfc3339: %v", got)
	}
	for _, bad := range []string{"-1h", "0s", "soon"} {
		if _, err := ParseTime(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAsks(t *testing.T) {
	ts := newTestServer(t)
	// a running jail with a control socket (short path: unix sockets are length-limited)
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	b := control.NewBroker("demo")
	cs, err := control.Listen(filepath.Join(dir, "demo.sock"), b, control.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	unreg, err := registry.Register(registry.Entry{Name: "demo", Control: cs.Path(), Audit: filepath.Join(dir, "a.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	// and one without (older binary): must be skipped, not break the listing
	unreg2, _ := registry.Register(registry.Entry{Name: "old", PID: os.Getpid()})
	defer unreg2()

	bearer := map[string]string{"Authorization": "Bearer " + tok}
	var ar AsksResponse
	getJSON(t, ts.URL+"/api/asks", bearer, &ar)
	if len(ar.Asks) != 0 || !b.Attached() {
		t.Fatalf("empty poll must attach: %+v %v", ar, b.Attached())
	}
	p := b.Submit("send_email", json.RawMessage(`{"to":"x@example"}`), time.Now().Add(time.Minute))
	getJSON(t, ts.URL+"/api/asks", bearer, &ar)
	if len(ar.Asks) != 1 || ar.Asks[0].ID != p.ID || ar.Asks[0].Server != "demo" || ar.Asks[0].Tool != "send_email" {
		t.Fatalf("asks: %+v", ar.Asks)
	}
	var st State
	getJSON(t, ts.URL+"/api/state", bearer, &st)
	var demo *ServerState
	for i := range st.Servers {
		if st.Servers[i].Name == "demo" {
			demo = &st.Servers[i]
		}
	}
	if demo == nil || !demo.Control || demo.Asks != 1 {
		t.Fatalf("state: %+v", st.Servers)
	}

	ok := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1"}
	url := ts.URL + "/api/servers/demo/asks/" + p.ID
	if code, _ := postBody(t, url, map[string]string{"Authorization": "Bearer " + tok}, `{"decision":"allow"}`); code != http.StatusForbidden {
		t.Errorf("no header: %d", code)
	}
	if code, _ := postBody(t, url, ok, `{"decision":"whatever"}`); code != http.StatusBadRequest {
		t.Errorf("bad decision: %d", code)
	}
	if code, _ := postBody(t, ts.URL+"/api/servers/old/asks/1", ok, `{"decision":"allow"}`); code != http.StatusNotFound {
		t.Errorf("no control socket: %d", code)
	}
	if code, _ := postBody(t, ts.URL+"/api/servers/demo/asks/77", ok, `{"decision":"allow"}`); code != http.StatusNotFound {
		t.Errorf("unknown id: %d", code)
	}
	select {
	case <-time.After(10 * time.Millisecond):
	case d := <-answered(p):
		t.Fatalf("refused requests must not answer: %+v", d)
	}
	code, body := postBody(t, url, ok, `{"decision":"allow"}`)
	if code != http.StatusOK || !strings.Contains(body, `"allow":true`) {
		t.Fatalf("answer: %d %s", code, body)
	}
	d, got := p.Wait(context.Background())
	if !got || !d.Allow || d.By != "dashboard" {
		t.Fatalf("decision: %+v %v", d, got)
	}
}

func answered(p *control.Pending) <-chan control.Decision {
	c := make(chan control.Decision, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		if d, ok := p.Wait(ctx); ok {
			c <- d
		}
	}()
	return c
}

func postBody(t *testing.T, url string, hdr map[string]string, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func TestRule(t *testing.T) {
	ts := newTestServer(t)
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	pol := filepath.Join(dir, "demo.yml")
	if err := os.WriteFile(pol, []byte("# demo\nname: demo\ntools:\n  default: ask\n  rules:\n    \"read_*\": allow # fast\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	var reloadErr error
	cs, err := control.Listen(filepath.Join(dir, "demo.sock"), control.NewBroker("demo"), control.Hooks{Reload: func() error { reloads++; return reloadErr }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	unreg, err := registry.Register(registry.Entry{Name: "demo", Policy: pol, Control: cs.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	// a server that only ran in the past: edit the file, nothing to reload
	oldPol := filepath.Join(dir, "old.yml")
	if err := os.WriteFile(oldPol, []byte("name: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreg2, _ := registry.Register(registry.Entry{Name: "old", PID: os.Getpid(), Policy: oldPol})
	unreg2() // gone from the live list, stays in the history

	ok := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1"}
	url := ts.URL + "/api/servers/demo/rules"
	if code, _ := postBody(t, url, map[string]string{"Authorization": "Bearer " + tok}, `{"tool":"x","decision":"allow"}`); code != http.StatusForbidden {
		t.Errorf("no header: %d", code)
	}
	for _, bad := range []string{`{"tool":"x","decision":"maybe"}`, `{"tool":"","decision":"allow"}`, `{"tool":"a b","decision":"deny"}`, `nope`} {
		if code, _ := postBody(t, url, ok, bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, code)
		}
	}
	if code, _ := postBody(t, ts.URL+"/api/servers/nobody/rules", ok, `{"tool":"x","decision":"allow"}`); code != http.StatusNotFound {
		t.Errorf("unknown server: %d", code)
	}
	if reloads != 0 {
		t.Fatalf("refused requests reloaded: %d", reloads)
	}
	code, body := postBody(t, url, ok, `{"tool":"delete_file","decision":"deny"}`)
	var rr RuleResponse
	if err := json.Unmarshal([]byte(body), &rr); err != nil || code != http.StatusOK || !rr.Live || rr.Policy != pol || rr.Warning != "" || reloads != 1 {
		t.Fatalf("rule: %d %s (reloads=%d err=%v)", code, body, reloads, err)
	}
	b, _ := os.ReadFile(pol)
	if s := string(b); !strings.Contains(s, "# demo\n") || !strings.Contains(s, `"read_*": allow # fast`) || !strings.Contains(s, "    delete_file: deny\n") {
		t.Fatalf("file:\n%s", s)
	}
	// the jail refuses the reload: the file is written, the response says so
	reloadErr = errors.New("control: boom")
	code, body = postBody(t, url, ok, `{"tool":"send_mail","decision":"allow"}`)
	_ = json.Unmarshal([]byte(body), &rr)
	if code != http.StatusOK || rr.Live || !strings.Contains(rr.Warning, "boom") {
		t.Fatalf("reload failure: %d %s", code, body)
	}
	// history-only server: written, not live
	code, body = postBody(t, ts.URL+"/api/servers/old/rules", ok, `{"tool":"x","decision":"ask"}`)
	_ = json.Unmarshal([]byte(body), &rr)
	if code != http.StatusOK || rr.Live || !strings.Contains(rr.Warning, "next start") {
		t.Fatalf("history: %d %s", code, body)
	}
	if b, _ := os.ReadFile(oldPol); !strings.Contains(string(b), "x: ask") {
		t.Fatalf("old.yml:\n%s", b)
	}
}

func TestStop(t *testing.T) {
	ts := newTestServer(t)
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	stopped := make(chan string, 1)
	cs, err := control.Listen(filepath.Join(dir, "demo.sock"), control.NewBroker("demo"), control.Hooks{Stop: func(by string) { stopped <- by }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	unreg, err := registry.Register(registry.Entry{Name: "demo", Control: cs.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	unreg2, _ := registry.Register(registry.Entry{Name: "old", PID: os.Getpid()}) // no control socket
	defer unreg2()

	ok := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1"}
	if code, _ := postBody(t, ts.URL+"/api/servers/demo/stop", map[string]string{"Authorization": "Bearer " + tok}, ``); code != http.StatusForbidden {
		t.Errorf("no header: %d", code)
	}
	if code, _ := postBody(t, ts.URL+"/api/servers/nobody/stop", ok, ``); code != http.StatusNotFound {
		t.Errorf("unknown: %d", code)
	}
	if code, body := postBody(t, ts.URL+"/api/servers/old/stop", ok, ``); code != http.StatusConflict || !strings.Contains(body, "stop pid") {
		t.Errorf("no socket: %d %s", code, body)
	}
	select {
	case by := <-stopped:
		t.Fatalf("refused requests must not stop: %s", by)
	case <-time.After(20 * time.Millisecond):
	}
	code, body := postBody(t, ts.URL+"/api/servers/demo/stop", ok, ``)
	if code != http.StatusOK || !strings.Contains(body, `"ok":true`) || !strings.Contains(body, `"pid":`) {
		t.Fatalf("stop: %d %s", code, body)
	}
	if by := <-stopped; by != "dashboard" {
		t.Fatalf("by: %s", by)
	}
}

func TestSameOrigin(t *testing.T) {
	ok := map[string]string{
		"http://127.0.0.1:4000": "127.0.0.1:4000",
		"http://localhost:4000": "127.0.0.1:4000",
		"http://[::1]:4000":     "127.0.0.1:4000",
	}
	for o, h := range ok {
		if !sameOrigin(o, h) {
			t.Errorf("%s vs %s refused", o, h)
		}
	}
	bad := map[string]string{
		"http://localhost.evil.example:4000": "127.0.0.1:4000",
		"http://localhost:4001":              "127.0.0.1:4000",
		"https://localhost:4000":             "127.0.0.1:4000",
		"http://evil.example":                "127.0.0.1:4000",
		"http://localhost@evil.example:4000": "127.0.0.1:4000",
		"null":                               "127.0.0.1:4000",
		"":                                   "127.0.0.1:4000",
	}
	for o, h := range bad {
		if sameOrigin(o, h) {
			t.Errorf("%s vs %s accepted", o, h)
		}
	}
}

func TestAnswerRejectsBadID(t *testing.T) {
	ts := newTestServer(t)
	ok := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1"}
	for _, id := range []string{"..", "x", "1%2F2"} {
		if code, _ := postBody(t, ts.URL+"/api/servers/demo/asks/"+id, ok, `{"decision":"allow"}`); code != http.StatusBadRequest && code != http.StatusNotFound {
			t.Errorf("id %q: %d", id, code)
		}
	}
}

func TestRulePromotesLiteralToolName(t *testing.T) {
	ts := newTestServer(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "demo.yml")
	if err := os.WriteFile(pol, []byte("name: demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreg, err := registry.Register(registry.Entry{Name: "demo", Policy: pol})
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	ok := map[string]string{"Authorization": "Bearer " + tok, mutationHeader: "1"}
	code, body := postBody(t, ts.URL+"/api/servers/demo/rules", ok, `{"tool":"*","decision":"allow"}`)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	p, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("*") != policy.Allow || p.Decide("delete_file") != policy.Ask {
		t.Fatalf("a tool named * must not become a rule for everything: %+v", p.Tools.Rules)
	}
}
