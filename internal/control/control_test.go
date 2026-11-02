package control

import (
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
)

func TestBroker(t *testing.T) {
	b := NewBroker("srv")
	if b.Attached() {
		t.Fatal("attached before any poll")
	}
	p := b.Submit("write_file", json.RawMessage(`{"path":"/x"}`), time.Now().Add(time.Minute))
	if p.ID != "1" || p.Server != "srv" || p.Tool != "write_file" || p.Since.IsZero() {
		t.Fatalf("pending: %+v", p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, ok := p.Wait(ctx); ok {
		t.Fatal("answered without an answer")
	}
	list := b.List()
	if len(list) != 1 || list[0].ID != "1" || !b.Attached() {
		t.Fatalf("list/attached: %+v %v", list, b.Attached())
	}
	if err := b.Answer("9", Decision{Allow: true, By: "x"}); err == nil {
		t.Fatal("unknown id accepted")
	}
	if err := b.Answer("1", Decision{Allow: true, By: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	_ = b.Answer("1", Decision{Allow: false, By: "late"}) // second answer is ignored
	d, ok := p.Wait(context.Background())
	if !ok || !d.Allow || d.By != "dashboard" {
		t.Fatalf("decision: %+v %v", d, ok)
	}
	b.Remove("1")
	if len(b.List()) != 0 {
		t.Fatal("not removed")
	}
	// ordering: oldest first
	b.Submit("b", nil, time.Time{})
	time.Sleep(time.Millisecond)
	b.Submit("c", nil, time.Time{})
	if l := b.List(); len(l) != 2 || l[0].Tool != "b" || l[1].Tool != "c" {
		t.Fatalf("order: %+v", l)
	}
}

func TestHandler(t *testing.T) {
	b := NewBroker("srv")
	p := b.Submit("rm", json.RawMessage(`{}`), time.Now().Add(time.Minute))
	ts := httptest.NewServer(Handler(b, Hooks{}))
	defer ts.Close()

	r, err := http.Get(ts.URL + "/asks")
	if err != nil {
		t.Fatal(err)
	}
	var list []Pending
	_ = json.NewDecoder(r.Body).Decode(&list)
	_ = r.Body.Close()
	if len(list) != 1 || list[0].ID != p.ID || list[0].Tool != "rm" {
		t.Fatalf("list: %+v", list)
	}
	post := func(id, body string) int {
		r, err := http.Post(ts.URL+"/asks/"+id, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		return r.StatusCode
	}
	if c := post(p.ID, `{"decision":"maybe"}`); c != http.StatusBadRequest {
		t.Errorf("bad decision: %d", c)
	}
	if c := post(p.ID, `not json`); c != http.StatusBadRequest {
		t.Errorf("bad body: %d", c)
	}
	if c := post("42", `{"decision":"allow"}`); c != http.StatusNotFound {
		t.Errorf("unknown: %d", c)
	}
	if c := post(p.ID, `{"decision":"deny","by":"dash\nboard"}`); c != http.StatusOK {
		t.Errorf("deny: %d", c)
	}
	d, ok := p.Wait(context.Background())
	if !ok || d.Allow || d.By != "control" { // control characters in `by` fall back to the default
		t.Fatalf("decision: %+v", d)
	}
}

func TestLongPathFallsBackToTempDir(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("deep/", 30), "x.sock")
	s, err := Listen(long, NewBroker("x"), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if s.Path() == long || !strings.HasPrefix(s.Path(), os.TempDir()) || filepath.Base(s.Path()) != "x.sock" {
		t.Fatalf("fallback path: %s", s.Path())
	}
	if _, err := Dial(s.Path()).List(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSocketRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "cs") // short: t.TempDir() can exceed the socket path limit
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	b := NewBroker("srv")
	path := SocketPath(dir, "my server/x", 123)
	if filepath.Base(path) != "my_server_x.123.sock" {
		t.Fatalf("path: %s", path)
	}
	// a stale socket file is replaced
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(path, b, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Path() != path {
		t.Fatalf("short path must be used as is: %s", s.Path())
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket perms: %v %v", st, err)
	}
	c := Dial(path)
	ctx := context.Background()
	if l, err := c.List(ctx); err != nil || len(l) != 0 {
		t.Fatalf("empty list: %v %v", l, err)
	}
	if !b.Attached() {
		t.Fatal("List over the socket must mark the dashboard attached")
	}
	p := b.Submit("send", json.RawMessage(`{"to":"x"}`), time.Now().Add(time.Minute))
	l, err := c.List(ctx)
	if err != nil || len(l) != 1 || l[0].ID != p.ID || string(l[0].Arguments) != `{"to":"x"}` {
		t.Fatalf("list: %+v %v", l, err)
	}
	if err := c.Answer(ctx, "nope", true, "dashboard"); err != ErrUnknown { //nolint:errorlint // sentinel from our own client
		t.Fatalf("unknown: %v", err)
	}
	if err := c.Answer(ctx, p.ID, true, "dashboard"); err != nil {
		t.Fatal(err)
	}
	if d, ok := p.Wait(ctx); !ok || !d.Allow || d.By != "dashboard" {
		t.Fatalf("decision: %+v", d)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("socket file not removed")
	}
	if _, err := c.List(ctx); err == nil {
		t.Fatal("list after close must fail")
	}
}

func TestReloadHook(t *testing.T) {
	calls := 0
	var fail error
	h := Hooks{Reload: func() error { calls++; return fail }}
	ts := httptest.NewServer(Handler(NewBroker("srv"), h))
	defer ts.Close()
	post := func(url string) (int, string) {
		r, err := http.Post(url, "application/json", nil) //nolint:gosec // test server URL
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		return r.StatusCode, string(b)
	}
	if c, b := post(ts.URL + "/reload"); c != http.StatusOK || calls != 1 || !strings.Contains(b, `"ok":true`) {
		t.Fatalf("ok: %d %s calls=%d", c, b, calls)
	}
	fail = errors.New("policy.yml: tools.default: bad")
	if c, b := post(ts.URL + "/reload"); c != http.StatusConflict || !strings.Contains(b, "tools.default: bad") {
		t.Fatalf("refused: %d %s", c, b)
	}
	none := httptest.NewServer(Handler(NewBroker("srv"), Hooks{}))
	defer none.Close()
	if c, _ := post(none.URL + "/reload"); c != http.StatusNotImplemented {
		t.Fatalf("no hook: %d", c)
	}
	if r, err := http.Get(ts.URL + "/reload"); err == nil {
		_ = r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Fatal("GET /reload must not reload")
		}
	}
}

func TestClientReload(t *testing.T) {
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	var fail error
	s, err := Listen(filepath.Join(dir, "r.sock"), NewBroker("srv"), Hooks{Reload: func() error { return fail }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	c := Dial(s.Path())
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = errors.New("nope: unparsable")
	if err := c.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "unparsable") {
		t.Fatalf("error not relayed: %v", err)
	}
}

func TestStopHook(t *testing.T) {
	var got []string
	h := Hooks{Stop: func(by string) { got = append(got, by) }}
	ts := httptest.NewServer(Handler(NewBroker("srv"), h))
	defer ts.Close()
	post := func(url, body string) int {
		r, err := http.Post(url, "application/json", strings.NewReader(body)) //nolint:gosec // test server URL
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		return r.StatusCode
	}
	if c := post(ts.URL+"/stop", `{"by":"dashboard"}`); c != http.StatusOK {
		t.Fatalf("stop: %d", c)
	}
	if c := post(ts.URL+"/stop", ``); c != http.StatusOK { // empty body: default name
		t.Fatalf("stop without body: %d", c)
	}
	if c := post(ts.URL+"/stop", `{"by":"bad\nname"}`); c != http.StatusOK {
		t.Fatalf("stop: %d", c)
	}
	if len(got) != 3 || got[0] != "dashboard" || got[1] != "control" || got[2] != "control" {
		t.Fatalf("hook calls: %v", got)
	}
	none := httptest.NewServer(Handler(NewBroker("srv"), Hooks{}))
	defer none.Close()
	if c := post(none.URL+"/stop", `{}`); c != http.StatusNotImplemented {
		t.Fatalf("no hook: %d", c)
	}
	if r, err := http.Get(ts.URL + "/stop"); err == nil {
		_ = r.Body.Close()
		if r.StatusCode == http.StatusOK || len(got) != 3 {
			t.Fatal("GET /stop must not stop")
		}
	}
}

func TestClientStop(t *testing.T) {
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	by := make(chan string, 1)
	s, err := Listen(filepath.Join(dir, "s.sock"), NewBroker("srv"), Hooks{Stop: func(b string) { by <- b }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := Dial(s.Path()).Stop(context.Background(), "dashboard"); err != nil {
		t.Fatal(err)
	}
	if b := <-by; b != "dashboard" {
		t.Fatalf("by: %s", b)
	}
	none, err := Listen(filepath.Join(dir, "n.sock"), NewBroker("srv"), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = none.Close() }()
	if err := Dial(none.Path()).Stop(context.Background(), "dashboard"); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unsupported: %v", err)
	}
}

func TestOwnedDir(t *testing.T) {
	root := t.TempDir()
	fresh := filepath.Join(root, "fresh")
	if err := ownedDir(fresh); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(fresh); st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if err := ownedDir(fresh); err != nil {
		t.Fatalf("existing private dir: %v", err)
	}
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o755); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	if err := ownedDir(open); err == nil {
		t.Error("group/world accessible dir accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	if err := ownedDir(link); err == nil {
		t.Error("symlink accepted")
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ownedDir(file); err == nil {
		t.Error("file accepted")
	}
}
