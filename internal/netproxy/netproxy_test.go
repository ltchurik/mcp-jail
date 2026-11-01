package netproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type allowFn func(string) bool

func (f allowFn) HostAllowed(h string) bool { return f(h) }

func TestFilter(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer up.Close()

	var mu sync.Mutex
	seen := map[string]bool{}
	p, err := Listen(allowFn(func(h string) bool { return h == "127.0.0.1" }), func(h string, ok bool) {
		mu.Lock()
		seen[h] = ok
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()

	pu, _ := url.Parse(p.Addr())
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	resp, err := cl.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "hello" {
		t.Fatalf("allowed host: got %q", b)
	}

	// Not in allowlist: proxy must answer 403 itself, never dial out.
	resp, err = cl.Get("http://example.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked host: status %d", resp.StatusCode)
	}

	// CONNECT to a blocked host is refused too.
	resp, err = cl.Get("https://example.invalid/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("CONNECT to blocked host should fail")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected Forbidden from proxy, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !seen["127.0.0.1"] || seen["example.invalid"] {
		t.Fatalf("observer: %v", seen)
	}
}
