package egress

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type allowFn func(string) bool

func (f allowFn) HostAllowed(h string) bool { return f(h) }

type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) observe(kind, host string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dec := "allow"
	if !ok {
		dec = "blocked"
	}
	r.seen = append(r.seen, kind+" "+host+" "+dec)
}

func (r *recorder) has(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.seen {
		if x == s {
			return true
		}
	}
	return false
}

// rig wires a relay and a shim on ephemeral ports, standing in for the jail.
type rig struct {
	relay                               *Relay
	shim                                *Shim
	rec                                 *recorder
	dns, httpAddr, httpsAddr, proxyAddr string
}

func newRig(t *testing.T, allow []string) *rig {
	t.Helper()
	rec := &recorder{}
	hostOK := func(h string) bool {
		s := &Shim{Allow: allow}
		return s.hostAllowed(h)
	}
	relay, err := ListenRelay(allowFn(hostOK), rec.observe)
	if err != nil {
		t.Fatal(err)
	}
	sh := &Shim{Socket: SocketPath(relay.Dir()), Allow: allow, Logf: t.Logf}
	if err := sh.Listen(0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	go sh.Serve()
	t.Cleanup(func() { sh.Close(); _ = relay.Close() })
	r := &rig{relay: relay, shim: sh, rec: rec}
	r.dns, r.httpAddr, r.httpsAddr, r.proxyAddr = sh.Addrs()
	return r
}

// redirect makes the relay dial upstream whenever the shim asks for name.
func (r *rig) redirect(name, upstream string) {
	inner := r.relay.dial
	r.relay.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, _, _ := net.SplitHostPort(addr); h == name {
			addr = upstream
		}
		return inner(ctx, network, addr)
	}
}

func TestProxyPath(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.Host+r.URL.Path) // #nosec G705 -- test echo
	}))
	defer up.Close()
	upHost := up.Listener.Addr().String() // 127.0.0.1:port
	r := newRig(t, []string{"127.0.0.1"})

	pu, _ := url.Parse("http://" + r.proxyAddr)
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}

	resp, err := cl.Get(up.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "hello "+upHost+"/a" {
		t.Fatalf("via proxy: %q", b)
	}
	if !r.rec.has("net 127.0.0.1 allow") {
		t.Fatalf("relay did not observe the connection: %v", r.rec.seen)
	}

	resp, err = cl.Get("http://blocked.example/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked host via proxy: %d", resp.StatusCode)
	}
	resp, err = cl.Get("https://blocked.example/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("CONNECT to blocked host must fail")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("CONNECT to blocked host: %v", err)
	}
	// The shim refuses locally, so the relay never hears about blocked hosts
	// through this path; it must not have dialled anything either.
	if r.rec.has("net blocked.example allow") {
		t.Fatal("blocked host reached the relay as allowed")
	}
}

func TestTransparentHTTP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain "+r.Host) // #nosec G705 -- test echo
	}))
	defer up.Close()
	r := newRig(t, []string{"allowed.test"})
	r.redirect("allowed.test", up.Listener.Addr().String())

	c, err := net.Dial("tcp", r.httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "GET /p HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(b), "HTTP/1.1 200") || !strings.HasSuffix(string(b), "plain allowed.test") {
		t.Fatalf("transparent http: %q", b)
	}

	c2, _ := net.Dial("tcp", r.httpAddr)
	defer func() { _ = c2.Close() }()
	_, _ = io.WriteString(c2, "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n")
	b, _ = io.ReadAll(c2)
	if !strings.HasPrefix(string(b), "HTTP/1.1 403") {
		t.Fatalf("blocked transparent http: %q", b)
	}

	// Host allowed by the shim but refused by the relay (authoritative).
	r.relay.allow = allowFn(func(string) bool { return false })
	c3, _ := net.Dial("tcp", r.httpAddr)
	defer func() { _ = c3.Close() }()
	_, _ = io.WriteString(c3, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	b, _ = io.ReadAll(c3)
	if !strings.HasPrefix(string(b), "HTTP/1.1 403") || !r.rec.has("net allowed.test blocked") {
		t.Fatalf("relay must be authoritative: %q %v", b, r.rec.seen)
	}
}

func TestTransparentTLS(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls "+r.TLS.ServerName) // #nosec G705 -- test echo
	}))
	defer up.Close()
	r := newRig(t, []string{"*.allowed.test"})
	r.redirect("api.allowed.test", up.Listener.Addr().String())

	dial := func(sni string) (string, error) {
		raw, err := net.Dial("tcp", r.httpsAddr)
		if err != nil {
			return "", err
		}
		defer func() { _ = raw.Close() }()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // test
		if err := tc.Handshake(); err != nil {
			return "", err
		}
		_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n")
		b, _ := io.ReadAll(tc)
		return string(b), nil
	}
	out, err := dial("api.allowed.test")
	if err != nil || !strings.HasSuffix(out, "tls api.allowed.test") {
		t.Fatalf("tls via sni: %q %v", out, err)
	}
	if _, err := dial("api.evil.test"); err == nil {
		t.Fatal("blocked sni must not complete a handshake")
	}
	if !r.rec.has("net api.allowed.test allow") {
		t.Fatalf("observer: %v", r.rec.seen)
	}
}

func TestDNSThroughShim(t *testing.T) {
	r := newRig(t, []string{"api.allowed.test"})
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", r.dns)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := res.LookupHost(ctx, "api.allowed.test")
	if err != nil || len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("allowed: %v %v", ips, err)
	}
	if _, err := res.LookupHost(ctx, "evil.test"); err == nil {
		t.Fatal("blocked name must fail")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !r.rec.has("dns evil.test blocked") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !r.rec.has("dns evil.test blocked") {
		t.Fatalf("relay must be told about refused lookups: %v", r.rec.seen)
	}
}

func TestRelayRejectsGarbage(t *testing.T) {
	r := newRig(t, nil)
	c, err := net.Dial("unix", SocketPath(r.relay.Dir()))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "HELLO\n")
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, _ := io.ReadAll(c); len(b) != 0 {
		t.Fatalf("garbage header must be dropped silently, got %q", b)
	}
	_ = c.Close()
	if len(r.rec.seen) != 0 {
		t.Fatalf("nothing should be observed: %v", r.rec.seen)
	}
}

func TestProxyEnv(t *testing.T) {
	env := ProxyEnv()
	if env["HTTPS_PROXY"] != "http://127.0.0.1:3128" || env["NO_PROXY"] != "" || env["NODE_USE_ENV_PROXY"] != "1" {
		t.Fatalf("env = %v", env)
	}
}
