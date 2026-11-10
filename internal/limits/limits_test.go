package limits

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	for in, want := range map[string]string{
		"60/1m": "60/1m", "10MB/1h": "10MB/1h", "500KB/30s": "500KB/30s", "100/1d": "100/1d", "1GB / 2h": "1GB/2h",
		"2048B/1m": "2KB/1m", "3KiB/1s": "3KB/1s", "": "none", "none": "none", "0": "none", "1500/90s": "1500/90s",
	} {
		r, err := ParseRate(in)
		if err != nil || r.String() != want {
			t.Errorf("ParseRate(%q) = %s, %v; want %s", in, r, err, want)
		}
	}
	for _, bad := range []string{"60", "60/", "/1m", "60/1y", "-1/1m", "60/0s", "1/40d", "ten/1m", "60/1m extra"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func clock(start time.Time) (func() time.Time, func(time.Duration)) {
	now := start
	return func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }
}

func TestReload(t *testing.T) {
	now, advance := clock(time.Unix(1_700_000_000, 0))
	l := New(mustRate("2/1m"), Rate{}, Rate{}, map[string]Rate{"send_*": mustRate("1/1h")}, now)
	l.Call("", 0)
	l.Call("", 0)
	if why := l.Call("", 0); why == "" {
		t.Fatal("third call must be over budget")
	}
	// raised: the balance stays (0), the refill is faster: 10/1m gives one token in 6s
	l.Reload(mustRate("10/1m"), mustRate("100B/1m"), mustRate("1KB/1h"), map[string]Rate{"send_*": mustRate("1/1h"), "get_*": mustRate("5/1m")})
	if why := l.Call("", 0); why == "" {
		t.Fatal("a raised cap does not hand out tokens at once")
	}
	advance(6 * time.Second)
	if why := l.Call("", 0); why != "" {
		t.Fatalf("after refill: %s", why)
	}
	advance(6 * time.Second) // one more global token for the next call
	if why := l.Call("get_*", 0); why != "" {
		t.Fatalf("a new tool budget starts full: %s", why)
	}
	advance(6 * time.Second)
	if why := l.Call("", 200); !strings.Contains(why, "args_bytes") {
		t.Fatalf("a new args budget applies: %q", why)
	}
	if l.Egress("h", 2048) || !l.hasEgress() {
		t.Fatal("a new egress budget applies")
	}
	// lowered: the balance (full after a minute) is clamped to the new cap
	l.Call("send_*", 0)
	advance(time.Minute)
	l.Reload(mustRate("1/1m"), Rate{}, Rate{}, nil)
	if why := l.Call("", 0); why != "" {
		t.Fatalf("clamped to 1, one call fits: %s", why)
	}
	if why := l.Call("", 0); why == "" {
		t.Fatal("and no more")
	}
	advance(time.Minute) // refill the global budget; only the removed per-tool one is under test
	if why := l.Call("send_*", 0); why != "" {
		t.Fatalf("removed tool budget must not apply: %s", why)
	}
	if !l.Egress("h", 1<<20) || l.hasEgress() {
		t.Fatal("removed egress budget must not apply")
	}
	var nilL *Limiter
	nilL.Reload(mustRate("1/1m"), Rate{}, Rate{}, nil) // a nil limiter stays nil-safe
}

func TestCall(t *testing.T) {
	now, advance := clock(time.Unix(1_700_000_000, 0))
	l := New(mustRate("3/1m"), mustRate("100B/1m"), Rate{}, map[string]Rate{"send_*": mustRate("1/1h")}, now)
	if why := l.Call("", 10); why != "" {
		t.Fatal(why)
	}
	if why := l.Call("send_*", 10); why != "" {
		t.Fatal(why)
	}
	if why := l.Call("send_*", 10); why != "limit: tools[send_*] 1/1h exceeded" {
		t.Fatalf("per-tool: %q", why)
	}
	// the refused call did not use up the global budget: one call is left
	if why := l.Call("", 10); why != "" {
		t.Fatal(why)
	}
	if why := l.Call("", 10); why != "limit: calls 3/1m exceeded" {
		t.Fatalf("calls: %q", why)
	}
	advance(20 * time.Second) // one token back
	if why := l.Call("", 200); why != "limit: args_bytes 100B/1m exceeded" {
		t.Fatalf("args: %q", why)
	}
	if why := l.Call("", 50); why != "" {
		t.Fatalf("after a refused arg budget the call budget must still be there: %q", why)
	}
	var nilL *Limiter
	if nilL.Call("x", 1) != "" || !nilL.Egress("h", 5) {
		t.Fatal("nil limiter must allow")
	}
}

func TestEgress(t *testing.T) {
	now, advance := clock(time.Unix(1_700_000_000, 0))
	var refused []string
	l := New(Rate{}, Rate{}, mustRate("10B/1s"), nil, now)
	l.OnEgress = func(host, why string) { refused = append(refused, host+": "+why) }
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	w := l.Wrap(a, "example.com")
	if _, err := w.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrBudget) {
		t.Fatalf("over budget must fail with ErrBudget, got %v", err)
	}
	if !l.Egress("example.com", 0) { // the question "may I start?" needs one token
		_ = 0
	} else {
		t.Fatal("no tokens left, start must be refused")
	}
	advance(500 * time.Millisecond)
	if !l.Egress("example.com", 0) || !l.Egress("example.com", 5) {
		t.Fatal("half a window refills half the budget")
	}
	if len(refused) != 2 || refused[0] != "example.com: egress_bytes 10B/1s exceeded" {
		t.Fatalf("refusals: %q", refused)
	}
	if l.Wrap(a, "h") == nil || New(Rate{}, Rate{}, Rate{}, nil, nil).Wrap(a, "h") != a {
		t.Fatal("no budget: the connection is returned as is")
	}
}

func mustRate(s string) Rate {
	r, err := ParseRate(s)
	if err != nil {
		panic(err)
	}
	return r
}
