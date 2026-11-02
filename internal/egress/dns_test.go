package egress

import (
	"context"
	"net"
	"testing"
	"time"
)

// Use Go's own resolver against serveDNS: if that round-trips, the wire
// format is right for real clients too.
func TestDNSResponder(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	var asked []string
	go serveDNS(pc, func(name string) bool {
		asked = append(asked, name)
		return name == "api.github.com" || name == "x.githubusercontent.com"
	})
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := r.LookupHost(ctx, "API.github.com.")
	if err != nil || len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("allowed name: %v %v", ips, err)
	}
	ips, err = r.LookupHost(ctx, "evil.example")
	var dnsErr *net.DNSError
	if err == nil || !asDNSError(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("blocked name must be NXDOMAIN, got %v %v", ips, err)
	}
	// AAAA for an allowed name: empty NOERROR, so the client falls back to A.
	ip6, err := r.LookupIP(ctx, "ip6", "x.githubusercontent.com")
	if err == nil && len(ip6) > 0 {
		t.Fatalf("no AAAA expected, got %v", ip6)
	}
}

func asDNSError(err error, target **net.DNSError) bool {
	for err != nil {
		if e, ok := err.(*net.DNSError); ok { //nolint:errorlint // walking the chain by hand
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error }) //nolint:errorlint // same
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestDNSMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 12), append([]byte{0, 1, 0x80}, make([]byte, 9)...)} {
		if _, err := parseDNSQuery(b); err == nil {
			t.Errorf("%v: expected error", b)
		}
	}
	// two questions
	q := make([]byte, 12)
	q[5] = 2
	if _, err := parseDNSQuery(q); err == nil {
		t.Error("qdcount=2 must fail")
	}
	// compression pointer in the question name
	q = append(make([]byte, 12), 0xC0, 0x0C, 0, 1, 0, 1)
	q[5] = 1
	if _, err := parseDNSQuery(q); err == nil {
		t.Error("compression pointer must fail")
	}
	if r := dnsRefused([]byte{0xAB, 0xCD, 1, 1}, rcodeNotImp); len(r) != 12 || r[0] != 0xAB || r[3]&0xF != rcodeNotImp {
		t.Errorf("refused = %v", r)
	}
}
