package egress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

func TestSniffSNI(t *testing.T) {
	// A real ClientHello from crypto/tls, captured on a pipe.
	c, s := net.Pipe()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: "API.Example.COM", InsecureSkipVerify: true}) //nolint:gosec // test
		_ = cl.Handshake()
		_ = c.Close()
	}()
	br := bufio.NewReaderSize(s, maxHelloLen+5)
	host, err := sniffSNI(br)
	if err != nil || host != "api.example.com" {
		t.Fatalf("got %q %v", host, err)
	}
	// Bytes must still be there for forwarding.
	if b, _ := br.Peek(5); b[0] != 0x16 {
		t.Fatal("client hello consumed")
	}
	_ = s.Close()

	for name, in := range map[string]string{
		"http":      "GET / HTTP/1.1\r\n",
		"empty":     "",
		"short":     "\x16\x03\x01",
		"not-hello": "\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00",
	} {
		if _, err := sniffSNI(bufio.NewReader(strings.NewReader(in))); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Hello without extensions: valid TLS but no SNI -> refuse.
	body := append([]byte{3, 3}, make([]byte, 32)...)                               // version + random
	body = append(body, 0)                                                          // session id
	body = append(body, 0, 2, 0x13, 0x01)                                           // one cipher suite
	body = append(body, 1, 0)                                                       // compression
	hs := append([]byte{1, 0, 0, uint8(len(body) & 0xFF)}, body...)                 // #nosec G115 -- fixture is < 256 bytes
	rec := append([]byte{0x16, 3, 1, 0, uint8(len(hs) & 0xFF)}, hs...)              // #nosec G115 -- same
	if _, err := sniffSNI(bufio.NewReader(bytes.NewReader(rec))); err != errNoSNI { //nolint:errorlint // sentinel
		t.Errorf("no extensions: got %v", err)
	}
}

func TestReadHTTPHead(t *testing.T) {
	cases := []struct {
		in         string
		host       string
		port       int
		method     string
		originLine string
	}{
		{"GET /x?y=1 HTTP/1.1\r\nHost: api.github.com\r\n\r\n", "api.github.com", 80, "GET", "GET /x?y=1 HTTP/1.1"},
		{"GET / HTTP/1.1\r\nHost: Example.COM.:8080\r\nConnection: keep-alive\r\n\r\n", "example.com", 8080, "GET", "GET / HTTP/1.1"},
		{"GET http://api.github.com/repos HTTP/1.1\r\nHost: api.github.com\r\nProxy-Connection: keep-alive\r\n\r\n", "api.github.com", 80, "GET", "GET /repos HTTP/1.1"},
		{"GET http://h.example:81 HTTP/1.1\r\nHost: h.example:81\r\n\r\n", "h.example", 81, "GET", "GET / HTTP/1.1"},
		{"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n", "api.github.com", 443, "CONNECT", ""},
		{"POST / HTTP/1.1\r\nHost: [::1]:9\r\nContent-Length: 3\r\n\r\nabc", "::1", 9, "POST", "POST / HTTP/1.1"},
	}
	for _, c := range cases {
		br := bufio.NewReader(strings.NewReader(c.in))
		h, err := readHTTPHead(br)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if h.host != c.host || h.port != c.port || h.method != c.method {
			t.Errorf("%q: got %s %s:%d", c.in, h.method, h.host, h.port)
		}
		if c.originLine != "" {
			of := originForm(h)
			first, _, _ := strings.Cut(string(of), "\r\n")
			if first != c.originLine {
				t.Errorf("%q: origin-form line %q, want %q", c.in, first, c.originLine)
			}
			if strings.Contains(strings.ToLower(string(of)), "proxy-connection") {
				t.Errorf("%q: proxy header not stripped", c.in)
			}
			if !strings.HasSuffix(string(of), "\r\nConnection: close\r\n\r\n") {
				t.Errorf("%q: head must end with Connection: close and a blank line: %q", c.in, of)
			}
			if strings.Count(strings.ToLower(string(of)), "connection:") != 1 {
				t.Errorf("%q: exactly one Connection header expected: %q", c.in, of)
			}
		}
		if c.method == "POST" {
			rest, _ := br.Peek(3)
			if string(rest) != "abc" {
				t.Errorf("body must remain in the reader, got %q", rest)
			}
		}
	}
	for _, in := range []string{"", "GET / HTTP/1.1\r\n\r\n", "garbage\r\n\r\n", "GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + strings.Repeat("a", 70<<10) + "\r\n\r\n"} {
		if _, err := readHTTPHead(bufio.NewReader(strings.NewReader(in))); err == nil {
			t.Errorf("%.40q: expected error", in)
		}
	}
}
