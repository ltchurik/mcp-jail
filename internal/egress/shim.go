package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Default ports the shim binds inside the jail (all on 127.0.0.1).
const (
	PortDNS   = 53
	PortHTTP  = 80
	PortHTTPS = 443
	PortProxy = 3128
)

// Shim is the in-jail half. It owns the loopback listeners and forwards each
// connection to the relay socket.
type Shim struct {
	Socket string   // path of the relay socket inside the jail
	Allow  []string // network.allow, for fast local refusal and DNS answers
	Logf   func(format string, args ...any)

	dns   net.PacketConn
	ports []net.Listener
}

// Listen binds the loopback listeners. ports are, in order, DNS (udp), HTTP,
// HTTPS and proxy; 0 picks an ephemeral port (tests).
func (s *Shim) Listen(dns, http, https, proxy int) error {
	pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(dns))
	if err != nil {
		return fmt.Errorf("dns listener: %w", err)
	}
	s.dns = pc
	for _, p := range []int{http, https, proxy} {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			s.Close()
			return fmt.Errorf("listener :%d: %w", p, err)
		}
		s.ports = append(s.ports, ln)
	}
	return nil
}

// Addrs returns the bound DNS, HTTP, HTTPS and proxy addresses.
func (s *Shim) Addrs() (dns, http, https, proxy string) {
	return s.dns.LocalAddr().String(), s.ports[0].Addr().String(), s.ports[1].Addr().String(), s.ports[2].Addr().String()
}

// Serve runs all listeners until Close.
func (s *Shim) Serve() {
	go serveDNS(s.dns, s.decideDNS)
	go s.accept(s.ports[0], s.handleHTTP)
	go s.accept(s.ports[1], s.handleTLS)
	s.accept(s.ports[2], s.handleProxy)
}

// Close shuts every listener.
func (s *Shim) Close() {
	if s.dns != nil {
		_ = s.dns.Close()
	}
	for _, ln := range s.ports {
		_ = ln.Close()
	}
}

func (s *Shim) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Shim) accept(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go h(c)
	}
}

// hostAllowed mirrors policy.HostAllowed; the relay re-checks anyway.
func (s *Shim) hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range s.Allow {
		a = strings.ToLower(a)
		if a == host {
			return true
		}
		if strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:]) {
			return true
		}
	}
	return false
}

func (s *Shim) decideDNS(name string) bool {
	ok := s.hostAllowed(name)
	if !ok {
		s.notify(Request{Verb: verbDNS, Host: name, Decision: "blocked"})
	}
	return ok
}

// notify sends an audit-only line to the relay.
func (s *Shim) notify(r Request) {
	c, err := net.DialTimeout("unix", s.Socket, 2*time.Second)
	if err != nil {
		return
	}
	_, _ = io.WriteString(c, r.String())
	_ = c.Close()
}

// connect asks the relay for a TCP connection to host:port.
func (s *Shim) connect(host string, port int) (net.Conn, error) {
	if !s.hostAllowed(host) {
		return nil, fmt.Errorf("host not in network.allow: %s", host)
	}
	c, err := net.DialTimeout("unix", s.Socket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("relay unavailable: %w", err)
	}
	if _, err := io.WriteString(c, Request{Verb: verbConnect, Host: host, Port: port}.String()); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if err := readStatus(br); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%w: %w", errRefused, err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return bufConn{Reader: br, Conn: c}, nil
}

// handleTLS: transparent HTTPS. The destination comes from the SNI.
func (s *Shim) handleTLS(c net.Conn) {
	br := bufio.NewReaderSize(c, maxHelloLen+5)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	host, err := sniffSNI(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		s.logf("egress: :443 %v", err)
		_ = c.Close()
		return
	}
	up, err := s.connect(host, PortHTTPS)
	if err != nil {
		s.logf("egress: %s:443 %v", host, err)
		_ = c.Close() // no way to speak an error inside a TLS stream we don't own
		return
	}
	pipe(up, bufConn{Reader: br, Conn: c})
}

// handleHTTP: transparent plain HTTP. The destination comes from Host.
func (s *Shim) handleHTTP(c net.Conn) {
	br := bufio.NewReaderSize(c, 64<<10)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	h, err := readHTTPHead(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		httpError(c, 400, err.Error())
		return
	}
	if h.method == "CONNECT" {
		httpError(c, 405, "CONNECT on :80 is not supported; use the proxy on :3128")
		return
	}
	up, err := s.connect(h.host, h.port)
	if err != nil {
		s.logf("egress: %s:%d %v", h.host, h.port, err)
		httpError(c, statusFor(err), err.Error())
		return
	}
	if _, err := up.Write(originForm(h)); err != nil {
		_ = up.Close()
		_ = c.Close()
		return
	}
	pipe(up, bufConn{Reader: br, Conn: c})
}

// handleProxy: an explicit HTTP proxy for clients that honour HTTP_PROXY.
func (s *Shim) handleProxy(c net.Conn) {
	br := bufio.NewReaderSize(c, 64<<10)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	h, err := readHTTPHead(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		httpError(c, 400, err.Error())
		return
	}
	up, err := s.connect(h.host, h.port)
	if err != nil {
		s.logf("egress: proxy %s:%d %v", h.host, h.port, err)
		httpError(c, statusFor(err), err.Error())
		return
	}
	if h.method == "CONNECT" {
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = up.Close()
			_ = c.Close()
			return
		}
	} else if _, err := up.Write(originForm(h)); err != nil {
		_ = up.Close()
		_ = c.Close()
		return
	}
	pipe(up, bufConn{Reader: br, Conn: c})
}

func statusFor(err error) int {
	if strings.Contains(err.Error(), "network.allow") {
		return 403
	}
	return 502
}

func httpError(c net.Conn, code int, msg string) {
	body := "mcp-jail: " + msg + "\n"
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, statusText(code), len(body), body)
	_ = c.Close()
}

func statusText(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 405:
		return "Method Not Allowed"
	default:
		return "Bad Gateway"
	}
}

// ResolvConf is what the jail gets as /etc/resolv.conf.
const ResolvConf = "# generated by mcp-jail: all lookups go to the egress shim\nnameserver 127.0.0.1\noptions ndots:0 attempts:1 timeout:2\n"

// ProxyEnv returns the environment that points cooperative clients at the
// shim's proxy. NODE_USE_ENV_PROXY makes Node's built-in fetch honour it.
func ProxyEnv() map[string]string {
	addr := "http://127.0.0.1:" + strconv.Itoa(PortProxy)
	env := map[string]string{"NO_PROXY": "", "no_proxy": "", "NODE_USE_ENV_PROXY": "1"}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env[k] = addr
	}
	return env
}

// RunShim is the entry point of `mcp-jail _egress-shim`: bind the listeners,
// start the server with argv under the given uid/gid, wait, exit like it did.
func RunShim(socket string, allow []string, uid, gid int, argv []string, logf func(string, ...any)) (int, error) {
	if len(argv) == 0 {
		return 2, fmt.Errorf("egress shim: no server command")
	}
	s := &Shim{Socket: socket, Allow: allow, Logf: logf}
	if err := s.Listen(PortDNS, PortHTTP, PortHTTPS, PortProxy); err != nil {
		return 1, fmt.Errorf("egress shim: %w (is the jail's net namespace ours?)", err)
	}
	go s.Serve()
	code, err := runServer(argv, uid, gid)
	s.Close()
	return code, err
}
