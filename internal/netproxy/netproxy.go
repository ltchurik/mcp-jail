// Package netproxy is a small HTTP forward proxy (plain + CONNECT) that only
// lets listed hosts through. It is cooperative: the jailed process must
// honour HTTP_PROXY/HTTPS_PROXY, which nearly every HTTP client does.
package netproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Allower decides whether a host may be reached.
type Allower interface {
	HostAllowed(host string) bool
}

// Observer receives one call per connection attempt.
type Observer func(host string, allowed bool)

// Proxy is a filtering forward proxy.
type Proxy struct {
	allow   Allower
	observe Observer
	ln      net.Listener
}

// Listen starts the proxy on 127.0.0.1:0 and returns it.
func Listen(allow Allower, observe Observer) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{allow: allow, observe: observe, ln: ln}
	go p.serve()
	return p, nil
}

// Addr returns the proxy URL to put into HTTP_PROXY / HTTPS_PROXY.
func (p *Proxy) Addr() string { return "http://" + p.ln.Addr().String() }

// Close stops the listener.
func (p *Proxy) Close() error { return p.ln.Close() }

func (p *Proxy) serve() {
	srv := &http.Server{
		Handler:           http.HandlerFunc(p.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	_ = srv.Serve(p.ln)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if r.Method == http.MethodConnect {
		host, _, _ = net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
	}
	ok := p.allow.HostAllowed(host)
	if p.observe != nil {
		p.observe(host, ok)
	}
	if !ok {
		http.Error(w, "mcp-jail: host not in network.allow: "+host, http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	p.forward(w, r)
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	up, err := d.DialContext(ctx, "tcp", r.Host)
	if err != nil {
		http.Error(w, "dial: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	cl, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = fmt.Fprint(cl, "HTTP/1.1 200 Connection Established\r\n\r\n")
	go pipe(up, readerOf(buf, cl))
	pipe(cl, up)
	up.Close()
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "proxy request must be absolute", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	stripHop(out.Header)
	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func stripHop(h http.Header) {
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
	for _, c := range h.Values("Connection") {
		for _, f := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
}

type rwConn struct {
	io.Reader
	net.Conn
}

func (c rwConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

func readerOf(buf *bufio.ReadWriter, c net.Conn) net.Conn {
	if buf.Reader.Buffered() > 0 {
		return rwConn{Reader: buf.Reader, Conn: c}
	}
	return c
}

func pipe(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
