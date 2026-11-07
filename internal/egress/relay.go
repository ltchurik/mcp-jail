package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ltchurik/mcp-jail/internal/limits"
	"github.com/ltchurik/mcp-jail/internal/netguard"
)

// Allower decides whether a host may be reached.
type Allower interface {
	HostAllowed(host string) bool
}

// Observer is told about every decision: kind is "net" (a connection) or
// "dns" (a lookup the shim refused), allowed says which way it went.
type Observer func(kind, host string, allowed bool)

// Relay is the host side: it listens on a Unix socket for the shim.
type Relay struct {
	// Limits meters the bytes relayed towards the network; nil: no budget.
	Limits *limits.Limiter

	allow   Allower
	observe Observer
	ln      net.Listener
	dir     string
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	wg      sync.WaitGroup
}

// ListenRelay creates a private directory holding the Unix socket and starts
// serving. The directory is what gets bind-mounted into the jail.
func ListenRelay(allow Allower, observe Observer) (*Relay, error) {
	dir, err := os.MkdirTemp("", "mcp-jail-")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", SocketPath(dir))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	r := &Relay{allow: allow, observe: observe, ln: ln, dir: dir}
	// The allowlist is checked on the name; the guard checks what the name
	// resolved to, so a hostname cannot be pointed at the host's own services.
	d := netguard.Dialer(15*time.Second, allow.HostAllowed)
	r.dial = d.DialContext
	r.wg.Add(1)
	go r.serve()
	return r, nil
}

// SocketPath is the socket's path inside a relay directory.
func SocketPath(dir string) string { return dir + "/egress.sock" }

// Dir is the directory to bind-mount into the jail.
func (r *Relay) Dir() string { return r.dir }

// Close stops accepting and removes the directory. Open connections finish
// on their own.
func (r *Relay) Close() error {
	err := r.ln.Close()
	r.wg.Wait()
	_ = os.RemoveAll(r.dir)
	return err
}

func (r *Relay) serve() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(c)
	}
}

func (r *Relay) handle(c net.Conn) {
	br := bufio.NewReaderSize(c, 4096)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := readHeader(br)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if req.Verb == verbDNS {
		if r.observe != nil {
			r.observe("dns", req.Host, req.Decision == "allow")
		}
		_ = c.Close()
		return
	}
	ok := r.allow.HostAllowed(req.Host)
	if r.observe != nil {
		r.observe("net", req.Host, ok)
	}
	if !ok {
		_, _ = fmt.Fprintf(c, "ERR host not in network.allow: %s\n", req.Host)
		_ = c.Close()
		return
	}
	if !r.Limits.Egress(req.Host, 0) {
		_, _ = fmt.Fprintf(c, "ERR egress budget exceeded: %s\n", req.Host)
		_ = c.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	up, err := r.dial(ctx, "tcp", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(c, "ERR dial: %s\n", oneLine(err))
		_ = c.Close()
		return
	}
	if _, err := c.Write([]byte("OK\n")); err != nil {
		_ = up.Close()
		_ = c.Close()
		return
	}
	pipe(r.Limits.Wrap(up, req.Host), bufConn{Reader: br, Conn: c})
}

// bufConn replays bytes the header reader buffered ahead of the payload.
type bufConn struct {
	*bufio.Reader
	net.Conn
}

func (b bufConn) Read(p []byte) (int, error) { return b.Reader.Read(p) }

// CloseWrite half-closes the underlying connection so the peer sees EOF
// while the other direction keeps flowing.
func (b bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Close()
}

func oneLine(err error) string {
	s := err.Error()
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return s[:i]
		}
	}
	return s
}

// errRefused is what the shim reports when the relay said no.
var errRefused = errors.New("refused by relay")
