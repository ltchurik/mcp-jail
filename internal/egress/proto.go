package egress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Wire protocol on the Unix socket. The shim sends exactly one header line,
// the relay answers with exactly one status line, then both sides pipe bytes.
//
//	CONNECT <host> <port>\n     open a TCP connection to host:port
//	DNS <name> <allow|blocked>\n audit-only notice; the relay closes the socket
//
//	OK\n                         connection established
//	ERR <message>\n              refused; the socket is closed

const (
	verbConnect = "CONNECT"
	verbDNS     = "DNS"
	maxHeader   = 1024
)

// Request is one parsed header line.
type Request struct {
	Verb     string
	Host     string
	Port     int    // CONNECT only
	Decision string // DNS only
}

// ErrBadHeader is returned for malformed header lines.
var ErrBadHeader = errors.New("egress: bad header")

func (r Request) String() string {
	if r.Verb == verbDNS {
		return fmt.Sprintf("%s %s %s\n", verbDNS, r.Host, r.Decision)
	}
	return fmt.Sprintf("%s %s %d\n", verbConnect, r.Host, r.Port)
}

// readHeader reads and parses one header line.
func readHeader(r *bufio.Reader) (Request, error) {
	line, err := readLine(r)
	if err != nil {
		return Request{}, err
	}
	f := strings.Fields(line)
	if len(f) != 3 {
		return Request{}, ErrBadHeader
	}
	switch f[0] {
	case verbConnect:
		port, err := strconv.Atoi(f[2])
		if err != nil || port < 1 || port > 65535 || !validHost(f[1]) {
			return Request{}, ErrBadHeader
		}
		return Request{Verb: verbConnect, Host: f[1], Port: port}, nil
	case verbDNS:
		if f[2] != "allow" && f[2] != "blocked" || !validHost(f[1]) {
			return Request{}, ErrBadHeader
		}
		return Request{Verb: verbDNS, Host: f[1], Decision: f[2]}, nil
	}
	return Request{}, ErrBadHeader
}

// readStatus reads the relay's answer; nil means OK.
func readStatus(r *bufio.Reader) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if line == "OK" {
		return nil
	}
	if msg, ok := strings.CutPrefix(line, "ERR "); ok {
		return errors.New(msg)
	}
	return ErrBadHeader
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return "", ErrBadHeader
		}
		return "", err
	}
	if len(line) > maxHeader {
		return "", ErrBadHeader
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// validHost accepts DNS names and IP literals; anything with spaces, slashes
// or control characters is refused so a header line cannot be smuggled.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return true
	}
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// pipe copies in both directions and closes both ends when either side is done.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}
