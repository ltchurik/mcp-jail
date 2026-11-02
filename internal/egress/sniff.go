package egress

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var (
	errNoSNI    = errors.New("egress: tls client hello without server_name")
	errNotTLS   = errors.New("egress: not a tls client hello")
	errBadHTTP  = errors.New("egress: malformed http request")
	errNoHost   = errors.New("egress: http request without host")
	maxHelloLen = 16 << 10
	maxHTTPHead = 64 << 10
)

// sniffSNI peeks a TLS ClientHello and returns the server_name. The bytes
// stay in the reader so they can be forwarded untouched.
func sniffSNI(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", errNotTLS
	}
	if hdr[0] != 0x16 || hdr[1] != 3 { // handshake record, TLS 1.x
		return "", errNotTLS
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < 4 || n > maxHelloLen {
		return "", errNotTLS
	}
	rec, err := br.Peek(5 + n)
	if err != nil {
		return "", errNotTLS
	}
	return parseClientHello(rec[5:])
}

// parseClientHello extracts server_name from a handshake message body.
func parseClientHello(b []byte) (string, error) {
	// handshake header: type(1) length(3)
	if len(b) < 4 || b[0] != 1 {
		return "", errNotTLS
	}
	hl := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if hl > len(b) {
		return "", errNotTLS
	}
	b = b[:hl]
	// client_version(2) random(32)
	if len(b) < 34 {
		return "", errNotTLS
	}
	b = b[34:]
	var ok bool
	if b, ok = skipVec(b, 1); !ok { // session_id
		return "", errNotTLS
	}
	if b, ok = skipVec(b, 2); !ok { // cipher_suites
		return "", errNotTLS
	}
	if b, ok = skipVec(b, 1); !ok { // compression_methods
		return "", errNotTLS
	}
	if len(b) < 2 {
		return "", errNoSNI // no extensions at all
	}
	el := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if el > len(b) {
		return "", errNotTLS
	}
	b = b[:el]
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if l > len(b) {
			return "", errNotTLS
		}
		ext := b[:l]
		b = b[l:]
		if typ != 0 { // server_name
			continue
		}
		if len(ext) < 2 {
			return "", errNotTLS
		}
		ll := int(binary.BigEndian.Uint16(ext))
		ext = ext[2:]
		if ll > len(ext) {
			return "", errNotTLS
		}
		ext = ext[:ll]
		for len(ext) >= 3 {
			nt := ext[0]
			nl := int(binary.BigEndian.Uint16(ext[1:]))
			ext = ext[3:]
			if nl > len(ext) {
				return "", errNotTLS
			}
			if nt == 0 { // host_name
				name := string(ext[:nl])
				if !validHost(name) {
					return "", errNoSNI
				}
				return strings.ToLower(strings.TrimSuffix(name, ".")), nil
			}
			ext = ext[nl:]
		}
	}
	return "", errNoSNI
}

func skipVec(b []byte, lenBytes int) ([]byte, bool) {
	if len(b) < lenBytes {
		return nil, false
	}
	var n int
	if lenBytes == 1 {
		n = int(b[0])
	} else {
		n = int(binary.BigEndian.Uint16(b))
	}
	b = b[lenBytes:]
	if n > len(b) {
		return nil, false
	}
	return b[n:], true
}

// httpHead is a parsed request head.
type httpHead struct {
	method string
	target string // request-target as sent
	host   string // destination host (from absolute target or Host header)
	port   int
	raw    []byte // the complete head including the blank line
}

// readHTTPHead reads one request head (up to the blank line) from br.
// It consumes the bytes; raw holds them for forwarding.
func readHTTPHead(br *bufio.Reader) (httpHead, error) {
	var raw bytes.Buffer
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				return httpHead{}, errBadHTTP
			}
			return httpHead{}, errBadHTTP
		}
		raw.Write(line)
		if raw.Len() > maxHTTPHead {
			return httpHead{}, errBadHTTP
		}
		if bytes.Equal(bytes.TrimRight(line, "\r\n"), nil) {
			break
		}
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw.Bytes())))
	if err != nil {
		return httpHead{}, errBadHTTP
	}
	h := httpHead{method: req.Method, target: req.RequestURI, raw: raw.Bytes()}
	hostport := req.Host
	defPort := 80
	if req.Method == http.MethodConnect {
		hostport = req.RequestURI
		defPort = 443
	} else if u, err := url.Parse(req.RequestURI); err == nil && u.IsAbs() {
		hostport = u.Host
		if u.Scheme == "https" {
			defPort = 443
		}
	}
	h.host, h.port, err = splitHostPort(hostport, defPort)
	if err != nil {
		return httpHead{}, errNoHost
	}
	return h, nil
}

func splitHostPort(hp string, def int) (string, int, error) {
	if hp == "" {
		return "", 0, errNoHost
	}
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		host, ps = hp, strconv.Itoa(def)
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			return "", 0, errNoHost
		}
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 || !validHost(host) {
		return "", 0, errNoHost
	}
	return host, port, nil
}

// originForm rewrites a proxy-style absolute-form request line into the
// origin-form an origin server expects, drops proxy-only headers and forces
// Connection: close. One request per connection means every request gets
// its own Host check; a kept-alive connection could otherwise carry a second
// request for a different host down a pipe that was opened for the first.
// The body, if any, is untouched (it follows raw in the stream).
func originForm(h httpHead) []byte {
	lines := bytes.Split(h.raw, []byte("\n"))
	if len(lines) == 0 {
		return h.raw
	}
	first := string(bytes.TrimRight(lines[0], "\r"))
	parts := strings.SplitN(first, " ", 3)
	if len(parts) == 3 {
		if u, err := url.Parse(parts[1]); err == nil && u.IsAbs() {
			path := u.RequestURI()
			if path == "" {
				path = "/"
			}
			parts[1] = path
			lines[0] = []byte(strings.Join(parts, " ") + "\r")
		}
	}
	out := make([][]byte, 0, len(lines)+1)
	for i, l := range lines {
		if i > 0 {
			k := strings.ToLower(string(bytes.TrimSpace(bytes.SplitN(l, []byte(":"), 2)[0])))
			if k == "proxy-connection" || k == "proxy-authorization" || k == "connection" {
				continue
			}
		}
		if len(bytes.TrimRight(l, "\r")) == 0 && i > 0 && i == len(lines)-2 {
			out = append(out, []byte("Connection: close\r")) // before the blank line
		}
		out = append(out, l)
	}
	return bytes.Join(out, []byte("\n"))
}
