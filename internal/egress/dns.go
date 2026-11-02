package egress

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// A minimal DNS responder: allowed names resolve to 127.0.0.1, everything
// else is NXDOMAIN. Only the question section is parsed; the answer echoes
// the question and adds at most one A record. Enough for getaddrinfo in
// glibc, musl, Go, Node (c-ares) and Python.

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsClassIN  = 1
	rcodeNX     = 3
	rcodeNotImp = 4
	rcodeRefuse = 5
)

var errDNS = errors.New("egress: malformed dns query")

// dnsQuery is the decoded question of a request.
type dnsQuery struct {
	id    uint16
	name  string
	qtype uint16
	raw   []byte // question section as received, replayed in the answer
}

func parseDNSQuery(b []byte) (dnsQuery, error) {
	if len(b) < 12 {
		return dnsQuery{}, errDNS
	}
	q := dnsQuery{id: binary.BigEndian.Uint16(b[0:2])}
	if b[2]&0x80 != 0 { // QR set: this is a response, not a query
		return dnsQuery{}, errDNS
	}
	if binary.BigEndian.Uint16(b[4:6]) != 1 { // exactly one question
		return dnsQuery{}, errDNS
	}
	labels, off, err := parseName(b, 12)
	if err != nil {
		return dnsQuery{}, err
	}
	if off+4 > len(b) {
		return dnsQuery{}, errDNS
	}
	q.qtype = binary.BigEndian.Uint16(b[off : off+2])
	if binary.BigEndian.Uint16(b[off+2:off+4]) != dnsClassIN {
		return dnsQuery{}, errDNS
	}
	q.name = strings.ToLower(strings.Join(labels, "."))
	q.raw = b[12 : off+4]
	return q, nil
}

// parseName reads an uncompressed name starting at off and returns its
// labels and the offset just past the terminating zero length.
func parseName(b []byte, off int) ([]string, int, error) {
	var labels []string
	for off < len(b) {
		l := int(b[off])
		off++
		if l == 0 {
			return labels, off, nil
		}
		if l&0xC0 != 0 || len(labels) > 127 {
			return nil, 0, errDNS // compression pointers never appear in a question name
		}
		end := off + l
		if end > len(b) {
			return nil, 0, errDNS
		}
		labels = append(labels, string(b[off:end]))
		off = end
	}
	return nil, 0, errDNS
}

// dnsAnswer builds the response. allowed=false yields NXDOMAIN. For allowed
// names an A query gets 127.0.0.1; AAAA (and anything else) gets an empty
// NOERROR so resolvers fall back to IPv4 instead of failing.
func dnsAnswer(q dnsQuery, allowed bool) []byte {
	out := make([]byte, 12, 12+len(q.raw)+16)
	binary.BigEndian.PutUint16(out[0:2], q.id)
	flags := uint16(0x8180) // QR, RD, RA
	if !allowed {
		flags |= rcodeNX
	}
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	out = append(out, q.raw...)
	if allowed && q.qtype == dnsTypeA {
		binary.BigEndian.PutUint16(out[6:8], 1) // ANCOUNT
		out = append(out, 0xC0, 0x0C)           // pointer to the question name
		out = binary.BigEndian.AppendUint16(out, dnsTypeA)
		out = binary.BigEndian.AppendUint16(out, dnsClassIN)
		out = binary.BigEndian.AppendUint32(out, 60) // TTL
		out = binary.BigEndian.AppendUint16(out, 4)
		out = append(out, 127, 0, 0, 1)
	}
	return out
}

// dnsRefused answers a query we could not parse at all.
func dnsRefused(b []byte, rcode uint16) []byte {
	if len(b) < 2 {
		return nil
	}
	out := make([]byte, 12)
	copy(out, b[:2])
	binary.BigEndian.PutUint16(out[2:4], 0x8180|rcode)
	return out
}

// serveDNS answers queries on pc until it is closed. decide is called with the
// lowercase name and must say whether it is allowed.
func serveDNS(pc net.PacketConn, decide func(name string) bool) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q, err := parseDNSQuery(buf[:n])
		if err != nil {
			_, _ = pc.WriteTo(dnsRefused(buf[:n], rcodeNotImp), addr)
			continue
		}
		_, _ = pc.WriteTo(dnsAnswer(q, decide(q.name)), addr)
	}
}
