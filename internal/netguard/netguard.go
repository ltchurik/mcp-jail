// Package netguard refuses outbound connections to addresses the host
// itself owns or that only make sense inside a private network, unless the
// policy names that exact address. An allowlisted hostname is still under
// the control of whoever runs its DNS; without this check it could be
// pointed at 127.0.0.1 or 10.0.0.0/8 and the jail's "egress" would reach the
// host's local services.
package netguard

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// Blocked reports whether ip is loopback, private, link-local, multicast,
// unspecified, carrier-grade NAT or otherwise not a public unicast address.
func Blocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		switch {
		case v4[0] == 0: // 0.0.0.0/8 "this network"
			return true
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 CGNAT
			return true
		case v4[0] >= 240: // 240.0.0.0/4 reserved, 255.255.255.255
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// Control is a net.Dialer.Control function: it sees the resolved address
// and refuses a Blocked one unless allowed(ip) says the policy lists that
// literal address.
func Control(allowed func(ip string) bool) func(network, address string) error {
	return func(_, address string) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		host = strings.Trim(host, "[]")
		if i := strings.IndexByte(host, '%'); i >= 0 { // zone
			host = host[:i]
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("netguard: %q is not an IP address", host)
		}
		if !Blocked(ip) || (allowed != nil && allowed(ip.String())) {
			return nil
		}
		return fmt.Errorf("netguard: %s is a local or private address; list it in network.allow to reach it", ip)
	}
}

// Dialer returns a net.Dialer whose connections pass Control(allowed).
func Dialer(timeout time.Duration, allowed func(ip string) bool) *net.Dialer {
	check := Control(allowed)
	return &net.Dialer{Timeout: timeout, Control: func(network, address string, _ syscall.RawConn) error {
		return check(network, address)
	}}
}
