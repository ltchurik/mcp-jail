// Package egress implements the hard network allowlist used on Linux.
//
// The jailed server runs in a network namespace that has only a loopback
// interface (bwrap --unshare-net). Nothing can leave that namespace except
// through a Unix socket that mcp-jail bind-mounts into the jail. Two halves
// cooperate:
//
//   - Shim (inside the jail): mcp-jail re-executes itself as PID-1-ish helper
//     before the server starts. It answers DNS on 127.0.0.1:53 (allowed names
//     resolve to 127.0.0.1, everything else is NXDOMAIN), accepts plain HTTP
//     on :80 (Host header), TLS on :443 (SNI) and acts as an HTTP proxy on
//     :3128 (CONNECT / absolute-form). Every connection is forwarded over the
//     Unix socket together with the destination it sniffed.
//
//   - Relay (on the host, inside the mcp-jail process): accepts connections
//     from the shim, checks the destination against network.allow, dials it
//     on the host network and pipes bytes. The relay is authoritative; the
//     shim's own checks are only there to fail fast with a readable error.
//
// A server that ignores HTTP_PROXY still works for HTTP and HTTPS because the
// fake resolver points every allowed name at the shim. A server that tries
// anything else (raw TCP to an IP, UDP, a host that is not listed) gets
// ENETUNREACH or NXDOMAIN. No CAP_NET_ADMIN, no pasta, no iptables.
package egress
