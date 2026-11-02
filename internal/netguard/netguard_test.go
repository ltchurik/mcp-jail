package netguard

import (
	"net"
	"testing"
)

func TestBlocked(t *testing.T) {
	blocked := []string{"127.0.0.1", "127.9.9.9", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "fe80::1", "fc00::1", "fd12::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "100.64.0.1", "100.127.255.255", "240.0.0.1", "255.255.255.255", "::ffff:127.0.0.1", "::ffff:10.0.0.1"}
	for _, s := range blocked {
		if !Blocked(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "::ffff:1.1.1.1"}
	for _, s := range public {
		if Blocked(net.ParseIP(s)) {
			t.Errorf("%s should pass", s)
		}
	}
	if !Blocked(nil) {
		t.Error("nil must be blocked")
	}
}

func TestControl(t *testing.T) {
	allow := func(ip string) bool { return ip == "127.0.0.1" }
	c := Control(allow)
	for _, addr := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443", "127.0.0.1:8080"} {
		if err := c("tcp", addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.1:80", "[::1]:80", "127.0.0.2:80", "169.254.169.254:80", "[fe80::1%en0]:80", "not-an-ip:80"} {
		if err := c("tcp", addr); err == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	if err := Control(nil)("tcp", "127.0.0.1:1"); err == nil {
		t.Error("nil allow must block loopback")
	}
}
