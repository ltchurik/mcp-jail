//go:build windows

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cmdExe() string {
	if c := os.Getenv("ComSpec"); c != "" {
		return c
	}
	return `C:\Windows\System32\cmd.exe`
}

// TestAppContainerIsolation starts cmd.exe in a real AppContainer: a file in
// a granted directory is readable, one outside is not, a read-only grant
// refuses writes, and the network follows the mode. It changes ACLs on
// temp directories and creates a profile, so it runs in CI or on request.
func TestAppContainerIsolation(t *testing.T) {
	if os.Getenv("CI") == "" && os.Getenv("MCP_JAIL_APPCONTAINER_TEST") == "" {
		t.Skip("creates an AppContainer profile and changes ACLs; set MCP_JAIL_APPCONTAINER_TEST=1")
	}
	root := t.TempDir()
	granted, outside := filepath.Join(root, "granted"), filepath.Join(root, "outside")
	for _, d := range []string{granted, outside} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f.txt"), []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	profile := profileName("test-" + hex.EncodeToString(rnd[:]))
	t.Cleanup(func() { _ = deleteProfile(profile) })

	run := func(net string, ro, rw []string, script string) int {
		t.Helper()
		code, err := RunAppContainer(AppContainerOptions{Profile: profile, Network: net, ReadOnly: ro, ReadWrite: rw,
			Command: []string{cmdExe(), "/c", script}}, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	diagnose := func() {
		t.Helper()
		out, _ := exec.Command(icaclsPath(), filepath.Join(granted, "f.txt")).CombinedOutput()
		t.Logf("acl of the file after the run:\n%s", out)
		_ = run("none", []string{granted}, nil, "whoami /all & icacls "+filepath.Join(granted, "f.txt"))
	}
	if c := run("none", []string{granted}, nil, "type "+filepath.Join(granted, "f.txt")); c != 0 {
		diagnose()
		t.Fatalf("granted file unreadable: exit %d", c)
	}
	if c := run("none", []string{granted}, nil, "type "+filepath.Join(outside, "f.txt")); c == 0 {
		t.Fatal("a file outside the granted directories was readable")
	}
	if c := run("none", []string{granted}, nil, "echo x > "+filepath.Join(granted, "new.txt")); c == 0 {
		t.Fatal("a read-only grant allowed a write")
	}
	if _, err := os.Stat(filepath.Join(granted, "new.txt")); err == nil {
		t.Fatal("new.txt was created through a read-only grant")
	}
	if c := run("none", nil, []string{granted}, "echo x > "+filepath.Join(granted, "rw.txt")); c != 0 {
		diagnose()
		t.Fatalf("a read_write grant refused a write: exit %d", c)
	}
	if _, err := os.Stat(filepath.Join(granted, "rw.txt")); err != nil {
		t.Fatal("rw.txt was not created through a read_write grant")
	}
	// the grant and the label are gone once the server has exited
	if out, _ := exec.Command(icaclsPath(), granted).CombinedOutput(); strings.Contains(string(out), "S-1-15-2-") || strings.Contains(string(out), "Low Mandatory") {
		t.Fatalf("container ACE or label left behind:\n%s", out)
	}
	// The network probe is this test binary, started inside the container
	// from its (granted) directory: TestNetProbeHelper does one HTTP GET.
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	probe := func(net string) int {
		t.Helper()
		code, err := RunAppContainer(AppContainerOptions{Profile: profile, Network: net, ReadOnly: []string{filepath.Dir(self)},
			Set: []string{"MCP_JAIL_NET_PROBE=1"}, Command: []string{self, "-test.run=^TestNetProbeHelper$"}}, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	if c := probe("none"); c == 0 {
		t.Fatal("network none: the container reached the internet")
	}
	if c := probe("all"); c != 0 {
		t.Fatalf("network all: probe exit %d", c)
	}
}

// TestNetProbeHelper is the body of the network probe above; on its own it
// does nothing.
func TestNetProbeHelper(t *testing.T) {
	if os.Getenv("MCP_JAIL_NET_PROBE") != "1" {
		t.Skip("helper for TestAppContainerIsolation")
	}
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get("http://example.com/")
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
	_ = resp.Body.Close()
	os.Exit(0)
}

func TestPlainScrubsEnvAndKeepsExitCode(t *testing.T) {
	t.Setenv("MCPJ_SECRET", "1")
	code, err := RunAppContainer(AppContainerOptions{Plain: true, Env: []string{"PATH"},
		Command: []string{cmdExe(), "/c", "if defined MCPJ_SECRET (exit 3) else (exit 0)"}}, t.Logf)
	if err != nil || code != 0 {
		t.Fatalf("secret leaked or failed: code %d, %v", code, err)
	}
	code, err = RunAppContainer(AppContainerOptions{Plain: true, Env: []string{"PATH", "MCPJ_SECRET"},
		Command: []string{cmdExe(), "/c", "if defined MCPJ_SECRET (exit 7) else (exit 0)"}}, t.Logf)
	if err != nil || code != 7 {
		t.Fatalf("listed variable missing or exit code lost: code %d, %v", code, err)
	}
}

func TestMergeEnv(t *testing.T) {
	got := mergeEnv([]string{"Path=a", "TEMP=x"}, []string{"PATH=b"}, []string{"HOME=h"})
	if strings.Join(got, ";") != "HOME=h;PATH=b;TEMP=x" {
		t.Fatalf("mergeEnv = %v", got)
	}
}
