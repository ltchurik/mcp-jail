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
	"syscall"
	"testing"
	"time"
	"unsafe"
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

// TestCapabilityVariants (temporary experiment): which capability SIDs
// CreateProcess accepts for a lowbox, and what each lets cmd.exe list.
func TestCapabilityVariants(t *testing.T) {
	if os.Getenv("CI") == "" && os.Getenv("MCP_JAIL_APPCONTAINER_TEST") == "" {
		t.Skip("creates an AppContainer profile")
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	profile := profileName("caps-" + hex.EncodeToString(rnd[:]))
	t.Cleanup(func() { _ = deleteProfile(profile) })
	sid, sidStr, err := ensureProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	folder, err := containerFolder(sidStr)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	lpacAppExperience := "S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622"
	iso := []string{capabilitySID("isolatedWin32-volumeRootMinimal"), capabilitySID("isolatedWin32-profilesRootMinimal"), capabilitySID("isolatedWin32-userProfileMinimal")}
	variants := []struct {
		name string
		lpac bool
		sids []string
	}{
		{"none", false, nil},
		{"userProfileMinimal", false, iso[2:]},
		{"lpacAppExperience", false, []string{lpacAppExperience}},
		{"three isolatedWin32", false, iso},
		{"internetClient+userProfileMinimal", false, []string{capInternetClient, iso[2]}},
		{"LPAC lpacAppExperience", true, []string{lpacAppExperience}},
		{"LPAC lpacAppExperience+three", true, append([]string{lpacAppExperience}, iso...)},
		{"LPAC none", true, nil},
	}
	env := mergeEnv(windowsBaseEnv(), nil, []string{"USERPROFILE=" + home})
	for _, v := range variants {
		var caps []sidAndAttributes
		for _, n := range v.sids {
			s16, _ := syscall.UTF16PtrFromString(n)
			var p uintptr
			if r, _, e := procConvertStringSidToSid.Call(uintptr(unsafe.Pointer(s16)), uintptr(unsafe.Pointer(&p))); r == 0 {
				t.Fatalf("%s: %v", n, e)
			}
			caps = append(caps, sidAndAttributes{Sid: p, Attributes: seGroupEnabled})
		}
		for _, probe := range []string{"exit 0", `dir C:\`, `dir C:\Users`, `dir "` + home + `"`, `dir C:\Windows`, `dir "C:\Program Files"`} {
			code, err := startLowbox(cmdExe(), []string{cmdExe(), "/c", probe + " >" + filepath.Join(folder, "out.txt") + " 2>&1"}, env, folder, sid, caps, v.lpac)
			out, _ := os.ReadFile(filepath.Join(folder, "out.txt"))
			first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
			t.Logf("%-34s %-28s code=%d err=%v  %s", v.name, probe, code, err, first)
			if err != nil {
				break
			}
		}
	}
}
