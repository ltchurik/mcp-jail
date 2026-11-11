//go:build windows

package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

	run := func(net string, ro []string, script string) int {
		t.Helper()
		code, err := RunAppContainer(AppContainerOptions{Profile: profile, Network: net, ReadOnly: ro,
			Command: []string{cmdExe(), "/c", script}}, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	if c := run("none", []string{granted}, "type "+filepath.Join(granted, "f.txt")+" >NUL"); c != 0 {
		t.Fatalf("granted file unreadable: exit %d", c)
	}
	if c := run("none", []string{granted}, "type "+filepath.Join(outside, "f.txt")+" >NUL"); c == 0 {
		t.Fatal("a file outside the granted directories was readable")
	}
	if c := run("none", []string{granted}, "echo x > "+filepath.Join(granted, "new.txt")); c == 0 {
		t.Fatal("a read-only grant allowed a write")
	}
	if _, err := os.Stat(filepath.Join(granted, "new.txt")); err == nil {
		t.Fatal("new.txt was created through a read-only grant")
	}
	// the grant is gone once the server has exited
	if out, _ := exec.Command(icaclsPath(), granted).CombinedOutput(); strings.Contains(string(out), "S-1-15-2-") {
		t.Fatalf("container ACE left behind:\n%s", out)
	}
	curl := filepath.Join(filepath.Dir(cmdExe()), "curl.exe")
	if _, err := os.Stat(curl); err != nil {
		t.Skip("no curl.exe for the network check")
	}
	if c := run("none", nil, curl+" -sS -o NUL --max-time 20 https://example.com"); c == 0 {
		t.Fatal("network none: the container reached the internet")
	}
	if c := run("all", nil, curl+" -sS -o NUL --max-time 20 https://example.com"); c != 0 {
		t.Fatalf("network all: curl exit %d", c)
	}
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
