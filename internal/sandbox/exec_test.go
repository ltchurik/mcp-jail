package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

func pinned(t *testing.T, dir string) (path, digest string) {
	t.Helper()
	path = filepath.Join(dir, "srv")
	writeExec(t, path)
	b, _ := os.ReadFile(path)
	sum := sha256.Sum256(b)
	return path, hex.EncodeToString(sum[:])
}

func TestCheckExec(t *testing.T) {
	dir := t.TempDir()
	path, digest := pinned(t, dir)
	p := policy.Default()
	p.Exec.Allow = []string{path}
	if err := checkExec(p); err != nil {
		t.Fatalf("allowed without a pin: %v", err)
	}
	p.Exec.SHA256 = map[string]string{path: digest}
	if err := checkExec(p); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	p.Exec.SHA256[path] = strings.Repeat("0", 64)
	if err := checkExec(p); err == nil || !strings.Contains(err.Error(), "has changed") {
		t.Fatalf("mismatch must refuse: %v", err)
	}
	p.Exec.SHA256 = nil
	p.Exec.Allow = []string{filepath.Join(dir, "nope")}
	if err := checkExec(p); err == nil {
		t.Fatal("a missing file must refuse")
	}
	p.Exec.Allow = []string{dir}
	if err := checkExec(p); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("a directory must refuse: %v", err)
	}

	// disabled sandbox or a platform without one cannot enforce a pin
	p.Exec.Allow = []string{path}
	p.Sandbox.Disabled = true
	if _, _, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}}); err == nil || !strings.Contains(err.Error(), "exec.allow") {
		t.Fatalf("disabled + exec must refuse: %v", err)
	}

	pins := execPins(p)
	if len(pins) != 1 || pins[0].Status != "not pinned" {
		t.Fatalf("pins: %+v", pins)
	}
	p.Exec.SHA256 = map[string]string{path: digest}
	if pins := execPins(p); pins[0].Status != "ok" {
		t.Fatalf("pins: %+v", pins)
	}
	p.Exec.SHA256[path] = strings.Repeat("0", 64)
	if pins := execPins(p); pins[0].Status != "sha256 mismatch" {
		t.Fatalf("pins: %+v", pins)
	}
	p.Exec.Allow = []string{filepath.Join(dir, "nope")}
	if pins := execPins(p); pins[0].Status != "missing" {
		t.Fatalf("pins: %+v", pins)
	}
}

func TestBuildBwrapExecPins(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	bin := t.TempDir()
	writeExec(t, filepath.Join(bin, "bwrap"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	dir := t.TempDir()
	path, digest := pinned(t, dir)
	inside := filepath.Join(dir, "ro", "tool")
	if err := os.MkdirAll(filepath.Dir(inside), 0o750); err != nil {
		t.Fatal(err)
	}
	writeExec(t, inside)

	p := policy.Default()
	p.Network.Mode = policy.NetNone
	p.Filesystem.ReadOnly = []string{filepath.Join(dir, "ro")}
	p.Exec.Allow = []string{path, inside}
	p.Exec.SHA256 = map[string]string{path: digest}
	argv, how, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--ro-bind "+path+" "+path) {
		t.Errorf("pinned file not bound: %s", joined)
	}
	if strings.Contains(joined, "--ro-bind "+inside+" "+inside) {
		t.Errorf("a file inside a bound dir needs no bind of its own: %s", joined)
	}
	if !strings.Contains(how, "2 exec pin(s)") || !strings.Contains(how, "siblings are executable too") {
		t.Errorf("how = %q", how)
	}
	p.Exec.SHA256[path] = strings.Repeat("0", 64)
	if _, _, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}}); err == nil {
		t.Fatal("a changed pinned file must not start")
	}
}

func TestDarwinProfileExecPins(t *testing.T) {
	skipWindows(t, "sandbox-exec profiles are built from Unix paths")
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(home, ".local", "bin", "srv")
	writeExec(t, pin)
	ro := filepath.Join(home, "projects")
	if err := os.MkdirAll(ro, 0o750); err != nil {
		t.Fatal(err)
	}
	p := policy.Default()
	p.Network.Mode = policy.NetNone
	p.Filesystem.ReadOnly = []string{ro}
	p.Exec.Allow = []string{pin}
	prof := darwinProfile(p, Spec{}, profilePaths{home: home, userTmp: filepath.Join(root, "tmp"), toolchain: filepath.Join(home, ".nvm")})
	for _, want := range []string{
		`(deny process-exec* (subpath "/Users") (subpath "` + home + `") (subpath "` + root + `/tmp"))`,
		`(allow process-exec* (subpath "` + ro + `") (subpath "` + home + `/.nvm"))`,
		`(allow process-exec* (literal "` + pin + `"))`,
		`(allow file-read* (literal "` + pin + `"))`,
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q:\n%s", want, prof)
		}
	}
	// the exec deny must come after the general allow and before the state deny at the end
	if strings.Index(prof, "(deny process-exec*") < strings.Index(prof, "(allow default)") {
		t.Error("exec rules must follow (allow default)")
	}
	p.Exec.Allow = nil
	if prof := darwinProfile(p, Spec{}, profilePaths{home: home}); strings.Contains(prof, "process-exec") {
		t.Errorf("no pins, no exec rules:\n%s", prof)
	}
}
