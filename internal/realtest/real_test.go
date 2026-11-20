// Package realtest drives a real MCP server, the reference filesystem server
// (node), through the built binary under whichever sandbox this host has:
// bubblewrap on Linux, sandbox-exec on macOS, an AppContainer on Windows.
// The suite's own python and echo servers never hit what a real toolchain
// does (node checks its stdio at start, npm caches, realpath on every
// ancestor); this does. It builds the binary, installs the server with npm
// and needs node, so it only runs with MCP_JAIL_E2E_REAL=1 (make e2e, CI).
package realtest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const serverPkg = "@modelcontextprotocol/server-filesystem@2.3.0"

type fixture struct {
	bin, root, webshop, secret, srv, state, serverJS, home string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("MCP_JAIL_E2E_REAL") == "" {
		t.Skip("builds the binary and installs a node server; set MCP_JAIL_E2E_REAL=1")
	}
	for _, tool := range []string{"node", "npm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s not in PATH: %v", tool, err)
		}
	}
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil { // macOS: /var -> /private/var
		root = real
	}
	f := &fixture{root: root}
	f.webshop = filepath.Join(root, "webshop")
	f.secret = filepath.Join(root, "secret")
	f.srv = filepath.Join(root, "srv")
	f.state = filepath.Join(root, "state")
	for _, d := range []string{f.webshop, f.secret, f.srv, f.state, filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	must(t, os.WriteFile(filepath.Join(f.webshop, "README.md"), []byte("webshop readme\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(f.secret, "key.txt"), []byte("hunter2\n"), 0o600))
	home, err := os.UserHomeDir()
	must(t, err)
	f.home = home

	f.bin = filepath.Join(root, "bin", "mcp-jail")
	if runtime.GOOS == "windows" {
		f.bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", f.bin, "github.com/ltchurik/mcp-jail/cmd/mcp-jail").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	npm := exec.Command("npm", "install", "--prefix", f.srv, "--prefer-offline", "--no-audit", "--no-fund", "--loglevel=error", serverPkg)
	if out, err := npm.CombinedOutput(); err != nil {
		if os.Getenv("CI") == "" {
			t.Skipf("npm install %s failed (offline?): %v\n%s", serverPkg, err, out)
		}
		t.Fatalf("npm install %s: %v\n%s", serverPkg, err, out)
	}
	f.serverJS = filepath.Join(f.srv, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js")
	if _, err := os.Stat(f.serverJS); err != nil {
		t.Fatal(err)
	}
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// y quotes a path for YAML (backslashes stay literal in single quotes).
func y(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (f *fixture) policy(t *testing.T) string { return f.policyFile(t, "fs.yml", "") }

// policyFile writes the policy as name, with extra sandbox.env entries.
func (f *fixture) policyFile(t *testing.T, name, extraEnv string) string {
	t.Helper()
	p := fmt.Sprintf(`name: real-fs
network: { mode: none }
filesystem:
  read_write: [%s]
  read_only: [%s]
  tmp: true
tools:
  default: deny
  rules:
    "read_*": allow
    "list_*": allow
    "search_*": allow
    "get_*": allow
    "delete_*": deny
    "move_*": deny
    write_file:
      decision: allow
      args: { path: { under: [%s] } }
    create_directory:
      decision: allow
      args: { path: { under: [%s] } }
lock: { enabled: true }
audit: { path: %s }
sandbox:
  env: [PATH, HOME, LANG%s]
`, y(f.webshop), y(f.srv), y(f.webshop), y(f.webshop), y(f.auditPath()), extraEnv)
	path := filepath.Join(f.state, name)
	must(t, os.WriteFile(path, []byte(p), 0o600))
	return path
}

func (f *fixture) auditPath() string { return filepath.Join(f.state, "audit.jsonl") }

// jail is `mcp-jail run` with a JSON-RPC client on its stdio.
type jail struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr string
	mu     sync.Mutex
	got    map[any]map[string]any
	raw    []string
	done   chan struct{}
}

func (f *fixture) start(t *testing.T, policy string, args ...string) *jail {
	t.Helper()
	j := &jail{got: map[any]map[string]any{}, done: make(chan struct{})}
	j.stderr = filepath.Join(f.state, "stderr.log") // a hidden file: node fstats fd 2 at start
	errf, err := os.Create(j.stderr)
	must(t, err)
	argv := append([]string{"run", "--quiet", "--policy", policy, "--"}, args...)
	j.cmd = exec.Command(f.bin, argv...)
	j.cmd.Env = append(os.Environ(), "MCP_JAIL_HOME="+filepath.Join(f.state, "home"))
	j.cmd.Stderr = errf
	j.stdin, err = j.cmd.StdinPipe()
	must(t, err)
	stdout, err := j.cmd.StdoutPipe()
	must(t, err)
	must(t, j.cmd.Start())
	_ = errf.Close()
	go func() {
		defer close(j.done)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var m map[string]any
			j.mu.Lock()
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil || m["id"] == nil {
				j.raw = append(j.raw, sc.Text())
			} else {
				j.got[m["id"]] = m
			}
			j.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = j.stdin.Close()
		select {
		case <-j.done:
		case <-time.After(20 * time.Second):
			_ = j.cmd.Process.Kill()
		}
		_ = j.cmd.Wait()
		if t.Failed() {
			out, _ := os.ReadFile(j.stderr)
			t.Logf("mcp-jail stderr:\n%s", out)
			if len(j.raw) > 0 {
				t.Logf("non-JSON-RPC stdout lines: %q", j.raw)
			}
		}
	})
	return j
}

func (j *jail) send(t *testing.T, obj map[string]any) {
	t.Helper()
	b, err := json.Marshal(obj)
	must(t, err)
	if _, err := j.stdin.Write(append(b, '\n')); err != nil {
		t.Fatalf("write to the jail: %v", err)
	}
}

func (j *jail) wait(t *testing.T, id float64, timeout time.Duration) map[string]any {
	t.Helper()
	m, err := j.waitErr(id, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (j *jail) waitErr(id float64, timeout time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		j.mu.Lock()
		m, ok := j.got[id]
		j.mu.Unlock()
		if ok {
			return m, nil
		}
		select {
		case <-j.done:
			_ = j.cmd.Wait()
			out, _ := os.ReadFile(j.stderr)
			return nil, fmt.Errorf("the jail exited (%v) before answering id %v\n%s", j.cmd.ProcessState, id, out)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("no answer to id %v within %s", id, timeout)
}

// diag runs a command under the policy with one initialize request on
// stdin, then EOF, and reports everything it produced.
func (f *fixture) diag(t *testing.T, policy string, args ...string) string {
	t.Helper()
	argv := append([]string{"run", "--quiet", "--policy", policy, "--"}, args...)
	cmd := exec.Command(f.bin, argv...)
	cmd.Env = append(os.Environ(), "MCP_JAIL_HOME="+filepath.Join(f.state, "home"))
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	var buf strings.Builder
	cmd.Stdout, cmd.Stderr = &buf, &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err.Error()
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return fmt.Sprintf("%v: %v\n%s", args, err, buf.String())
	case <-time.After(time.Minute):
		_ = cmd.Process.Kill()
		return fmt.Sprintf("%v: still running after 1m\n%s", args, buf.String())
	}
}

func (j *jail) call(t *testing.T, id float64, tool string, args map[string]any) map[string]any {
	t.Helper()
	j.send(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args}})
	return j.wait(t, id, 60*time.Second)
}

// text flattens a tools/call result; an error (JSON-RPC or isError) is
// prefixed so the assertions can tell the two apart.
func text(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		return fmt.Sprintf("ERROR %v: %v", e["code"], e["message"])
	}
	r, _ := m["result"].(map[string]any)
	var parts []string
	if content, ok := r["content"].([]any); ok {
		for _, c := range content {
			if cm, ok := c.(map[string]any); ok {
				parts = append(parts, fmt.Sprint(cm["text"]))
			}
		}
	}
	s := strings.Join(parts, " | ")
	if r["isError"] == true {
		s = "ISERROR " + s
	}
	return s
}

func errCode(m map[string]any) float64 {
	if e, ok := m["error"].(map[string]any); ok {
		c, _ := e["code"].(float64)
		return c
	}
	return 0
}

func TestRealServer(t *testing.T) {
	f := setup(t)

	t.Run("filesystem server under the policy", func(t *testing.T) {
		pol := f.policy(t)
		j := f.start(t, pol, "node", f.serverJS, f.webshop)
		j.send(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
			"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "realtest", "version": "0"}}})
		init, err := j.waitErr(1, 3*time.Minute)
		if err != nil {
			t.Log(f.diag(t, pol, "node", "-e", `process.stdin.on("data", d => process.stderr.write("event got " + d.length + "\n")); process.stdin.on("end", () => { process.stderr.write("event end\n"); process.exit(0) }); process.stdin.on("error", e => process.stderr.write("event error " + e + "\n"))`))
			t.Log(f.diag(t, pol, "node", "-e", `try { const b = require("fs").readFileSync(0); process.stderr.write("sync got " + b.length + "\n") } catch (e) { process.stderr.write("sync error " + e + "\n") }`))
			t.Log(f.diag(t, pol, "node", "-e", `process.stderr.write("stdin type " + require("tty").isatty(0) + " " + JSON.stringify(require("fs").fstatSync(0)) + "\n")`))
			dbg := f.policyFile(t, "dbg.yml", ", NODE_DEBUG=net,stream,pipe")
			t.Log(f.diag(t, dbg, "node", "--trace-exit", "--trace-uncaught", f.serverJS, f.webshop))
			t.Fatal(err)
		}
		if init["error"] != nil {
			t.Fatalf("initialize: %s", text(init))
		}
		j.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
		j.send(t, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
		list := j.wait(t, 2, time.Minute)
		res, _ := list["result"].(map[string]any)
		tools, _ := res["tools"].([]any)
		names := map[string]bool{}
		for _, tl := range tools {
			if tm, ok := tl.(map[string]any); ok {
				names[fmt.Sprint(tm["name"])] = true
			}
		}
		if len(tools) < 10 || !names["read_text_file"] || !names["write_file"] || !names["move_file"] {
			t.Fatalf("tools/list: %d tools %v (%s)", len(tools), names, text(list))
		}

		if s := text(j.call(t, 3, "list_allowed_directories", map[string]any{})); !strings.Contains(s, f.webshop) {
			t.Errorf("list_allowed_directories: %q", s)
		}
		if s := text(j.call(t, 4, "read_text_file", map[string]any{"path": filepath.Join(f.webshop, "README.md")})); s != "webshop readme\n" {
			t.Errorf("read inside the share: %q", s)
		}
		// outside the server's root: the server itself refuses, the policy
		// let it through (read_* is allowed)
		if s := text(j.call(t, 5, "read_text_file", map[string]any{"path": filepath.Join(f.secret, "key.txt")})); !strings.HasPrefix(s, "ISERROR") && !strings.HasPrefix(s, "ERROR") || strings.Contains(s, "hunter2") {
			t.Errorf("read outside the server root: %q", s)
		}
		newFile := filepath.Join(f.webshop, "new.txt")
		if s := text(j.call(t, 6, "write_file", map[string]any{"path": newFile, "content": "written from the jail\n"})); strings.HasPrefix(s, "ISERROR") || strings.HasPrefix(s, "ERROR") {
			t.Errorf("write inside the share: %q", s)
		}
		if b, err := os.ReadFile(newFile); err != nil || string(b) != "written from the jail\n" {
			t.Errorf("the written file on the host: %q %v", b, err)
		}
		// outside the arg constraint: refused by the policy before the server sees it
		if m := j.call(t, 7, "write_file", map[string]any{"path": filepath.Join(f.secret, "evil.txt"), "content": "pwned\n"}); errCode(m) != -32001 {
			t.Errorf("write outside under: %s", text(m))
		}
		if _, err := os.Stat(filepath.Join(f.secret, "evil.txt")); err == nil {
			t.Error("evil.txt was written")
		}
		if m := j.call(t, 8, "move_file", map[string]any{"source": filepath.Join(f.webshop, "README.md"), "destination": filepath.Join(f.webshop, "gone.md")}); errCode(m) != -32001 {
			t.Errorf("move_file (rule deny): %s", text(m))
		}
		if s := text(j.call(t, 9, "search_files", map[string]any{"path": f.webshop, "pattern": "*.md"})); !strings.Contains(s, "README.md") {
			t.Errorf("search_files: %q", s)
		}
		// a tool the server never listed: the lock refuses it before the rules
		if m := j.call(t, 10, "delete_file", map[string]any{"path": newFile}); errCode(m) != -32002 {
			t.Errorf("delete_file (not in the locked list): %s", text(m))
		}

		_ = j.stdin.Close()
		<-j.done
		audit, err := os.ReadFile(f.auditPath())
		must(t, err)
		a := string(audit)
		for _, want := range []string{
			`"tool":"write_file","decision":"deny"`,
			`"tool":"move_file","decision":"deny"`,
			`"tool":"read_text_file","decision":"allow"`,
			`"kind":"lock"`,
		} {
			if !strings.Contains(a, want) {
				t.Errorf("audit lacks %s:\n%s", want, a)
			}
		}
	})

	t.Run("node sees only the shares", func(t *testing.T) {
		pol := f.policy(t)
		probe := filepath.Join(f.srv, "probe.js")
		must(t, os.WriteFile(probe, []byte(probeJS), 0o600))
		j := f.start(t, pol, "node", probe, f.webshop, f.srv, f.secret, f.auditPath(), f.root, f.home)
		j.send(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}})
		_ = j.stdin.Close()
		select {
		case <-j.done:
		case <-time.After(2 * time.Minute):
			t.Fatal("node probe did not finish")
		}
		_ = j.cmd.Wait()
		out, _ := os.ReadFile(j.stderr)
		line := ""
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "PROBE ") {
				line = strings.TrimPrefix(l, "PROBE ")
			}
		}
		if line == "" {
			t.Fatalf("no PROBE line from node:\n%s", out)
		}
		var r map[string]string
		must(t, json.Unmarshal([]byte(line), &r))
		want := map[string]string{
			"read_rw": "ok", "write_rw": "ok", "read_ro": "ok",
			"write_ro": "err", "read_hidden": "err", "write_hidden": "err",
			"read_state": "err",
		}
		for k, w := range want {
			got := r[k]
			if w == "err" && strings.HasPrefix(got, "err:") {
				continue
			}
			if got != w {
				t.Errorf("%s: want %s, got %q", k, w, got)
			}
		}
		// Listing the directories above a share is denied (macOS, Windows)
		// or shows the empty skeleton bubblewrap makes for its mounts: the
		// names of the shares (and of the working directory's parents), never
		// a file or a sibling.
		hostFiles := map[string]bool{}
		if ents, err := os.ReadDir(f.home); err == nil {
			for _, e := range ents {
				if !e.IsDir() {
					hostFiles[e.Name()] = true
				}
			}
		}
		for _, k := range []string{"list_root", "list_home"} {
			got := r[k]
			if strings.HasPrefix(got, "err:") {
				continue
			}
			for _, name := range strings.Split(strings.TrimPrefix(got, "ok:"), ",") {
				switch {
				case name == "":
				case k == "list_root" && name != "webshop" && name != "srv":
					t.Errorf("%s: %q visible from the jail", k, name)
				case k == "list_home" && (hostFiles[name] || name == "secret" || name == "state"):
					t.Errorf("%s: %q visible from the jail", k, name)
				}
			}
		}
		if t.Failed() {
			t.Logf("probe: %v", r)
		}
		if _, err := os.Stat(filepath.Join(f.secret, "evil.txt")); err == nil {
			t.Error("node wrote into the hidden directory")
		}
	})
}

// probeJS tries the filesystem from inside the jail and reports on stderr
// (stdout is the JSON-RPC channel). argv: rw dir, ro dir, hidden dir,
// audit file, test root, the user's home.
const probeJS = `
const fs = require("fs"), path = require("path");
const [rw, ro, hidden, audit, root, home] = process.argv.slice(2);
const r = {};
const attempt = (k, fn) => { try { const v = fn(); r[k] = Array.isArray(v) ? "ok:" + v.join(",") : "ok"; } catch (e) { r[k] = "err:" + (e.code || e.message); } };
attempt("read_rw", () => fs.readFileSync(path.join(rw, "README.md")));
attempt("write_rw", () => fs.writeFileSync(path.join(rw, "probe.txt"), "x"));
attempt("read_ro", () => fs.readFileSync(path.join(ro, "probe.js")));
attempt("write_ro", () => fs.writeFileSync(path.join(ro, "x.txt"), "x"));
attempt("read_hidden", () => fs.readFileSync(path.join(hidden, "key.txt")));
attempt("write_hidden", () => fs.writeFileSync(path.join(hidden, "evil.txt"), "x"));
attempt("read_state", () => fs.readFileSync(audit));
attempt("list_root", () => fs.readdirSync(root));
attempt("list_home", () => fs.readdirSync(home));
attempt("list_root_parent", () => fs.readdirSync(path.dirname(root)));
attempt("list_home_parent", () => fs.readdirSync(path.dirname(home)));
r.env_home = process.env.HOME; r.cwd = process.cwd();
process.stderr.write("PROBE " + JSON.stringify(r) + "\n");
process.stdin.resume();
process.stdin.on("end", () => process.exit(0));
`
