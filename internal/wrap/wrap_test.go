package wrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "%s"]},
    "github": {"command": "uvx", "args": ["mcp-server-github"], "env": {"GITHUB_TOKEN": "ghp_x", "HOME_DIR": "/x"}},
    "remote": {"type": "http", "url": "https://example.com/mcp", "headers": {"Authorization": "Bearer abc", "X-Trace": "1"}},
    "legacy": {"type": "sse", "url": "https://example.com/sse"},
    "done": {"command": "/usr/local/bin/mcp-jail", "args": ["run", "--policy", "/p.yml", "--", "x"]},
    "bad/name": {"command": "x"}
  },
  "other": {"keep": true}
}`

func TestRewrite(t *testing.T) {
	proj := t.TempDir()
	in := []byte(strings.ReplaceAll(sample, "%s", proj))
	res, err := Rewrite(in, Options{Bin: "/opt/mcp-jail", PolicyDir: "/pol"})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, c := range res.Changes {
		actions[c.Name] = c.Action
	}
	want := map[string]string{"filesystem": "wrapped", "github": "wrapped", "remote": "wrapped", "legacy": "remote", "done": "already-wrapped", "bad/name": "invalid"}
	for n, a := range want {
		if actions[n] != a {
			t.Errorf("%s: %s, want %s", n, actions[n], a)
		}
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(res.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	var other map[string]bool
	if json.Unmarshal(cfg["other"], &other) != nil || !other["keep"] {
		t.Errorf("unknown top-level keys must survive: %s", cfg["other"])
	}
	var servers map[string]struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
		URL     string            `json:"url"`
	}
	if err := json.Unmarshal(cfg["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	fs := servers["filesystem"]
	if fs.Command != "/opt/mcp-jail" || strings.Join(fs.Args, " ") != "run --policy /pol/filesystem.yml -- npx -y @modelcontextprotocol/server-filesystem "+proj {
		t.Errorf("filesystem rewritten wrong: %s %v", fs.Command, fs.Args)
	}
	gh := servers["github"]
	if gh.Env["GITHUB_TOKEN"] != "ghp_x" || gh.Args[0] != "run" {
		t.Errorf("github: env must be untouched, args wrapped: %+v", gh)
	}
	if servers["legacy"].URL != "https://example.com/sse" || servers["done"].Command != "/usr/local/bin/mcp-jail" {
		t.Errorf("legacy sse/already-wrapped must be untouched: %+v %+v", servers["legacy"], servers["done"])
	}
	rm := servers["remote"]
	if rm.URL != "" || rm.Command != "/opt/mcp-jail" || strings.Join(rm.Args, " ") != "run --policy /pol/remote.yml" || rm.Env["REMOTE_AUTHORIZATION"] != "Bearer abc" || len(rm.Env) != 1 {
		t.Errorf("remote rewritten wrong: %+v", rm)
	}
	rp := res.PolicyText("remote")
	for _, want := range []string{"name: remote", `url: "https://example.com/mcp"`, `Authorization: "${REMOTE_AUTHORIZATION}"`, `X-Trace: "1"`, "default: ask", "enabled: true"} {
		if !strings.Contains(rp, want) {
			t.Errorf("remote policy missing %q:\n%s", want, rp)
		}
	}
	if strings.Contains(rp, "Bearer abc") || strings.Contains(rp, "sandbox:") || strings.Contains(rp, "network:") {
		t.Errorf("remote policy must not carry the token or sandbox sections:\n%s", rp)
	}
	t.Setenv("REMOTE_AUTHORIZATION", "Bearer abc")
	if err := Validate(rp); err != nil {
		t.Errorf("remote policy does not load: %v", err)
	}

	pol := res.PolicyText("filesystem")
	for _, want := range []string{"name: filesystem", "mode: none", "read_write: " + yamlList([]string{proj, "~/.npm/_npx"}), "read_only: [~/.npm/_cacache]",
		"default: ask", "enabled: true", "env: [PATH, HOME, LANG]"} {
		if !strings.Contains(pol, want) {
			t.Errorf("filesystem policy missing %q:\n%s", want, pol)
		}
	}
	gp := res.PolicyText("github")
	if !strings.Contains(gp, "env: [PATH, HOME, LANG, GITHUB_TOKEN, HOME_DIR]") || !strings.Contains(gp, "read_write: [~/.cache/uv]") {
		t.Errorf("github policy:\n%s", gp)
	}
	for _, n := range []string{"filesystem", "github"} {
		if err := Validate(res.PolicyText(n)); err != nil {
			t.Errorf("generated policy for %s does not load: %v", n, err)
		}
	}

	// Rewriting the output again changes nothing: idempotent.
	again, err := Rewrite(res.Config, Options{Bin: "/opt/mcp-jail", PolicyDir: "/pol"})
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Config) != string(res.Config) {
		t.Errorf("second pass must be a no-op:\n%s\n---\n%s", res.Config, again.Config)
	}
	for _, c := range again.Changes {
		if c.Action == "wrapped" {
			t.Errorf("%s wrapped twice", c.Name)
		}
	}

	if _, err := Rewrite([]byte(`{"servers":{}}`), Options{PolicyDir: "/p"}); err == nil {
		t.Error("config without mcpServers must fail")
	}
	if _, err := Rewrite(in, Options{PolicyDir: "/p", Network: "allowlist"}); err == nil {
		t.Error("allowlist without hosts is not a valid starter network mode")
	}
	res, _ = Rewrite(in, Options{PolicyDir: "/p", Network: "all"})
	if !strings.Contains(res.PolicyText("github"), "mode: all") {
		t.Error("network all not applied")
	}
}

func TestRunWritesFilesAndBackup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "claude_desktop_config.json")
	in := strings.ReplaceAll(sample, "%s", dir)
	if err := os.WriteFile(cfg, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	polDir := filepath.Join(dir, "policies")
	opts := Options{Bin: "/opt/mcp-jail", PolicyDir: polDir}

	dry, err := Run(cfg, Options{Bin: "/opt/mcp-jail", PolicyDir: polDir, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != in || dry.Backup != "" {
		t.Fatal("dry run must not write")
	}
	if _, err := os.Stat(polDir); !os.IsNotExist(err) {
		t.Fatal("dry run must not create policies")
	}

	res, err := Run(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Backup != cfg+".bak" {
		t.Fatalf("backup = %q", res.Backup)
	}
	if b, _ := os.ReadFile(res.Backup); string(b) != in {
		t.Fatal("backup must hold the original")
	}
	for _, n := range []string{"filesystem", "github"} {
		if _, err := os.Stat(filepath.Join(polDir, n+".yml")); err != nil {
			t.Errorf("policy %s not written: %v", n, err)
		}
	}
	// A user edit to a policy survives a re-run without --force.
	edited := "# edited\n" + res.PolicyText("github")
	if err := os.WriteFile(filepath.Join(polDir, "github.yml"), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := Run(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Backup != "" {
		t.Error("no-op run must not write another backup")
	}
	if b, _ := os.ReadFile(filepath.Join(polDir, "github.yml")); string(b) != edited {
		t.Error("existing policy must be kept")
	}
	// --force on an unrelated unwrapped config regenerates.
	if err := os.WriteFile(cfg, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	res3, err := Run(cfg, Options{Bin: "/opt/mcp-jail", PolicyDir: polDir, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if res3.Backup != cfg+".bak.1" {
		t.Errorf("second backup = %q", res3.Backup)
	}
	if b, _ := os.ReadFile(filepath.Join(polDir, "github.yml")); string(b) == edited {
		t.Error("--force must regenerate the policy")
	}
}

func TestYAMLQuoting(t *testing.T) {
	for in, want := range map[string]string{
		"plain":        "plain",
		"has space":    "has space",
		"a:b":          `"a:b"`,
		"true":         `"true"`,
		"12":           `"12"`,
		"~/.npm/_npx":  "~/.npm/_npx",
		"/p/with#hash": `"/p/with#hash"`,
		"":             `""`,
	} {
		if got := yamlStr(in); got != want {
			t.Errorf("yamlStr(%q) = %s, want %s", in, got, want)
		}
	}
	if err := Validate(Policy("odd: name", "x", []string{"/nonexistent dir"}, []string{"K"}, "none", nil)); err != nil {
		t.Errorf("policy with odd name must still load: %v", err)
	}
}

// An unpinned launcher is reported with the change and in the policy header.
func TestRewriteWarnsUnpinned(t *testing.T) {
	in := []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/srv"]},"git":{"command":"uvx","args":["mcp-server-git==0.6.2"]}}}`)
	res, err := Rewrite(in, Options{Bin: "/opt/mcp-jail", PolicyDir: "/pol"})
	if err != nil {
		t.Fatal(err)
	}
	var fs, git Change
	for _, c := range res.Changes {
		switch c.Name {
		case "fs":
			fs = c
		case "git":
			git = c
		}
	}
	if len(fs.Warnings) != 1 || !strings.Contains(fs.Warnings[0], `npx resolves "@scope/srv"`) || len(git.Warnings) != 0 {
		t.Fatalf("warnings: fs=%q git=%q", fs.Warnings, git.Warnings)
	}
	pol := res.PolicyText("fs")
	if !strings.Contains(pol, "# WARNING: npx resolves") || !strings.Contains(pol, "npm_config_ignore_scripts=true") {
		t.Fatalf("policy header:\n%s", pol)
	}
	if err := Validate(pol); err != nil {
		t.Fatal(err)
	}
}

func TestPolicySkipsRootAndHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	out := Policy("fs", "npx", []string{"-y", "server", "/", home, "/tmp"}, nil, "none", nil)
	if strings.Contains(out, "- /\n") || strings.Contains(out, "- "+home+"\n") {
		t.Fatalf("root or home became read_write:\n%s", out)
	}
	if !strings.Contains(out, "NOT added: /") || !strings.Contains(out, "NOT added: "+home) || !strings.Contains(out, "read_write: [/tmp") {
		t.Fatalf("notes/paths:\n%s", out)
	}
}
