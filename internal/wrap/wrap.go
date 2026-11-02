// Package wrap rewrites an MCP client configuration so that every stdio
// server starts through mcp-jail, and writes a starter policy per server.
package wrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

// Options control a wrap run.
type Options struct {
	Bin       string // mcp-jail binary to put in "command" (absolute path recommended)
	PolicyDir string // where <name>.yml files go
	Network   string // network.mode for new policies: none | all
	Force     bool   // overwrite existing policy files
	DryRun    bool   // compute everything, write nothing
}

// Change describes what happened to one server entry.
type Change struct {
	Name   string
	Action string // wrapped | already-wrapped | remote | invalid
	Policy string // policy file path (wrapped only)
	Note   string
}

// Result is what Run reports.
type Result struct {
	Changes  []Change
	Config   []byte // the rewritten configuration
	Backup   string // path of the backup written, "" when none
	Policies []string

	policyText map[string]string // name -> rendered policy
}

// PolicyText returns the rendered policy for a wrapped server.
func (r *Result) PolicyText(name string) string { return r.policyText[name] }

// Run wraps the configuration file at path in place.
func Run(path string, o Options) (*Result, error) {
	in, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res, err := Rewrite(in, o)
	if err != nil {
		return nil, err
	}
	if o.DryRun {
		return res, nil
	}
	for _, c := range res.Changes {
		if c.Action != "wrapped" {
			continue
		}
		pol := res.policyText[c.Name]
		if err := os.MkdirAll(filepath.Dir(c.Policy), 0o700); err != nil {
			return nil, err
		}
		if _, err := os.Stat(c.Policy); err == nil && !o.Force {
			continue // keep what the user has; the config points at it anyway
		}
		if err := os.WriteFile(c.Policy, []byte(pol), 0o600); err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(bytes.TrimSpace(in), bytes.TrimSpace(res.Config)) {
		bak := backupName(path)
		if err := os.WriteFile(bak, in, 0o600); err != nil { // #nosec G703 -- the config path is the CLI argument by design
			return nil, fmt.Errorf("backup: %w", err)
		}
		res.Backup = bak
		if err := os.WriteFile(path, res.Config, 0o600); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func backupName(path string) string {
	bak := path + ".bak"
	for i := 1; ; i++ {
		if _, err := os.Stat(bak); errors.Is(err, os.ErrNotExist) {
			return bak
		}
		bak = fmt.Sprintf("%s.bak.%d", path, i)
	}
}

// Rewrite computes the wrapped configuration and the policies without
// touching the filesystem. Policies that already exist on disk are reported
// but not regenerated unless Force is set.
func Rewrite(in []byte, o Options) (*Result, error) {
	if o.Bin == "" {
		o.Bin = "mcp-jail"
	}
	if o.PolicyDir == "" {
		return nil, errors.New("policy directory is required")
	}
	switch o.Network {
	case "", "none":
		o.Network = "none"
	case "all":
	default:
		return nil, fmt.Errorf("network must be none or all, got %q", o.Network)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(in, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	rawServers, ok := cfg["mcpServers"]
	if !ok {
		return nil, errors.New(`config has no "mcpServers" object`)
	}
	var servers map[string]map[string]json.RawMessage
	if err := json.Unmarshal(rawServers, &servers); err != nil {
		return nil, fmt.Errorf("mcpServers: %w", err)
	}
	res := &Result{policyText: map[string]string{}}
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		srv := servers[name]
		ch := wrapOne(name, srv, o, res)
		res.Changes = append(res.Changes, ch)
	}
	out, err := json.Marshal(servers)
	if err != nil {
		return nil, err
	}
	cfg["mcpServers"] = out
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	res.Config = buf.Bytes()
	return res, nil
}

// wrapOne rewrites a single server entry in place and returns the change.
func wrapOne(name string, srv map[string]json.RawMessage, o Options, res *Result) Change {
	var command string
	var args []string
	if raw, ok := srv["command"]; ok {
		_ = json.Unmarshal(raw, &command)
	}
	if raw, ok := srv["args"]; ok {
		_ = json.Unmarshal(raw, &args)
	}
	if command == "" {
		if _, ok := srv["url"]; ok {
			return Change{Name: name, Action: "remote", Note: "remote (url) servers are not wrapped"}
		}
		return Change{Name: name, Action: "invalid", Note: "no command"}
	}
	if alreadyWrapped(command, args, o.Bin) {
		return Change{Name: name, Action: "already-wrapped", Note: "runs through " + command}
	}
	if !validName(name) {
		return Change{Name: name, Action: "invalid", Note: "server name is not usable as a file name"}
	}
	polPath := filepath.Join(o.PolicyDir, name+".yml")
	var envKeys []string
	if raw, ok := srv["env"]; ok {
		var env map[string]json.RawMessage
		_ = json.Unmarshal(raw, &env)
		for k := range env {
			envKeys = append(envKeys, k)
		}
		sort.Strings(envKeys)
	}
	res.policyText[name] = Policy(name, command, args, envKeys, o.Network)
	res.Policies = append(res.Policies, polPath)

	newArgs := append([]string{"run", "--policy", polPath, "--", command}, args...)
	srv["command"], _ = json.Marshal(o.Bin)
	srv["args"], _ = json.Marshal(newArgs)
	note := ""
	if _, err := os.Stat(polPath); err == nil && !o.Force {
		note = "policy exists, kept"
	}
	return Change{Name: name, Action: "wrapped", Policy: polPath, Note: note}
}

func validName(n string) bool {
	if n == "" || n == "." || n == ".." || len(n) > 128 {
		return false
	}
	return !strings.ContainsAny(n, "/\\\x00")
}

// Policy renders a starter policy for a server. Absolute directories among
// the arguments become read_write paths (the usual shape of a filesystem
// server); npx/uvx get their caches; env keys from the client config are
// passed through so tokens still reach the server.
func Policy(name, command string, args, envKeys []string, network string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# mcp-jail policy for %q, generated by `mcp-jail wrap`.\n", name)
	fmt.Fprintf(&b, "# Server: %s\n#\n", strings.Join(append([]string{command}, args...), " "))
	b.WriteString("# Review before trusting: tighten the paths, pick the network mode the server\n")
	b.WriteString("# really needs, and turn `ask` into allow/deny rules as you learn its tools.\n")
	fmt.Fprintf(&b, "name: %s\n\n", yamlStr(name))

	fmt.Fprintf(&b, "network:\n  mode: %s", network)
	if network == "none" {
		b.WriteString("            # none | allowlist | all; allowlist is hard on Linux and macOS")
	}
	b.WriteString("\n  allow: []             # hostnames or \"*.suffix\" for allowlist mode\n\n")

	var rw, ro []string
	home, _ := os.UserHomeDir()
	for _, a := range args {
		if filepath.IsAbs(a) {
			if st, err := os.Stat(a); err == nil && st.IsDir() {
				if a := filepath.Clean(a); a == "/" || a == home || (home != "" && strings.HasPrefix(home, a+"/")) {
					// the root or the home directory: too much to hand a
					// server read-write; the user picks a narrower path
					b.WriteString("  # NOT added: " + a + " is the root or home directory; list a narrower read_write path yourself\n")
					continue
				}
				rw = append(rw, a)
			}
		}
	}
	switch filepath.Base(command) {
	case "npx", "npm", "node":
		rw = append(rw, "~/.npm/_npx")
		ro = append(ro, "~/.npm/_cacache")
	case "uvx", "uv":
		rw = append(rw, "~/.cache/uv")
	case "pipx":
		ro = append(ro, "~/.local/pipx")
	}
	b.WriteString("filesystem:\n")
	b.WriteString("  # Directories from the command line are writable; move the ones the server\n")
	b.WriteString("  # only needs to read into read_only.\n")
	b.WriteString("  read_only: " + yamlList(ro) + "\n")
	b.WriteString("  read_write: " + yamlList(rw) + "\n")
	b.WriteString("  tmp: true\n\n")

	b.WriteString("tools:\n  default: ask          # allow | deny | ask (ask needs a terminal; denied without one)\n")
	b.WriteString("  rules:\n    \"read_*\": allow\n    \"list_*\": allow\n    \"get_*\": allow\n    \"search_*\": allow\n    \"delete_*\": deny\n\n")
	b.WriteString("lock:\n  enabled: true         # refuse changed tool/prompt/resource definitions until approved\n\n")
	fmt.Fprintf(&b, "audit:\n  path: ~/.local/state/mcp-jail/%s.jsonl\n  args: false\n\n", safeFile(name))

	env := append([]string{"PATH", "HOME", "LANG"}, envKeys...)
	b.WriteString("sandbox:\n  disabled: false\n")
	b.WriteString("  env: " + yamlList(uniq(env)) + "   # variables passed into the jail\n")
	return b.String()
}

func yamlStr(s string) string {
	if s != "" && !strings.ContainsAny(s, ":#{}[],&*!|>'\"%@`\\\n\t") && !strings.HasPrefix(s, " ") && !strings.HasSuffix(s, " ") && s != "true" && s != "false" && s != "null" {
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return s
		}
	}
	return strconv.Quote(s)
}

func yamlList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	q := make([]string, 0, len(items))
	for _, it := range items {
		q = append(q, yamlStr(it))
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func safeFile(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, name)
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Validate loads a rendered policy to make sure it parses. Used by tests and
// by the CLI as a self-check before writing.
func Validate(text string) error {
	dir, err := os.MkdirTemp("", "mcp-jail-wrap-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		return err
	}
	_, err = policy.Load(p)
	return err
}

// alreadyWrapped reports whether a server entry already starts through
// mcp-jail: a command named like our binary followed by "run". The change
// note shows the command, so a look-alike path is visible to the user.
func alreadyWrapped(command string, args []string, bin string) bool {
	return len(args) > 0 && args[0] == "run" && filepath.Base(command) == filepath.Base(bin)
}
