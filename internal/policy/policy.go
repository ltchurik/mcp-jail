// Package policy defines the mcp-jail policy file and its loader.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decision is what to do with a tool call.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
	Ask   Decision = "ask"
)

// NetMode controls network access of the jailed server.
type NetMode string

const (
	// NetNone removes network access entirely (network namespace, no interfaces).
	NetNone NetMode = "none"
	// NetAllowlist permits only the listed hosts. On Linux with the sandbox
	// on this is enforced by an empty network namespace plus an in-jail
	// relay (hard); elsewhere it is a filtering HTTP_PROXY (cooperative).
	NetAllowlist NetMode = "allowlist"
	// NetAll leaves the network untouched.
	NetAll NetMode = "all"
)

// Policy is the on-disk policy document.
type Policy struct {
	// Name identifies the jailed server; used for lock and audit file names.
	Name string `yaml:"name"`

	Network struct {
		Mode  NetMode  `yaml:"mode"`
		Allow []string `yaml:"allow"` // hostnames or *.suffix; used in allowlist mode
	} `yaml:"network"`

	Filesystem struct {
		// ReadOnly paths bind-mounted read-only into the jail.
		ReadOnly []string `yaml:"read_only"`
		// ReadWrite paths bind-mounted read-write into the jail.
		ReadWrite []string `yaml:"read_write"`
		// Tmp gives the jail a private writable /tmp.
		Tmp bool `yaml:"tmp"`
	} `yaml:"filesystem"`

	Tools struct {
		Default Decision            `yaml:"default"`
		Rules   map[string]Decision `yaml:"rules"` // exact name or glob (filepath.Match)
	} `yaml:"tools"`

	Lock struct {
		// Enabled turns on rug-pull protection: tools/list is hashed on first run
		// and any later change is refused until `mcp-jail approve`.
		Enabled bool `yaml:"enabled"`
	} `yaml:"lock"`

	Audit struct {
		// Path of the JSONL audit log. Empty disables it. Supports ~ expansion.
		Path string `yaml:"path"`
		// Args logs tool-call arguments. Off by default: they may hold secrets.
		Args bool `yaml:"args"`
	} `yaml:"audit"`

	Sandbox struct {
		// Disabled runs the server unsandboxed (policy + lock + audit only).
		Disabled bool `yaml:"disabled"`
		// Env lists environment variables passed through to the jailed server.
		Env []string `yaml:"env"`
	} `yaml:"sandbox"`
}

// Default returns a policy with safe defaults.
func Default() *Policy {
	p := &Policy{}
	p.Network.Mode = NetNone
	p.Filesystem.Tmp = true
	p.Tools.Default = Ask
	p.Lock.Enabled = true
	return p
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Validate checks enum fields and expands paths.
func (p *Policy) Validate() error {
	switch p.Network.Mode {
	case NetNone, NetAllowlist, NetAll:
	default:
		return fmt.Errorf("network.mode must be one of none|allowlist|all, got %q", p.Network.Mode)
	}
	if p.Network.Mode == NetAllowlist && len(p.Network.Allow) == 0 {
		return fmt.Errorf("network.mode=allowlist requires network.allow")
	}
	if err := checkDecision(p.Tools.Default); err != nil {
		return fmt.Errorf("tools.default: %w", err)
	}
	for k, v := range p.Tools.Rules {
		if err := checkDecision(v); err != nil {
			return fmt.Errorf("tools.rules[%s]: %w", k, err)
		}
	}
	p.Filesystem.ReadOnly = expandAll(p.Filesystem.ReadOnly)
	p.Filesystem.ReadWrite = expandAll(p.Filesystem.ReadWrite)
	p.Audit.Path = expand(p.Audit.Path)
	return nil
}

func checkDecision(d Decision) error {
	switch d {
	case Allow, Deny, Ask:
		return nil
	}
	return fmt.Errorf("must be allow|deny|ask, got %q", d)
}

// Decide returns the decision for a tool name. Exact match wins over glob;
// among globs, the longest pattern wins.
func (p *Policy) Decide(tool string) Decision {
	if d, ok := p.Tools.Rules[tool]; ok {
		return d
	}
	best, bestLen := p.Tools.Default, -1
	for pat, d := range p.Tools.Rules {
		if ok, _ := filepath.Match(pat, tool); ok && len(pat) > bestLen {
			best, bestLen = d, len(pat)
		}
	}
	return best
}

// HostAllowed reports whether a hostname passes the network allowlist.
func (p *Policy) HostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range p.Network.Allow {
		a = strings.ToLower(a)
		if a == host {
			return true
		}
		if strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:]) {
			return true
		}
	}
	return false
}

func expandAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, expand(s))
	}
	return out
}

func expand(s string) string {
	if strings.HasPrefix(s, "~/") || s == "~" {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, s[1:])
		}
	}
	return os.ExpandEnv(s)
}

// Example is a documented starter policy written by `mcp-jail init`.
const Example = `# mcp-jail policy — https://github.com/ltchurik/mcp-jail
name: my-server

network:
  # none      – no network at all (hard: network namespace)
  # allowlist – only hosts below (hard on Linux; HTTP_PROXY-based elsewhere)
  # all       – unrestricted
  mode: none
  allow:
    - api.github.com
    - "*.githubusercontent.com"

filesystem:
  read_only:
    - ~/projects/myrepo
  read_write: []
  tmp: true

tools:
  # allow | deny | ask   (ask = confirm on the terminal; denied when no TTY)
  default: ask
  rules:
    "read_*": allow
    "list_*": allow
    "delete_*": deny

lock:
  enabled: true   # refuse to run if tool definitions change (rug-pull)

audit:
  path: ~/.local/state/mcp-jail/my-server.jsonl
  args: false     # log tool arguments (may contain secrets)

sandbox:
  disabled: false
  env: [PATH, HOME, LANG]
`
