// Package policy defines the mcp-jail policy file and its loader.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
		// ReadOnly paths visible read-only inside the jail.
		ReadOnly []string `yaml:"read_only"`
		// ReadWrite paths visible read-write inside the jail.
		ReadWrite []string `yaml:"read_write"`
		// Tmp gives the jail a private writable tmp (/tmp on Linux, $TMPDIR on macOS).
		Tmp bool `yaml:"tmp"`
	} `yaml:"filesystem"`

	// Tools and Ask are the sections a running jail reloads when the
	// dashboard promotes a rule (SetRule + control /reload); the rest is
	// fixed at start.
	Tools struct {
		Default Decision        `yaml:"default"`
		Rules   map[string]Rule `yaml:"rules"` // exact name or glob (filepath.Match)
	} `yaml:"tools"`

	Ask struct {
		// Timeout bounds how long an `ask` without a terminal waits for the
		// dashboard (`mcp-jail ui`) before it is denied. Default 60s, max 10m.
		// A webhook has its own timeout below.
		Timeout time.Duration `yaml:"timeout"`
		// Webhook answers `ask` decisions when there is no terminal (headless
		// clients such as Claude Desktop). mcp-jail POSTs a JSON description of
		// the call and expects {"decision":"allow"} back within Timeout;
		// anything else — a deny, a timeout, an error, an unexpected body — is
		// a deny. The same payload carries a "text" field, so a Slack incoming
		// webhook URL yields a notification (and, since Slack answers "ok", a
		// deny).
		Webhook struct {
			URL     string            `yaml:"url"`
			Timeout time.Duration     `yaml:"timeout"` // default 60s, max 10m
			Headers map[string]string `yaml:"headers"` // values support ${ENV} expansion
		} `yaml:"webhook"`
	} `yaml:"ask"`

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

// Rule is the value of a tools.rules entry: either a bare decision
// ("read_*": allow) or a mapping with per-argument constraints:
//
//	write_file:
//	  decision: allow
//	  args:
//	    path: { under: [~/projects] }
//	    url:  { host: [network.allow] }
type Rule struct {
	Decision Decision                 `yaml:"decision"`
	Args     map[string]ArgConstraint `yaml:"args"`
}

// ArgConstraint restricts one tool argument. A constrained argument that is
// missing from the call is refused unless Optional is set; a value of an
// unexpected type is always refused.
type ArgConstraint struct {
	// Under requires a filesystem path argument to be absolute and inside
	// one of these directories (after cleaning, so ".." cannot escape).
	Under []string `yaml:"under"`
	// Host requires a URL or host[:port] argument to match one of these
	// patterns (exact name or *.suffix). The entry "network.allow" stands
	// for the network allowlist.
	Host []string `yaml:"host"`
	// Optional lets the call through when the argument is absent.
	Optional bool `yaml:"optional"`
}

// UnmarshalYAML accepts both the scalar and the mapping form.
func (r *Rule) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.Decision = Decision(n.Value)
		return nil
	}
	type plain Rule
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = Rule(p)
	return nil
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
	return parse(b, path)
}

// parse decodes and validates policy text; path only labels errors.
func parse(b []byte, path string) (*Policy, error) {
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
	if err := checkName(p.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	for _, s := range append(append(append([]string{}, p.Network.Allow...), p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...) {
		if hasControl(s) {
			return fmt.Errorf("%q: control character in a path or host", s)
		}
	}
	if hasControl(p.Audit.Path) {
		return fmt.Errorf("audit.path: control character")
	}
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
	for k, r := range p.Tools.Rules {
		if err := checkDecision(r.Decision); err != nil {
			return fmt.Errorf("tools.rules[%s]: %w", k, err)
		}
		for arg, c := range r.Args {
			if len(c.Under) == 0 && len(c.Host) == 0 {
				return fmt.Errorf("tools.rules[%s].args[%s]: needs under or host", k, arg)
			}
			if len(c.Under) > 0 && len(c.Host) > 0 {
				return fmt.Errorf("tools.rules[%s].args[%s]: under and host are mutually exclusive", k, arg)
			}
			for _, h := range c.Host {
				if h == "" {
					return fmt.Errorf("tools.rules[%s].args[%s]: empty host pattern", k, arg)
				}
				if h == "network.allow" && len(p.Network.Allow) == 0 {
					return fmt.Errorf("tools.rules[%s].args[%s]: network.allow is empty", k, arg)
				}
			}
			c.Under = expandAll(c.Under)
			for i, d := range c.Under {
				if !filepath.IsAbs(d) {
					return fmt.Errorf("tools.rules[%s].args[%s]: under must be absolute, got %q", k, arg, d)
				}
				c.Under[i] = filepath.Clean(d)
			}
			r.Args[arg] = c
		}
	}
	p.Filesystem.ReadOnly = expandAll(p.Filesystem.ReadOnly)
	p.Filesystem.ReadWrite = expandAll(p.Filesystem.ReadWrite)
	p.Audit.Path = expand(p.Audit.Path)
	switch {
	case p.Ask.Timeout == 0:
		p.Ask.Timeout = 60 * time.Second
	case p.Ask.Timeout < 0, p.Ask.Timeout > 10*time.Minute:
		return fmt.Errorf("ask.timeout: must be between 1s and 10m, got %s", p.Ask.Timeout)
	}
	if w := &p.Ask.Webhook; w.URL != "" {
		u, err := url.Parse(w.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("ask.webhook.url must be an http(s) URL, got %q", w.URL)
		}
		switch {
		case w.Timeout == 0:
			w.Timeout = 60 * time.Second
		case w.Timeout < 0:
			return fmt.Errorf("ask.webhook.timeout must be positive")
		case w.Timeout > 10*time.Minute:
			return fmt.Errorf("ask.webhook.timeout must be at most 10m")
		}
		for k, v := range w.Headers {
			w.Headers[k] = os.ExpandEnv(v)
		}
	}
	return nil
}

// checkName bounds the server name: it becomes part of lock, registry and
// socket file names, so it must be one path element without control
// characters. Empty is allowed and filled in by `run`.
func checkName(n string) error {
	switch {
	case n == "": // `run` fills in the command's base name
		return nil
	case n == "." || n == "..":
		return fmt.Errorf("%q is not a name", n)
	case len(n) > 128:
		return errors.New("longer than 128 bytes")
	case strings.ContainsAny(n, "/\\") || hasControl(n):
		return fmt.Errorf("%q: must not contain path separators or control characters", n)
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func checkDecision(d Decision) error {
	switch d {
	case Allow, Deny, Ask:
		return nil
	}
	return fmt.Errorf("must be allow|deny|ask, got %q", d)
}

// Rule returns the rule for a tool name. Exact match wins over glob; among
// globs, the longest pattern wins; otherwise the default decision applies.
func (p *Policy) Rule(tool string) Rule {
	if r, ok := p.Tools.Rules[tool]; ok {
		return r
	}
	best, bestLen := Rule{Decision: p.Tools.Default}, -1
	for pat, r := range p.Tools.Rules {
		if ok, _ := filepath.Match(pat, tool); ok && len(pat) > bestLen {
			best, bestLen = r, len(pat)
		}
	}
	return best
}

// Decide returns the decision for a tool name.
func (p *Policy) Decide(tool string) Decision { return p.Rule(tool).Decision }

// CheckArgs applies the rule's argument constraints to a tools/call
// arguments object. It returns nil when every constraint holds, otherwise a
// reason suitable for the audit log and the error sent to the client.
// Anything that cannot be verified (unparsable arguments, a value of the
// wrong type, a relative path) is a violation.
func (p *Policy) CheckArgs(tool string, args json.RawMessage) error {
	r := p.Rule(tool)
	if len(r.Args) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &m); err != nil {
			return errors.New("arguments are not an object")
		}
	}
	names := make([]string, 0, len(r.Args))
	for n := range r.Args {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		c := r.Args[name]
		raw, ok := m[name]
		if !ok || string(raw) == "null" {
			if c.Optional {
				continue
			}
			return fmt.Errorf("argument %q is required by policy", name)
		}
		vals, err := stringValues(raw)
		if err != nil {
			return fmt.Errorf("argument %q: %w", name, err)
		}
		for _, v := range vals {
			if len(c.Under) > 0 {
				if err := checkUnder(v, c.Under); err != nil {
					return fmt.Errorf("argument %q: %w", name, err)
				}
			}
			if len(c.Host) > 0 {
				if err := p.checkHost(v, c.Host); err != nil {
					return fmt.Errorf("argument %q: %w", name, err)
				}
			}
		}
	}
	return nil
}

// stringValues accepts a string or an array of strings.
func stringValues(raw json.RawMessage) ([]string, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}, nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list, nil
	}
	return nil, errors.New("must be a string or a list of strings")
}

func checkUnder(v string, dirs []string) error {
	if !filepath.IsAbs(v) {
		return fmt.Errorf("path %q is not absolute", v)
	}
	clean := filepath.Clean(v)
	for _, d := range dirs {
		if clean == d || strings.HasPrefix(clean, strings.TrimSuffix(d, string(filepath.Separator))+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("path %q is outside %v", v, dirs)
}

func (p *Policy) checkHost(v string, patterns []string) error {
	host := v
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("url %q has no host", v)
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return fmt.Errorf("%q has no host", v)
	}
	for _, pat := range patterns {
		if pat == "network.allow" {
			if p.HostAllowed(host) {
				return nil
			}
			continue
		}
		if matchHost([]string{pat}, host) {
			return nil
		}
	}
	return fmt.Errorf("host %q not allowed", host)
}

// HostAllowed reports whether a hostname passes the network allowlist.
func (p *Policy) HostAllowed(host string) bool { return matchHost(p.Network.Allow, host) }

// matchHost matches a hostname against patterns: exact name or *.suffix.
func matchHost(patterns []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range patterns {
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
    # A rule can also constrain arguments. A constrained argument that is
    # missing, of the wrong type or outside the bounds makes the call fail.
    # write_file:
    #   decision: allow
    #   args:
    #     path: { under: [~/projects/myrepo] }   # absolute path inside one of these
    # fetch:
    #   decision: allow
    #   args:
    #     url: { host: [network.allow] }          # host must be in network.allow

# ask without a terminal (Claude Desktop, Cursor): the call waits up to
# ask.timeout for an answer from the dashboard (mcp-jail ui) when one is open,
# and/or POSTs to a webhook that answers {"decision":"allow"}; no answer denies.
# ask:
#   timeout: 60s
#   webhook:
#     url: https://approvals.example.internal/mcp-jail
#     timeout: 60s
#     headers: { Authorization: "Bearer ${MCP_JAIL_WEBHOOK_TOKEN}" }

lock:
  enabled: true   # refuse to run if tool definitions change (rug-pull)

audit:
  path: ~/.local/state/mcp-jail/my-server.jsonl
  args: false     # log tool arguments (may contain secrets)

sandbox:
  disabled: false
  env: [PATH, HOME, LANG]
`
