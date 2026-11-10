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

	"github.com/ltchurik/mcp-jail/internal/limits"
	"github.com/ltchurik/mcp-jail/internal/scan"
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

// FirstContact is lock.first: what the lock does with a list it has never
// recorded.
type FirstContact string

const (
	// FirstRecord trusts the first list and records it (trust on first contact).
	FirstRecord FirstContact = "record"
	// FirstReview refuses the first list until someone has looked at it and
	// approved it; nothing is recorded before that.
	FirstReview FirstContact = "review"
)

// LockScope is lock.scope: what a change in a recorded list invalidates.
type LockScope string

const (
	// ScopeList (default) refuses the whole list and every use of it when
	// anything in it changed, until the new list is approved.
	ScopeList LockScope = "list"
	// ScopeItem forwards the items that still match the lock and holds only
	// the added or changed ones (and their use) for approval. Resource
	// templates are always locked as a list, because a read URI cannot be
	// matched to one template.
	ScopeItem LockScope = "item"
)

// Backend is sandbox.backend.
type Backend string

const (
	BackendAuto        Backend = "auto"
	BackendBwrap       Backend = "bwrap"
	BackendSandboxExec Backend = "sandbox-exec"
	BackendDocker      Backend = "docker"
	BackendNone        Backend = "none"
)

// SecretsMode is what a credential found in tool arguments does.
type SecretsMode string

const (
	SecretsOff  SecretsMode = "off"
	SecretsWarn SecretsMode = "warn"
	SecretsDeny SecretsMode = "deny"
	SecretsAsk  SecretsMode = "ask"
)

func checkSecretsMode(m SecretsMode) error {
	switch m {
	case SecretsOff, SecretsWarn, SecretsDeny, SecretsAsk:
		return nil
	}
	return fmt.Errorf("must be off|warn|deny|ask, got %q", m)
}

// LintMode is what a lint finding does.
type LintMode string

const (
	LintOff  LintMode = "off"
	LintWarn LintMode = "warn"
	LintDeny LintMode = "deny"
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
		// Secrets is what happens when a tools/call argument looks like a
		// credential (an AWS key, a private key, a JWT, a bearer token, a
		// password assignment, the value of a secret-looking variable in
		// mcp-jail's own environment; see scan.Secrets): "warn" (default)
		// audits it (kind secret), "deny" refuses the call, "ask" asks even
		// when the rule says allow, "off" skips the check. A rule's own
		// secrets field overrides it for that tool.
		Secrets SecretsMode `yaml:"secrets"`
		// SecretsIgnore lists secrets rule ids (scan.SecretRules) to skip.
		SecretsIgnore []string `yaml:"secrets_ignore"`
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
		// First says what happens to a list seen for the first time: "record"
		// (default) trusts and records it; "review" shows it and records it
		// only after an explicit approve (terminal, dashboard or `mcp-jail
		// approve`); until then the list and its uses are refused.
		First FirstContact `yaml:"first"`
		// Scope says what a change invalidates: "list" (default) refuses the
		// whole list; "item" forwards the unchanged items and holds only the
		// added or changed ones for approval.
		Scope LockScope `yaml:"scope"`
		// Notify, unless false, makes a running jail watch the lock while a
		// change is pending and tell the client (notifications/tools/
		// list_changed and the prompts/resources equivalents) once it was
		// approved out of band, so the client lists again without a restart.
		Notify *bool `yaml:"notify"`
	} `yaml:"lock"`

	// ServerRequests decides the requests a server sends to the client:
	// sampling/createMessage (the server asks the model to generate text
	// under a prompt it wrote), elicitation/create (the server asks the user
	// for input through a form it wrote), roots/list, ping. They are
	// decided like tool calls: exact method or glob, allow | deny | ask.
	// With no rules listed, ping and roots/list are allowed and everything
	// else denied; listing rules replaces those defaults. Reloaded with
	// tools and ask.
	ServerRequests struct {
		Default Decision            `yaml:"default"`
		Rules   map[string]Decision `yaml:"rules"`
	} `yaml:"server_requests"`

	// Limits are budgets per window (token buckets, see package limits):
	// tools/call overall and per rule pattern, bytes of tools/call
	// arguments, bytes written to the network (relay, HTTP_PROXY, or the
	// request bodies of a remote server). A call over budget is denied
	// before it reaches the server; a connection over budget ends. Fixed
	// at start.
	Limits struct {
		Calls       limits.Rate            `yaml:"calls"`
		Tools       map[string]limits.Rate `yaml:"tools"` // exact name or glob
		ArgsBytes   limits.Rate            `yaml:"args_bytes"`
		EgressBytes limits.Rate            `yaml:"egress_bytes"`
	} `yaml:"limits"`

	// Lint applies content heuristics (package scan) to what the server
	// defines: hidden markup and invisible characters, text addressed to
	// the model, sensitive paths, fetch-and-run and exfiltration phrases.
	// A finding is a hint for the person approving, not a verdict.
	Lint struct {
		// Lists covers tools/list, prompts/list and resources(/templates)/list
		// whenever the lock has something new to decide (first contact or a
		// change): "warn" (default) logs and audits the findings, "deny"
		// also holds a first-contact list for review as if lock.first were
		// review, "off" skips the scan.
		Lists LintMode `yaml:"lists"`
		// Results covers what the server returns: tools/call results,
		// resources/read contents, prompts/get messages and
		// notifications/message, with the rules that make sense for data
		// (hidden characters, hidden markup, text addressed to the model).
		// "warn" (default) audits the findings and forwards the result;
		// "deny" replaces the result with an error (and drops the
		// notification), also when it is too large to scan; "off" skips it.
		Results LintMode `yaml:"results"`
		// Ignore lists rule ids (scan.Rules) that are not reported.
		Ignore []string `yaml:"ignore"`
	} `yaml:"lint"`

	Audit struct {
		// Path of the JSONL audit log. Empty disables it. Supports ~ expansion.
		Path string `yaml:"path"`
		// Args logs tool-call arguments. Off by default: they may hold secrets.
		Args bool `yaml:"args"`
	} `yaml:"audit"`

	Sandbox struct {
		// Disabled runs the server unsandboxed (policy + lock + audit only).
		// Backend none is the same thing.
		Disabled bool `yaml:"disabled"`
		// Backend picks the isolation: auto (default: bwrap on Linux,
		// sandbox-exec on macOS), bwrap, sandbox-exec, docker (a container
		// from Image with the policy's paths bind-mounted; works wherever
		// docker or podman does, Windows included) or none.
		Backend Backend `yaml:"backend"`
		// Image is the container image for the docker backend. Empty: derived
		// from the launcher (node/npx, bun/bunx, uv/uvx, python), otherwise
		// required.
		Image string `yaml:"image"`
		// Env lists environment variables for the jailed server: a bare NAME
		// passes the host's value through, NAME=value sets one. Every jail
		// also gets the update-check and telemetry opt-outs (DO_NOT_TRACK=1,
		// NO_UPDATE_NOTIFIER=1, npm_config_update_notifier=false), which an
		// entry of the same name overrides.
		Env []string `yaml:"env"`
	} `yaml:"sandbox"`

	// Exec pins executables outside the base system paths that the jailed
	// process tree may run, for launchers (npx, uvx, a thin npm package)
	// that exec a separately installed binary. Each Allow entry is made
	// visible on its own (a file bind on Linux, a process-exec literal on
	// macOS), so an unlisted sibling in the same directory is absent or not
	// executable; a directory listed in filesystem.* stays executable as a
	// whole. SHA256 pins a file's content: a mismatch refuses to start.
	// Needs the sandbox; refused with sandbox.disabled or on a platform
	// without one.
	Exec struct {
		Allow  []string          `yaml:"allow"`
		SHA256 map[string]string `yaml:"sha256"` // path -> hex digest
	} `yaml:"exec"`

	// Server, when url is set, is a remote MCP server reached over Streamable
	// HTTP instead of a command started in a sandbox: `run` takes no command,
	// the sandbox, filesystem and network sections do not apply (the jail
	// itself talks to exactly this URL), and tools, ask, lock and audit work
	// as for a local server. Plain http is accepted for localhost only;
	// redirects are never followed; headers go to this URL and nowhere else.
	Server struct {
		URL     string            `yaml:"url"`
		Headers map[string]string `yaml:"headers"` // values support ${ENV} expansion
	} `yaml:"server"`
}

// LockNotify reports lock.notify (default true).
func (p *Policy) LockNotify() bool { return p.Lock.Notify == nil || *p.Lock.Notify }

// Remote reports whether the policy names a remote server (server.url).
func (p *Policy) Remote() bool { return p.Server.URL != "" }

// reservedHeaders are set by the transport and cannot come from the policy.
var reservedHeaders = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "accept": true,
	"mcp-session-id": true, "mcp-protocol-version": true, "last-event-id": true,
	"connection": true, "transfer-encoding": true,
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
	// Secrets overrides tools.secrets for this rule; "" inherits.
	Secrets SecretsMode `yaml:"secrets"`
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
	p.Lock.First = FirstRecord
	p.Lock.Scope = ScopeList
	p.Lint.Lists = LintWarn
	p.Lint.Results = LintWarn
	p.Tools.Secrets = SecretsWarn
	p.ServerRequests.Default = Deny
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
	switch p.Lock.First {
	case "":
		p.Lock.First = FirstRecord
	case FirstRecord, FirstReview:
	default:
		return fmt.Errorf("lock.first must be record|review, got %q", p.Lock.First)
	}
	switch p.Lock.Scope {
	case "":
		p.Lock.Scope = ScopeList
	case ScopeList, ScopeItem:
	default:
		return fmt.Errorf("lock.scope must be list|item, got %q", p.Lock.Scope)
	}
	for pat := range p.Limits.Tools {
		if pat == "" || hasControl(pat) {
			return fmt.Errorf("limits.tools: %q is not a tool name or glob", pat)
		}
	}
	if !p.Limits.EgressBytes.Zero() && p.Network.Mode == NetAll && !p.Remote() {
		return errors.New("limits.egress_bytes needs network.mode: allowlist (the budget is enforced on the relay or proxy) or a remote server")
	}
	if p.ServerRequests.Default == "" {
		p.ServerRequests.Default = Deny
	}
	if err := checkDecision(p.ServerRequests.Default); err != nil {
		return fmt.Errorf("server_requests.default: %w", err)
	}
	if p.ServerRequests.Rules == nil {
		p.ServerRequests.Rules = map[string]Decision{"ping": Allow, "roots/list": Allow}
	}
	for m, d := range p.ServerRequests.Rules {
		if m == "" || hasControl(m) {
			return fmt.Errorf("server_requests.rules: %q is not a method", m)
		}
		if err := checkDecision(d); err != nil {
			return fmt.Errorf("server_requests.rules[%s]: %w", m, err)
		}
	}
	switch p.Lint.Lists {
	case "":
		p.Lint.Lists = LintWarn
	case LintOff, LintWarn, LintDeny:
	default:
		return fmt.Errorf("lint.lists must be off|warn|deny, got %q", p.Lint.Lists)
	}
	switch p.Lint.Results {
	case "":
		p.Lint.Results = LintWarn
	case LintOff, LintWarn, LintDeny:
	default:
		return fmt.Errorf("lint.results must be off|warn|deny, got %q", p.Lint.Results)
	}
	for _, r := range p.Lint.Ignore {
		if !scan.Known(r) {
			return fmt.Errorf("lint.ignore: unknown rule %q (rules: %s)", r, strings.Join(scan.Rules, ", "))
		}
	}
	if p.Tools.Secrets == "" {
		p.Tools.Secrets = SecretsWarn
	}
	if err := checkSecretsMode(p.Tools.Secrets); err != nil {
		return fmt.Errorf("tools.secrets: %w", err)
	}
	for _, r := range p.Tools.SecretsIgnore {
		if !knownSecretRule(r) {
			return fmt.Errorf("tools.secrets_ignore: unknown rule %q (rules: %s)", r, strings.Join(scan.SecretRules, ", "))
		}
	}
	for k, r := range p.Tools.Rules {
		if err := checkDecision(r.Decision); err != nil {
			return fmt.Errorf("tools.rules[%s]: %w", k, err)
		}
		if r.Secrets != "" {
			if err := checkSecretsMode(r.Secrets); err != nil {
				return fmt.Errorf("tools.rules[%s].secrets: %w", k, err)
			}
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
	for _, e := range p.Sandbox.Env {
		name, _, _ := strings.Cut(e, "=")
		if !envName(name) || hasControl(e) {
			return fmt.Errorf("sandbox.env: %q is not NAME or NAME=value", e)
		}
	}
	switch p.Sandbox.Backend {
	case "":
		p.Sandbox.Backend = BackendAuto
	case BackendNone:
		p.Sandbox.Disabled = true
	case BackendAuto, BackendBwrap, BackendSandboxExec, BackendDocker:
	default:
		return fmt.Errorf("sandbox.backend must be auto|bwrap|sandbox-exec|docker|none, got %q", p.Sandbox.Backend)
	}
	if p.Sandbox.Disabled {
		p.Sandbox.Backend = BackendNone
	}
	if p.Sandbox.Image != "" {
		if p.Sandbox.Backend != BackendDocker {
			return errors.New("sandbox.image needs sandbox.backend: docker")
		}
		if strings.ContainsAny(p.Sandbox.Image, " \t\"'") || hasControl(p.Sandbox.Image) || strings.HasPrefix(p.Sandbox.Image, "-") {
			return fmt.Errorf("sandbox.image: %q is not an image reference", p.Sandbox.Image)
		}
	}
	p.Filesystem.ReadOnly = expandAll(p.Filesystem.ReadOnly)
	p.Filesystem.ReadWrite = expandAll(p.Filesystem.ReadWrite)
	p.Audit.Path = expand(p.Audit.Path)
	if err := p.validateExec(); err != nil {
		return err
	}
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
		if u.Scheme == "http" && !loopbackName(u.Hostname()) {
			// an allow over plain HTTP is one on-path attacker away
			return fmt.Errorf("ask.webhook.url: plain http is only allowed for localhost, got %q", w.URL)
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
	if s := &p.Server; s.URL != "" {
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("server.url must be an http(s) URL, got %q", s.URL)
		}
		if u.User != nil {
			return errors.New("server.url: credentials in the URL are not allowed; use server.headers")
		}
		if u.Scheme == "http" && !loopbackName(u.Hostname()) {
			return fmt.Errorf("server.url: plain http is only allowed for localhost, got %q", s.URL)
		}
		for k, v := range s.Headers {
			v = os.ExpandEnv(v)
			if k == "" || hasControl(k) || strings.ContainsAny(k, " :") || hasControl(v) {
				return fmt.Errorf("server.headers[%q]: not a valid header", k)
			}
			if reservedHeaders[strings.ToLower(k)] {
				return fmt.Errorf("server.headers[%s]: set by mcp-jail, cannot be overridden", k)
			}
			s.Headers[k] = v
		}
	}
	return nil
}

// validateExec expands and checks exec.allow and exec.sha256: absolute,
// clean, distinct paths; every pinned digest names an allowed path and is a
// lowercase SHA-256 hex string.
func (p *Policy) validateExec() error {
	e := &p.Exec
	if len(e.Allow) == 0 && len(e.SHA256) == 0 {
		return nil
	}
	if p.Sandbox.Disabled {
		return errors.New("exec.allow cannot be enforced with sandbox.disabled: true")
	}
	if p.Remote() {
		return errors.New("exec.allow does not apply to a remote server (server.url)")
	}
	seen := map[string]bool{}
	for i, a := range e.Allow {
		if hasControl(a) {
			return fmt.Errorf("exec.allow[%d]: control character in path", i)
		}
		a = expand(a)
		if !filepath.IsAbs(a) {
			return fmt.Errorf("exec.allow[%d]: must be an absolute path, got %q", i, a)
		}
		a = filepath.Clean(a)
		if seen[a] {
			return fmt.Errorf("exec.allow: %s listed twice", a)
		}
		seen[a] = true
		e.Allow[i] = a
	}
	pins := make(map[string]string, len(e.SHA256))
	for k, v := range e.SHA256 {
		if hasControl(k) {
			return errors.New("exec.sha256: control character in path")
		}
		path := filepath.Clean(expand(k))
		if !seen[path] {
			return fmt.Errorf("exec.sha256[%s]: not in exec.allow", k)
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
			return fmt.Errorf("exec.sha256[%s]: must be a 64-digit hex SHA-256", k)
		}
		pins[path] = v
	}
	e.SHA256 = pins
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

// envName reports whether s is a portable environment variable name.
func envName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// loopbackName reports whether host names the local machine.
func loopbackName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func checkDecision(d Decision) error {
	switch d {
	case Allow, Deny, Ask:
		return nil
	}
	return fmt.Errorf("must be allow|deny|ask, got %q", d)
}

// Rule returns the rule for a tool name. Exact match wins over glob; among
// globs, the longest pattern wins, and between patterns of the same length
// the stricter decision (deny over ask over allow) so that the outcome
// does not depend on map order; otherwise the default decision applies.
func (p *Policy) Rule(tool string) Rule {
	if r, ok := pick(p.Tools.Rules, tool, func(r Rule) Decision { return r.Decision }); ok {
		return r
	}
	return Rule{Decision: p.Tools.Default}
}

func knownSecretRule(id string) bool {
	for _, r := range scan.SecretRules {
		if r == id {
			return true
		}
	}
	return false
}

// SecretsFor returns the secrets mode in force for a tool: the matching
// rule's own, else tools.secrets.
func (p *Policy) SecretsFor(tool string) SecretsMode {
	if m := p.Rule(tool).Secrets; m != "" {
		return m
	}
	return p.Tools.Secrets
}

// ToolLimit returns the limits.tools pattern that governs tool and its
// rate, matched like a rule; "" when none.
func (p *Policy) ToolLimit(tool string) (string, limits.Rate) {
	type pr struct {
		pat  string
		rate limits.Rate
	}
	rules := make(map[string]pr, len(p.Limits.Tools))
	for pat, r := range p.Limits.Tools {
		rules[pat] = pr{pat, r}
	}
	// every pattern is equally strict: ties go to the longest, then the
	// first in sorted order so the outcome does not depend on map order
	if r, ok := rules[tool]; ok {
		return r.pat, r.rate
	}
	best := pr{}
	for pat, r := range rules {
		if ok, _ := filepath.Match(pat, tool); ok && (len(pat) > len(best.pat) || (len(pat) == len(best.pat) && pat < best.pat)) {
			best = r
		}
	}
	return best.pat, best.rate
}

// ServerRequest returns the decision for a request the server sends to
// the client, matched like a tool rule.
func (p *Policy) ServerRequest(method string) Decision {
	if d, ok := pick(p.ServerRequests.Rules, method, func(d Decision) Decision { return d }); ok {
		return d
	}
	return p.ServerRequests.Default
}

// pick finds the rule governing name: an exact key, else the longest
// matching glob, ties broken by the stricter decision.
func pick[V any](rules map[string]V, name string, dec func(V) Decision) (V, bool) {
	if r, ok := rules[name]; ok {
		return r, true
	}
	var best V
	bestLen := -1
	for pat, r := range rules {
		ok, _ := filepath.Match(pat, name)
		if !ok {
			continue
		}
		if len(pat) > bestLen || (len(pat) == bestLen && strictness(dec(r)) > strictness(dec(best))) {
			best, bestLen = r, len(pat)
		}
	}
	return best, bestLen >= 0
}

func strictness(d Decision) int {
	switch d {
	case Deny:
		return 2
	case Ask:
		return 1
	}
	return 0
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
  # An argument that looks like a credential (AWS key, private key, JWT, bearer
  # token, password assignment, the value of a secret-looking variable in
  # mcp-jail's environment): warn audits it, deny refuses the call, ask asks
  # even when the rule says allow. A rule may set its own "secrets:".
  secrets: warn
  # secrets_ignore: [password-assignment]

# Budgets per window (a burst up to the limit passes, a steady drip above it
# does not). A call over budget is denied; a connection over budget ends.
# limits:
#   calls: 60/1m                 # tools/call, all tools
#   tools: { "send_*": 5/1h }    # per tool (exact name or glob)
#   args_bytes: 1MB/1h           # bytes of tools/call arguments
#   egress_bytes: 50MB/1h        # bytes out to the network (allowlist mode or a remote server)

# Requests the server sends to the client: sampling/createMessage (the server
# asks the model to generate text under its own prompt), elicitation/create
# (a form for the user), roots/list, ping. Decided like tools: allow | deny |
# ask. Without rules, ping and roots/list are allowed and the rest denied;
# listing rules replaces those defaults.
# server_requests:
#   default: deny
#   rules:
#     ping: allow
#     roots/list: allow
#     sampling/createMessage: ask

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
  # record – trust the first tools/prompts/resources list and record it
  # review – show the first list and record it only after you approve it
  #          (terminal prompt, Approve in the dashboard, or mcp-jail approve)
  first: record
  # list – a change refuses the whole list and every use of it until approved
  # item – the unchanged items keep working; only the added or changed ones
  #        are held back until approved (for servers whose tool list varies)
  scope: list
  # notify: false  # do not tell the client (notifications/*/list_changed) when a pending change is approved

# Content heuristics on what the server defines, applied whenever the lock
# has something new to decide: hidden markup or invisible characters, text
# addressed to the model, sensitive paths, fetch-and-run or exfiltration
# phrases. warn logs them; deny also holds a first-contact list for review.
lint:
  lists: warn     # off | warn | deny: tool, prompt and resource definitions
  results: warn   # off | warn | deny: what the server returns (results, resources, prompts, log messages)
  # ignore: [encoded]   # rule ids to skip: hidden-unicode hidden-markup instruction
                        # sensitive-path fetch-and-run exfiltration encoded shadowing

audit:
  path: ~/.local/state/mcp-jail/my-server.jsonl
  args: false     # log tool arguments (may contain secrets)

sandbox:
  disabled: false
  # auto (bwrap on Linux, sandbox-exec on macOS) | bwrap | sandbox-exec | none
  # docker: run the server in a container (docker or podman) with the policy's
  #         paths bind-mounted; the only sandbox on Windows. network allowlist
  #         needs a Linux host; exec pins do not apply (the image is the pin)
  backend: auto
  # image: node:22-slim         # docker only; derived from npx/uvx/python when omitted
  env: [PATH, HOME, LANG]       # NAME passes the host's value through, NAME=value sets one
  # env: [PATH, HOME, npm_config_ignore_scripts=true]   # e.g. no install scripts for npx packages

# Pin executables a launcher (npx, uvx, a thin npm package) execs from
# outside the system paths: each file is made visible on its own, so an
# unlisted sibling is not. sha256 refuses to start if the file changed.
# exec:
#   allow:
#     - ~/.local/bin/some-server
#   sha256:
#     ~/.local/bin/some-server: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# A remote server over Streamable HTTP instead of a command: set server.url
# (https, or http for localhost) and run without a command after --. The
# sandbox, filesystem and network sections then do not apply.
# server:
#   url: https://mcp.example.com/mcp
#   headers: { Authorization: "Bearer ${MCP_EXAMPLE_TOKEN}" }
`
