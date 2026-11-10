package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecide(t *testing.T) {
	p := Default()
	p.Tools.Default = Ask
	p.Tools.Rules = map[string]Rule{
		"read_*":    {Decision: Allow},
		"read_file": {Decision: Deny},
		"*":         {Decision: Deny},
		"list_*":    {Decision: Allow},
	}
	cases := map[string]Decision{
		"read_file":  Deny,  // exact beats glob
		"read_dir":   Allow, // longest glob beats "*"
		"list_tools": Allow,
		"write_file": Deny, // "*"
	}
	for tool, want := range cases {
		if got := p.Decide(tool); got != want {
			t.Errorf("Decide(%q) = %s, want %s", tool, got, want)
		}
	}
	p.Tools.Rules = nil
	if got := p.Decide("anything"); got != Ask {
		t.Errorf("default: got %s", got)
	}
}

func TestHostAllowed(t *testing.T) {
	p := Default()
	p.Network.Allow = []string{"api.github.com", "*.githubusercontent.com"}
	for host, want := range map[string]bool{
		"api.github.com":              true,
		"API.GITHUB.COM.":             true,
		"raw.githubusercontent.com":   true,
		"githubusercontent.com":       false,
		"evil-api.github.com":         false,
		"api.github.com.evil.example": false,
	} {
		if got := p.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	p := Default()
	p.Network.Mode = "sometimes"
	if err := p.Validate(); err == nil {
		t.Error("expected error for bad network.mode")
	}
	p = Default()
	p.Network.Mode = NetAllowlist
	if err := p.Validate(); err == nil {
		t.Error("expected error for allowlist without hosts")
	}
	p = Default()
	p.Tools.Rules = map[string]Rule{"x": {Decision: "maybe"}}
	if err := p.Validate(); err == nil {
		t.Error("expected error for bad decision")
	}
}

func TestRuleYAMLForms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	doc := `
name: t
network: { mode: allowlist, allow: [api.github.com] }
tools:
  default: deny
  rules:
    "read_*": allow
    write_file:
      decision: allow
      args:
        path: { under: [` + dir + `/proj, "~/x"] }
    fetch:
      decision: ask
      args:
        url: { host: [network.allow, "*.example.org"], optional: true }
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("read_x") != Allow || p.Decide("write_file") != Allow || p.Decide("fetch") != Ask || p.Decide("other") != Deny {
		t.Fatalf("decisions: %+v", p.Tools.Rules)
	}
	home, _ := os.UserHomeDir()
	under := p.Tools.Rules["write_file"].Args["path"].Under
	if len(under) != 2 || under[0] != filepath.Join(dir, "proj") || under[1] != filepath.Join(home, "x") {
		t.Fatalf("under not expanded: %v", under)
	}

	bad := []string{
		"tools: { rules: { w: { decision: allow, args: { p: {} } } } }",
		"tools: { rules: { w: { decision: allow, args: { p: { under: [rel/path] } } } } }",
		"tools: { rules: { w: { decision: allow, args: { p: { under: [/a], host: [b] } } } } }",
		"tools: { rules: { w: { decision: allow, args: { p: { host: [network.allow] } } } } }", // network.allow is empty
		"tools: { rules: { w: { decision: maybe } } }",
		"tools: { rules: { w: { decision: allow, args: { p: { host: [\"\"] } } } } }",
	}
	for _, b := range bad {
		if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("expected error for %s", b)
		}
	}
}

func TestCheckArgs(t *testing.T) {
	p := Default()
	p.Network.Allow = []string{"api.github.com"}
	p.Tools.Rules = map[string]Rule{
		"write_file": {Decision: Allow, Args: map[string]ArgConstraint{"path": {Under: []string{"/srv/proj"}}}},
		"read_many":  {Decision: Allow, Args: map[string]ArgConstraint{"paths": {Under: []string{"/srv/proj"}, Optional: true}}},
		"fetch":      {Decision: Allow, Args: map[string]ArgConstraint{"url": {Host: []string{"network.allow", "*.example.org"}}}},
		"plain":      {Decision: Allow},
	}
	ok := map[string]string{
		"write_file": `{"path":"/srv/proj/a.txt"}`,
		"read_many":  `{"paths":["/srv/proj/a","/srv/proj/b/c"]}`,
		"fetch":      `{"url":"https://api.github.com/repos"}`,
		"plain":      `{"anything":1}`,
	}
	for tool, args := range ok {
		if err := p.CheckArgs(tool, json.RawMessage(args)); err != nil {
			t.Errorf("%s %s: unexpected %v", tool, args, err)
		}
	}
	if err := p.CheckArgs("read_many", nil); err != nil {
		t.Errorf("optional missing arg must pass: %v", err)
	}
	if err := p.CheckArgs("fetch", json.RawMessage(`{"url":"sub.example.org:8443"}`)); err != nil {
		t.Errorf("bare host:port against *.example.org: %v", err)
	}
	if err := p.CheckArgs("write_file", json.RawMessage(`{"path":"/srv/proj"}`)); err != nil {
		t.Errorf("the directory itself is inside: %v", err)
	}

	bad := map[string][]string{
		"write_file": {
			`{}`,                                 // required
			`{"path":null}`,                      // required
			`{"path":"/srv/proj/../../etc/pw"}`,  // traversal
			`{"path":"/srv/project/x"}`,          // sibling with same prefix
			`{"path":"relative/x"}`,              // not absolute
			`{"path":42}`,                        // wrong type
			`{"path":["/srv/proj/a","/etc/pw"]}`, // one bad element
			`[]`,                                 // not an object
			`not json`,
		},
		"read_many": {`{"paths":["/srv/proj/a","/tmp/x"]}`, `{"paths":"/etc"}`},
		"fetch": {
			`{"url":"https://evil.example.com/"}`,
			`{"url":"https://api.github.com.evil.net/"}`,
			`{"url":"/relative"}`,
			`{"url":""}`,
			`{"url":"https://user@/x"}`,
			`{}`,
		},
	}
	for tool, list := range bad {
		for _, args := range list {
			err := p.CheckArgs(tool, json.RawMessage(args))
			if err == nil {
				t.Errorf("%s %s: expected violation", tool, args)
			} else if !strings.Contains(err.Error(), "argument") && !strings.Contains(err.Error(), "arguments") {
				t.Errorf("%s %s: reason should name the argument: %v", tool, args, err)
			}
		}
	}
}

func TestAskWebhookValidate(t *testing.T) {
	t.Setenv("TOK", "secret")
	p := Default()
	p.Ask.Webhook.URL = "https://hooks.example/x"
	p.Ask.Webhook.Headers = map[string]string{"Authorization": "Bearer ${TOK}"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Ask.Webhook.Timeout != 60*time.Second || p.Ask.Webhook.Headers["Authorization"] != "Bearer secret" {
		t.Fatalf("defaults/expansion: %+v", p.Ask.Webhook)
	}
	for _, bad := range []func(*Policy){
		func(p *Policy) { p.Ask.Webhook.URL = "ftp://x" },
		func(p *Policy) { p.Ask.Webhook.URL = "https://" },
		func(p *Policy) { p.Ask.Webhook.URL = "https://x"; p.Ask.Webhook.Timeout = -time.Second },
		func(p *Policy) { p.Ask.Webhook.URL = "https://x"; p.Ask.Webhook.Timeout = time.Hour },
	} {
		p := Default()
		bad(p)
		if err := p.Validate(); err == nil {
			t.Errorf("expected error for %+v", p.Ask.Webhook)
		}
	}
	// yaml duration strings parse
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte("ask: { webhook: { url: https://x.example/h, timeout: 90s } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lp, err := Load(path)
	if err != nil || lp.Ask.Webhook.Timeout != 90*time.Second {
		t.Fatalf("load: %v %+v", err, lp)
	}
}

func TestRuleTieBreakIsStrict(t *testing.T) {
	p := Default()
	p.Tools.Default = Allow
	p.Tools.Rules = map[string]Rule{"read_*": {Decision: Allow}, "*_file": {Decision: Deny}}
	for i := 0; i < 50; i++ {
		if d := p.Decide("read_file"); d != Deny {
			t.Fatalf("iteration %d: %s", i, d)
		}
	}
	p.Tools.Rules = map[string]Rule{"read_*": {Decision: Ask}, "*_file": {Decision: Allow}}
	if d := p.Decide("read_file"); d != Ask {
		t.Fatal(d)
	}
	p.Tools.Rules["read_file"] = Rule{Decision: Allow} // exact still wins
	if d := p.Decide("read_file"); d != Allow {
		t.Fatal(d)
	}
}

func TestValidateName(t *testing.T) {
	for _, bad := range []string{"..", ".", "a/b", `a\b`, "a\nb", "x\x00", strings.Repeat("n", 129)} {
		p := Default()
		p.Name = bad
		if err := p.Validate(); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	for _, ok := range []string{"", "github", "my server", "@scope-server", "a.b-c_d"} {
		p := Default()
		p.Name = ok
		if err := p.Validate(); err != nil {
			t.Errorf("name %q: %v", ok, err)
		}
	}
	p := Default()
	p.Filesystem.ReadOnly = []string{"/tmp/a\nb"}
	if err := p.Validate(); err == nil {
		t.Error("control character in a path accepted")
	}
}

func TestWebhookPlainHTTPOnlyForLoopback(t *testing.T) {
	for _, u := range []string{"http://approvals.internal.example/x", "http://10.0.0.5:8765/", "http://[fe80::1]/"} {
		p := Default()
		p.Ask.Webhook.URL = u
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"http://127.0.0.1:8765/", "http://localhost:8765/", "http://[::1]:8765/", "https://approvals.internal.example/x"} {
		p := Default()
		p.Ask.Webhook.URL = u
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestServerValidate(t *testing.T) {
	t.Setenv("TOK", "secret")
	p := Default()
	p.Server.URL = "https://mcp.example.com/mcp"
	p.Server.Headers = map[string]string{"Authorization": "Bearer ${TOK}"}
	if err := p.Validate(); err != nil || p.Server.Headers["Authorization"] != "Bearer secret" || !p.Remote() {
		t.Fatalf("%v %+v", err, p.Server)
	}
	for _, bad := range []func(*Policy){
		func(p *Policy) { p.Server.URL = "http://mcp.example.com/mcp" },
		func(p *Policy) { p.Server.URL = "ftp://x/mcp" },
		func(p *Policy) { p.Server.URL = "https://user:pw@mcp.example.com/mcp" },
		func(p *Policy) {
			p.Server.URL = "https://x/mcp"
			p.Server.Headers = map[string]string{"Mcp-Session-Id": "x"}
		},
		func(p *Policy) { p.Server.URL = "https://x/mcp"; p.Server.Headers = map[string]string{"X-A": "a\nb"} },
		func(p *Policy) {
			p.Server.URL = "https://x/mcp"
			p.Server.Headers = map[string]string{"bad header": "a"}
		},
	} {
		p := Default()
		bad(p)
		if err := p.Validate(); err == nil {
			t.Errorf("accepted %+v", p.Server)
		}
	}
	for _, ok := range []string{"http://localhost:3000/mcp", "http://127.0.0.1:3000/mcp", "http://[::1]:3000/mcp"} {
		p := Default()
		p.Server.URL = ok
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestLockFirst(t *testing.T) {
	for in, want := range map[string]FirstContact{"": FirstRecord, "record": FirstRecord, "review": FirstReview} {
		text := "name: x\nlock:\n  enabled: true\n"
		if in != "" {
			text += "  first: " + in + "\n"
		}
		p, err := parse([]byte(text), "t.yml")
		if err != nil || p.Lock.First != want {
			t.Errorf("first %q: got %q, %v", in, p.Lock.First, err)
		}
	}
	if _, err := parse([]byte("name: x\nlock:\n  first: maybe\n"), "t.yml"); err == nil || !strings.Contains(err.Error(), "lock.first") {
		t.Errorf("bad lock.first accepted: %v", err)
	}
}

func TestLockScope(t *testing.T) {
	for in, want := range map[string]LockScope{"": ScopeList, "list": ScopeList, "item": ScopeItem} {
		text := "name: x\nlock:\n  enabled: true\n"
		if in != "" {
			text += "  scope: " + in + "\n"
		}
		p, err := parse([]byte(text), "t.yml")
		if err != nil || p.Lock.Scope != want {
			t.Errorf("scope %q: got %q, %v", in, p.Lock.Scope, err)
		}
	}
	if _, err := parse([]byte("name: x\nlock:\n  scope: tool\n"), "t.yml"); err == nil || !strings.Contains(err.Error(), "lock.scope") {
		t.Errorf("bad lock.scope accepted: %v", err)
	}
	if Default().Lock.Scope != ScopeList {
		t.Errorf("default scope %q", Default().Lock.Scope)
	}
}

func TestExecValidate(t *testing.T) {
	home, _ := os.UserHomeDir()
	good := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	p, err := parse([]byte("name: x\nexec:\n  allow: [~/.local/bin/srv, /opt/x/../bin/tool]\n  sha256:\n    ~/.local/bin/srv: "+strings.ToUpper(good)+"\n"), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Exec.Allow[0] != filepath.Join(home, ".local/bin/srv") || p.Exec.Allow[1] != "/opt/bin/tool" {
		t.Fatalf("allow not expanded/cleaned: %v", p.Exec.Allow)
	}
	if p.Exec.SHA256[filepath.Join(home, ".local/bin/srv")] != good {
		t.Fatalf("sha256 not keyed by the clean path / lowercased: %v", p.Exec.SHA256)
	}
	for name, text := range map[string]string{
		"relative":      "name: x\nexec: { allow: [bin/srv] }\n",
		"twice":         "name: x\nexec: { allow: [/a/b, /a/./b] }\n",
		"sha not allow": "name: x\nexec: { allow: [/a/b], sha256: { /a/c: " + good + " } }\n",
		"sha short":     "name: x\nexec: { allow: [/a/b], sha256: { /a/b: abc } }\n",
		"sha not hex":   "name: x\nexec: { allow: [/a/b], sha256: { /a/b: " + strings.Repeat("g", 64) + " } }\n",
		"disabled":      "name: x\nsandbox: { disabled: true }\nexec: { allow: [/a/b] }\n",
		"remote":        "name: x\nserver: { url: https://h/mcp }\nexec: { allow: [/a/b] }\n",
	} {
		if _, err := parse([]byte(text), "t.yml"); err == nil || !strings.Contains(err.Error(), "exec.") {
			t.Errorf("%s: expected an exec error, got %v", name, err)
		}
	}
}

func TestLintSection(t *testing.T) {
	p, err := parse([]byte("lint: { lists: deny, ignore: [encoded, shadowing] }"), "p")
	if err != nil || p.Lint.Lists != LintDeny || len(p.Lint.Ignore) != 2 {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := parse([]byte("name: x"), "p"); err != nil || p.Lint.Lists != LintWarn {
		t.Fatalf("default must be warn: %+v %v", p, err)
	}
	for _, bad := range []string{"lint: { lists: maybe }", "lint: { ignore: [nope] }"} {
		if _, err := parse([]byte(bad), "p"); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
}

func TestSandboxEnvEntries(t *testing.T) {
	if _, err := parse([]byte("sandbox: { env: [PATH, npm_config_ignore_scripts=true, X_1=a=b] }"), "p"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"sandbox: { env: [1X] }", "sandbox: { env: [\"=v\"] }", "sandbox: { env: [\"A B\"] }", "sandbox: { env: [\"A=\\u0001\"] }"} {
		if _, err := parse([]byte(bad), "p"); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
}

func TestServerRequests(t *testing.T) {
	p, err := parse([]byte("name: x"), "p")
	if err != nil {
		t.Fatal(err)
	}
	for m, want := range map[string]Decision{"ping": Allow, "roots/list": Allow, "sampling/createMessage": Deny, "elicitation/create": Deny} {
		if got := p.ServerRequest(m); got != want {
			t.Errorf("default %s = %s, want %s", m, got, want)
		}
	}
	p, err = parse([]byte("server_requests: { default: ask, rules: { \"sampling/*\": allow, sampling/createMessage: deny } }"), "p")
	if err != nil {
		t.Fatal(err)
	}
	for m, want := range map[string]Decision{"ping": Ask, "sampling/createMessage": Deny, "sampling/other": Allow} {
		if got := p.ServerRequest(m); got != want {
			t.Errorf("%s = %s, want %s", m, got, want)
		}
	}
	// listing rules replaces the defaults: an empty mapping denies ping too
	if p, err := parse([]byte("server_requests: { rules: {} }"), "p"); err != nil || p.ServerRequest("ping") != Deny {
		t.Fatalf("empty rules: %v %v", p, err)
	}
	for _, bad := range []string{"server_requests: { default: maybe }", "server_requests: { rules: { ping: sometimes } }", "server_requests: { rules: { \"\": allow } }"} {
		if _, err := parse([]byte(bad), "p"); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
}

func TestLimitsSection(t *testing.T) {
	p, err := parse([]byte("network: { mode: allowlist, allow: [a.example] }\nlimits: { calls: 60/1m, tools: { \"send_*\": 5/1h, send_mail: 2/1h, \"*\": 100/1h }, args_bytes: 1MB/1h, egress_bytes: 50MB/1h }"), "p")
	if err != nil {
		t.Fatal(err)
	}
	if p.Limits.Calls.String() != "60/1m" || p.Limits.ArgsBytes.String() != "1MB/1h" || p.Limits.EgressBytes.String() != "50MB/1h" {
		t.Fatalf("%+v", p.Limits)
	}
	for tool, want := range map[string]string{"send_mail": "send_mail", "send_x": "send_*", "other": "*"} {
		if pat, _ := p.ToolLimit(tool); pat != want {
			t.Errorf("ToolLimit(%s) = %q, want %q", tool, pat, want)
		}
	}
	if pat, r := Default().ToolLimit("x"); pat != "" || !r.Zero() {
		t.Fatalf("no limits: %q %v", pat, r)
	}
	for _, bad := range []string{"limits: { calls: 60 }", "limits: { calls: 1/1y }", "limits: { tools: { \"\": 1/1m } }", "network: { mode: all }\nlimits: { egress_bytes: 1MB/1h }"} {
		if _, err := parse([]byte(bad), "p"); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
	if _, err := parse([]byte("server: { url: https://x.example/mcp }\nlimits: { egress_bytes: 1MB/1h }"), "p"); err != nil {
		t.Fatalf("remote egress budget: %v", err)
	}
}

func TestSecretsSettings(t *testing.T) {
	p, err := parse([]byte("tools: { secrets: deny, secrets_ignore: [bearer], rules: { set_token: { decision: allow, secrets: off }, \"read_*\": allow } }"), "p")
	if err != nil {
		t.Fatal(err)
	}
	if p.SecretsFor("set_token") != SecretsOff || p.SecretsFor("read_x") != SecretsDeny || p.SecretsFor("other") != SecretsDeny {
		t.Fatalf("%+v", p.Tools)
	}
	if p, err := parse([]byte("name: x"), "p"); err != nil || p.SecretsFor("x") != SecretsWarn {
		t.Fatalf("default must be warn: %v %v", p, err)
	}
	for _, bad := range []string{"tools: { secrets: maybe }", "tools: { secrets_ignore: [nope] }", "tools: { rules: { x: { decision: allow, secrets: loud } } }"} {
		if _, err := parse([]byte(bad), "p"); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
}
