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
