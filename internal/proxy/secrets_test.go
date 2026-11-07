package proxy

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

const awsCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x","note":"key AKIAIOSFODNN7EXAMPLE"}}}` //nolint:gosec // the documented AWS example key, not a credential

func startSecrets(t *testing.T, p *policy.Policy, env map[string]string, logf func(string, ...any)) *session {
	t.Helper()
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), EnvSecrets: env}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	return s
}

// tools.secrets: warn (the default) lets the call through and logs it; deny
// refuses it; ask asks even for an allow rule (and denies without a tty);
// a rule's own secrets field wins; env values count as credentials.
func TestSecretsModes(t *testing.T) {
	p := basePolicy(t)
	var logs []string
	s := startSecrets(t, p, nil, func(f string, a ...any) { logs = append(logs, sprintf(f, a...)) })
	if m := s.call(awsCall); m.Error != nil {
		t.Fatalf("warn must forward: %s", m.Raw)
	}
	s.close()
	if countPrefix(logs, "secret: tools/call read_file: argument looks like a credential: note: aws-access-key (20 bytes)") != 1 {
		t.Fatalf("logs: %q", logs)
	}

	p = basePolicy(t)
	p.Tools.Secrets = policy.SecretsDeny
	s = startSecrets(t, p, nil, t.Logf)
	m := s.call(awsCall)
	if m.Error == nil || m.Error.Code != jsonrpc.CodePolicyDenied || !strings.Contains(m.Error.Message, "denied by policy: argument looks like a credential: note: aws-access-key (20 bytes)") {
		t.Fatalf("deny: %s", m.Raw)
	}
	if m := s.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"}}}`); m.Error != nil {
		t.Fatalf("clean call under deny: %s", m.Raw)
	}
	s.close()

	p = basePolicy(t)
	p.Tools.Secrets = policy.SecretsAsk
	s = startSecrets(t, p, nil, t.Logf)
	m = s.call(awsCall)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeAskRejected || !strings.Contains(m.Error.Message, "not approved (no tty)") {
		t.Fatalf("ask without tty: %s", m.Raw)
	}
	s.close()

	// a rule's own secrets: off overrides tools.secrets: deny
	p = basePolicy(t)
	p.Tools.Secrets = policy.SecretsDeny
	p.Tools.Rules["read_*"] = policy.Rule{Decision: policy.Allow, Secrets: policy.SecretsOff}
	s = startSecrets(t, p, nil, t.Logf)
	if m := s.call(awsCall); m.Error != nil {
		t.Fatalf("rule override: %s", m.Raw)
	}
	s.close()

	// the value of a secret-looking variable of mcp-jail's environment
	p = basePolicy(t)
	p.Tools.Secrets = policy.SecretsDeny
	s = startSecrets(t, p, map[string]string{"GITHUB_TOKEN": "ghp_not_a_real_token_but_long"}, t.Logf) //nolint:gosec // a made-up value, the test checks it is recognised as the env value
	m = s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x","body":"token=ghp_not_a_real_token_but_long"}}}`)
	if m.Error == nil || !strings.Contains(m.Error.Message, "body: env-value (value of $GITHUB_TOKEN)") || strings.Contains(m.Error.Message, "ghp_not") {
		t.Fatalf("env value: %s", m.Raw)
	}
	s.close()

	// secrets_ignore drops a rule
	p = basePolicy(t)
	p.Tools.Secrets = policy.SecretsDeny
	p.Tools.SecretsIgnore = []string{"aws-access-key"}
	s = startSecrets(t, p, nil, t.Logf)
	defer s.close()
	if m := s.call(awsCall); m.Error != nil {
		t.Fatalf("ignored rule: %s", m.Raw)
	}
}
