package proxy

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

// startWithProxy is startNoTTY that also hands back the proxy, so a test
// can reload its policy mid-session.
func startWithProxy(t *testing.T, p *policy.Policy) (*session, *Proxy) {
	t.Helper()
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty")}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	s.call(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`)
	return s, px
}

func TestReloadChangesToolDecisions(t *testing.T) {
	p := basePolicy(t)
	p.Tools.Default = policy.Deny
	p.Tools.Rules = nil
	s, px := startWithProxy(t, p)
	defer s.close()
	if m := s.call(callReq); m.Error == nil || m.Error.Code != jsonrpc.CodePolicyDenied {
		t.Fatalf("before reload: %s", m.Raw)
	}
	np := basePolicy(t)
	np.Tools.Default = policy.Deny
	np.Tools.Rules = map[string]policy.Rule{"read_*": {Decision: policy.Allow}}
	np.Network.Mode = policy.NetAll // must not leak into the live policy
	if err := px.Reload(np); err != nil {
		t.Fatal(err)
	}
	if m := s.call(callReq); m.Error != nil {
		t.Fatalf("after reload: %+v", m.Error)
	}
	if px.rules().Network.Mode != p.Network.Mode || px.Policy.Tools.Default != policy.Deny || px.Policy.Tools.Rules != nil {
		t.Errorf("reload touched more than tools/ask: live=%+v orig=%+v", px.rules().Network, px.Policy.Tools)
	}
	// back to deny
	np2 := basePolicy(t)
	np2.Tools.Default = policy.Deny
	np2.Tools.Rules = map[string]policy.Rule{"read_file": {Decision: policy.Deny}}
	if err := px.Reload(np2); err != nil {
		t.Fatal(err)
	}
	if m := s.call(callReq); m.Error == nil || m.Error.Code != jsonrpc.CodePolicyDenied {
		t.Fatalf("after second reload: %s", m.Raw)
	}
}

func TestReloadRefusesOtherServerAndNil(t *testing.T) {
	p := basePolicy(t)
	px := &Proxy{Policy: p, Logf: t.Logf}
	other := basePolicy(t)
	other.Name = p.Name + "-other"
	if err := px.Reload(other); err == nil || !strings.Contains(err.Error(), "policy is for") {
		t.Fatalf("other name: %v", err)
	}
	if err := px.Reload(nil); err == nil {
		t.Fatal("nil accepted")
	}
	if px.live.Load() != nil {
		t.Fatal("refused reload must not be stored")
	}
}
