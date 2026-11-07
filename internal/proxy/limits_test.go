package proxy

import (
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/limits"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

func mustRate(t *testing.T, s string) limits.Rate {
	t.Helper()
	r, err := limits.ParseRate(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Call, per-tool and argument budgets deny a call before it reaches the
// server; a denied call is not charged.
func TestLimitsOnCalls(t *testing.T) {
	p := basePolicy(t)
	p.Tools.Default = policy.Allow
	p.Limits.Calls = mustRate(t, "3/1h")
	p.Limits.Tools = map[string]limits.Rate{"delete_*": mustRate(t, "1/1h")}
	p.Limits.ArgsBytes = mustRate(t, "40B/1h")
	lim := limits.New(p.Limits.Calls, p.Limits.ArgsBytes, p.Limits.EgressBytes, p.Limits.Tools, nil)
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), Limits: lim}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	defer s.close()
	s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	call := func(id int, name, args string) *jsonrpc.Message {
		return s.call(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`)
	}
	if m := call(2, "delete_file", `{}`); m.Error != nil {
		t.Fatalf("first delete: %s", m.Raw)
	}
	m := call(3, "delete_file", `{}`)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeLimit || !strings.Contains(m.Error.Message, "over budget (tools[delete_*] 1/1h exceeded)") {
		t.Fatalf("second delete must be over budget: %s", m.Raw)
	}
	m = call(4, "read_file", `{"path":"`+strings.Repeat("x", 60)+`"}`)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeLimit || !strings.Contains(m.Error.Message, "args_bytes 40B/1h exceeded") {
		t.Fatalf("big arguments must be over budget: %s", m.Raw)
	}
	// the two refused calls were not charged: two of three calls are left
	if m := call(5, "read_file", `{}`); m.Error != nil {
		t.Fatalf("second call: %s", m.Raw)
	}
	if m := call(6, "read_file", `{}`); m.Error != nil {
		t.Fatalf("third call: %s", m.Raw)
	}
	m = call(7, "read_file", `{}`)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeLimit || !strings.Contains(m.Error.Message, "calls 3/1h exceeded") {
		t.Fatalf("fourth call must be over budget: %s", m.Raw)
	}
	// a policy-denied call never touches the budgets
	p.Tools.Rules["read_*"] = policy.Rule{Decision: policy.Deny}
	if m := call(8, "read_file", `{}`); m.Error == nil || m.Error.Code != jsonrpc.CodePolicyDenied {
		t.Fatalf("policy deny: %s", m.Raw)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
