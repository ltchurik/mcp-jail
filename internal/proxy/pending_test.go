package proxy

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
)

func TestSilentServerCannotGrowPending(t *testing.T) {
	p := basePolicy(t)
	p.Lock.Enabled = false
	sIn, sOut := rawServer(t, nil) // never answers
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), MaxPending: 2}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	defer s.close()

	for _, id := range []string{`"a"`, `2`} {
		if l := s.send(`{"jsonrpc":"2.0","id":` + id + `,"method":"ping"}`); !strings.Contains(l, `"seen"`) {
			t.Fatalf("expected the server to see the request, got %s", l)
		}
	}
	// the third request pushes the oldest ("a") out
	l := s.send(`{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	m, err := jsonrpc.Parse([]byte(l))
	if err != nil || m.Error == nil || m.Error.Code != jsonrpc.CodeNoResponse || string(m.ID) != `"a"` || !strings.Contains(m.Error.Message, "did not answer ping") {
		t.Fatalf("expected a no-response error for id \"a\", got %s", l)
	}
	if l := s.next(); !strings.Contains(l, `"seen"`) {
		t.Fatalf("third request should still reach the server, got %s", l)
	}
	px.pmu.Lock()
	n := len(px.pending)
	px.pmu.Unlock()
	if n != 2 {
		t.Fatalf("pending = %d, want 2", n)
	}
}

func TestExpiredListNoLongerCountsAsInFlight(t *testing.T) {
	p := basePolicy(t)
	sIn, sOut := rawServer(t, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), MaxPending: 1}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	defer s.close()

	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`) // seen, never answered
	l := s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)  // evicts the list
	if m, err := jsonrpc.Parse([]byte(l)); err != nil || m.Error == nil || m.Error.Code != jsonrpc.CodeNoResponse || string(m.ID) != "1" {
		t.Fatalf("expected the list to expire, got %s", l)
	}
	s.next() // seen
	// With the list gone, a call must be refused at once, not parked on it.
	l = s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	if m, err := jsonrpc.Parse([]byte(l)); err != nil || m.Error == nil || m.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(m.Error.Message, "before tools/list was verified") {
		t.Fatalf("expected an immediate refusal, got %s", l)
	}
}
