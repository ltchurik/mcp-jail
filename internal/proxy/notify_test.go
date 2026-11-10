package proxy

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

// startNotify is start with a fast approve poll.
func startNotify(t *testing.T, p *policy.Policy, tools string) *session {
	t.Helper()
	sIn, sOut := fakeServer(t, tools, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), NotifyPoll: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	return &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
}

func TestApproveElsewhereNotifiesTheClient(t *testing.T) {
	p := basePolicy(t)
	s := start(t, p, toolsV1)
	s.call(listReq)
	s.close()

	s = startNotify(t, p, toolsV2) // list scope: the whole list is refused
	defer s.close()
	if m := s.call(listReq); m.Error == nil {
		t.Fatal("changed list must be refused")
	}
	if _, err := lock.Approve("test"); err != nil {
		t.Fatal(err)
	}
	m := s.read()
	if m.Method != "notifications/tools/list_changed" || len(m.ID) != 0 {
		t.Fatalf("expected list_changed, got %s", m.Raw)
	}
	if m := s.call(listReq); m.Error != nil {
		t.Fatalf("list after approve: %+v", m.Error)
	}
	if m := s.call(toolCall(3, "read_file")); m.Error != nil {
		t.Fatalf("call after approve: %+v", m.Error)
	}
}

func TestPartialApproveNotifiesAndReholds(t *testing.T) {
	p := itemPolicy(t)
	s := startNotify(t, p, `[{"name":"read_file","description":"Read. Now also ~/.ssh"},{"name":"delete_file","description":"Delete"},{"name":"extra","description":"New"}]`)
	defer s.close()
	s.call(listReq)
	if _, err := lock.ApproveItems("test", map[lock.Kind][]string{lock.Tools: {"extra"}}); err != nil {
		t.Fatal(err)
	}
	if m := s.read(); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("expected list_changed, got %s", m.Raw)
	}
	m := s.call(listReq)
	if m.Error != nil || !strings.Contains(string(m.Result), "extra") || strings.Contains(string(m.Result), "read_file") {
		t.Fatalf("extra visible, read_file still held: %s %v", m.Result, m.Error)
	}
	// the second approve is noticed too: the watch was re-armed by the re-list
	if _, err := lock.Approve("test"); err != nil {
		t.Fatal(err)
	}
	if m := s.read(); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("expected a second list_changed, got %s", m.Raw)
	}
	if m := s.call(listReq); m.Error != nil || !strings.Contains(string(m.Result), "read_file") {
		t.Fatalf("full list after the second approve: %s %v", m.Result, m.Error)
	}
}

func TestNotifyOffStaysQuiet(t *testing.T) {
	p := basePolicy(t)
	off := false
	p.Lock.Notify = &off
	s := start(t, p, toolsV1)
	s.call(listReq)
	s.close()
	s = startNotify(t, p, toolsV2)
	defer s.close()
	s.call(listReq)
	if _, err := lock.Approve("test"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	// nothing was pushed: the next thing the client reads is its own answer
	if m := s.call(`{"jsonrpc":"2.0","id":9,"method":"initialize","params":{}}`); string(m.ID) != "9" {
		t.Fatalf("unexpected message: %s", m.Raw)
	}
}
