package proxy

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/control"
	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

func reviewPolicy(t *testing.T) *policy.Policy {
	p := basePolicy(t)
	p.Lock.First = policy.FirstReview
	p.Ask.Timeout = 3 * time.Second
	return p
}

// Without a terminal or a dashboard, a first list is refused at once, saved
// for review, and its uses are refused; `approve` records it for the next
// session.
func TestReviewRefusesFirstContactHeadless(t *testing.T) {
	p := reviewPolicy(t)
	s := start(t, p, toolsV1)
	m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(m.Error.Message, "seen for the first time") || !strings.Contains(m.Error.Message, "no tty") {
		t.Fatalf("first contact must be refused for review, got %s", m.Raw)
	}
	m = s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	if m.Error == nil || m.Error.Code != jsonrpc.CodeRugPull || !strings.Contains(m.Error.Message, "seen for the first time") {
		t.Fatalf("use of an unreviewed list must be refused, got %s", m.Raw)
	}
	s.close()
	if f, _ := lock.Load("test"); f != nil {
		t.Fatalf("nothing may be recorded before approval, got %+v", f)
	}
	pend, err := lock.LoadPending("test")
	if err != nil || pend == nil || len(pend.Sections[lock.Tools].Items) != 2 {
		t.Fatalf("pending: %+v %v", pend, err)
	}
	if _, err := lock.Approve("test"); err != nil {
		t.Fatal(err)
	}
	s = start(t, p, toolsV1)
	defer s.close()
	if m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); m.Error != nil {
		t.Fatalf("approved list refused: %s", m.Raw)
	}
	if m := s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`); m.Error != nil {
		t.Fatalf("call after approval refused: %s", m.Raw)
	}
}

// With a dashboard attached the list waits for an out-of-band approve
// (Approve button, `mcp-jail approve`) and is forwarded once it lands.
func TestReviewWaitsForDashboardApprove(t *testing.T) {
	p := reviewPolicy(t)
	b := control.NewBroker("test")
	b.List() // the dashboard polled: attached
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), Asks: b}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	defer s.close()
	go func() {
		for i := 0; i < 100; i++ {
			if pend, _ := lock.LoadPending("test"); pend != nil {
				_, _ = lock.Approve("test")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	start := time.Now()
	m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if m.Error != nil {
		t.Fatalf("approved during the wait, yet refused: %s", m.Raw)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %s, should return as soon as the approve lands", time.Since(start))
	}
	if m := s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`); m.Error != nil {
		t.Fatalf("call after dashboard approval refused: %s", m.Raw)
	}
	f, _ := lock.Load("test")
	if f == nil || f.Section(lock.Tools) == nil {
		t.Fatal("lock not recorded")
	}
}

// Nobody approves in time: refused, nothing recorded, pending kept.
func TestReviewDashboardTimeoutRefuses(t *testing.T) {
	p := reviewPolicy(t)
	p.Ask.Timeout = time.Second
	b := control.NewBroker("test")
	b.List()
	sIn, sOut := fakeServer(t, toolsV1, nil)
	cInR, cInW := io.Pipe()
	cOutR, cOutW := io.Pipe()
	px := &Proxy{Policy: p, Logf: t.Logf, TTYPath: filepath.Join(t.TempDir(), "no-such-tty"), Asks: b}
	done := make(chan error, 1)
	go func() { done <- px.Run(cInR, cOutW, sIn, sOut); _ = cOutW.Close() }()
	s := &session{t: t, toCli: cInW, fromCl: newReader(cOutR), done: done}
	defer s.close()
	m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if m.Error == nil || !strings.Contains(m.Error.Message, "no answer within") {
		t.Fatalf("expected a timeout refusal, got %s", m.Raw)
	}
	if f, _ := lock.Load("test"); f != nil {
		t.Fatal("nothing may be recorded on a timeout")
	}
	if pend, _ := lock.LoadPending("test"); pend == nil {
		t.Fatal("pending must be kept for a later approve")
	}
}

// The default (record) keeps today's behaviour: trust on first contact.
func TestRecordIsDefault(t *testing.T) {
	p := basePolicy(t)
	if p.Lock.First != policy.FirstRecord {
		t.Fatalf("default lock.first = %q", p.Lock.First)
	}
	s := start(t, p, toolsV1)
	defer s.close()
	if m := s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); m.Error != nil {
		t.Fatalf("record mode must forward the first list: %s", m.Raw)
	}
}

func TestCatalog(t *testing.T) {
	items := rawItems(`[{"name":"b","description":"Second\nline two"},{"name":"a","description":"` + strings.Repeat("x", 150) + `"},{"name":"c"}]`)
	got := catalog(lock.Tools, items, 2)
	if len(got) != 3 || !strings.HasPrefix(got[0], "a  —  "+strings.Repeat("x", 100)+"…") || got[1] != "b  —  Second" || got[2] != "… and 1 more" {
		t.Fatalf("catalog = %q", got)
	}
	if got := catalog(lock.Resources, rawItems(`[{"uri":"file:///r","description":"R"}]`), 10); len(got) != 1 || got[0] != "file:///r  —  R" {
		t.Fatalf("resources catalog = %q", got)
	}
}

func rawItems(s string) []json.RawMessage {
	var items []json.RawMessage
	_ = json.Unmarshal([]byte(s), &items)
	return items
}
