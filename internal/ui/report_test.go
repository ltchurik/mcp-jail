package ui

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
)

func sampleLog(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.jsonl")
	l, err := audit.Open(p, "fs")
	if err != nil {
		t.Fatal(err)
	}
	l.Log(audit.Event{Kind: "start", Reason: "bwrap"})
	l.Log(audit.Event{Kind: "lock", Decision: "created", Reason: "tools abc"})
	for i := 0; i < 3; i++ {
		l.Log(audit.Event{Kind: "tool_call", Tool: "read_file", Decision: "allow"})
		l.Log(audit.Event{Kind: "tool_result", Tool: "read_file", Duration: 10 * time.Millisecond})
	}
	l.Log(audit.Event{Kind: "tool_call", Tool: "delete_file", Decision: "deny", Reason: "policy"})
	l.Log(audit.Event{Kind: "tool_call", Tool: "delete_file", Decision: "deny", Reason: "policy"})
	l.Log(audit.Event{Kind: "tool_call", Tool: "fetch", Decision: "ask_allow", Reason: "tty"})
	l.Log(audit.Event{Kind: "tool_result", Tool: "fetch", Duration: 30 * time.Millisecond, Error: "timeout"}) // single call+result pair: order matters
	l.Log(audit.Event{Kind: "tool_call", Tool: "fetch", Decision: "ask_deny", Reason: "webhook: timeout"})
	l.Log(audit.Event{Kind: "net", Host: "api.github.com", Decision: "allow"})
	l.Log(audit.Event{Kind: "net", Host: "pastebin.com", Decision: "blocked"})
	l.Log(audit.Event{Kind: "dns", Host: "pastebin.com", Decision: "blocked"})
	l.Log(audit.Event{Kind: "exit", Reason: "0"})
	_ = l.Close()
	return p
}

func TestBuildReport(t *testing.T) {
	p := sampleLog(t)
	now := time.Now().UTC()
	r := BuildReport([]string{p}, Filter{Since: now.Add(-time.Hour)}, now)
	if r.Total != 17 || r.Skipped != 0 || r.Truncated || len(r.Files) != 1 {
		t.Fatalf("totals: %+v", r)
	}
	if r.Decisions["allow"] != 4 || r.Decisions["deny"] != 2 || r.Decisions["blocked"] != 2 || r.Decisions["ask_allow"] != 1 || r.Decisions["ask_deny"] != 1 || r.Decisions["created"] != 1 {
		t.Fatalf("decisions: %v", r.Decisions)
	}
	if len(r.Servers) != 1 || r.Servers[0].Name != "fs" || r.Servers[0].Calls != 7 || r.Servers[0].Starts != 1 {
		t.Fatalf("servers: %+v", r.Servers)
	}
	if len(r.Tools) != 3 || r.Tools[0].Tool != "delete_file" || r.Tools[0].Deny != 2 || r.Tools[1].Tool != "fetch" || r.Tools[1].AskDeny != 1 || r.Tools[1].AskAllow != 1 || r.Tools[1].Errors != 1 {
		t.Fatalf("tools order (most denied first): %+v", r.Tools)
	}
	rf := r.Tools[2]
	if rf.Tool != "read_file" || rf.Allow != 3 || rf.AvgMs != 10 {
		t.Fatalf("read_file: %+v", rf)
	}
	if len(r.Hosts) != 2 || r.Hosts[0].Host != "pastebin.com" || r.Hosts[0].Blocked != 2 || r.Hosts[1].Allowed != 1 || r.Hosts[0].Servers[0] != "fs" {
		t.Fatalf("hosts: %+v", r.Hosts)
	}
	if len(r.Locks) != 1 || r.Locks[0].Decision != "created" {
		t.Fatalf("locks: %+v", r.Locks)
	}
	if r.Errors != 1 {
		t.Fatalf("errors: %d", r.Errors)
	}
	if len(r.Reasons) != 2 || r.Reasons[0].Count != 2 || r.Reasons[1].Count != 2 || r.Reasons[0].Reason != "network: pastebin.com" || r.Reasons[1].Reason != "policy" {
		t.Fatalf("reasons (count desc, then name): %+v", r.Reasons)
	}
	if r.Bucket != "5m0s" || len(r.Timeline) < 12 || len(r.Timeline) > 14 {
		t.Fatalf("timeline for 1h: bucket %s, %d slots", r.Bucket, len(r.Timeline))
	}
	var sum TimelineBucket
	for _, b := range r.Timeline {
		sum.Allow += b.Allow
		sum.Deny += b.Deny
		sum.Blocked += b.Blocked
		sum.Ask += b.Ask
	}
	if sum.Allow != 4 || sum.Deny != 2 || sum.Blocked != 2 || sum.Ask != 2 {
		t.Fatalf("timeline sums: %+v", sum)
	}

	// filtered by server that does not exist: empty but well-formed
	e := BuildReport([]string{p}, Filter{Server: "nope"}, now)
	if e.Total != 0 || e.Servers == nil || e.Tools == nil || e.Timeline == nil || e.Since.IsZero() {
		t.Fatalf("empty report: %+v", e)
	}
	// zero since: from the earliest event
	z := BuildReport([]string{p}, Filter{}, now)
	if z.Since.IsZero() || z.Since.After(z.Until) || z.Total != 17 {
		t.Fatalf("open since: %+v", z)
	}
}

func TestReportWriters(t *testing.T) {
	p := sampleLog(t)
	r := BuildReport([]string{p}, Filter{}, time.Now())
	var txt bytes.Buffer
	if err := r.WriteText(&txt); err != nil {
		t.Fatal(err)
	}
	s := txt.String()
	for _, want := range []string{"17 events from 1 file", "allow 4", "deny 2", "blocked 2", "delete_file", "pastebin.com", "lock events: 1", "events with errors: 1", "top deny / block reasons"} {
		if !strings.Contains(s, want) {
			t.Errorf("text report missing %q:\n%s", want, s)
		}
	}
	var c bytes.Buffer
	if err := r.WriteCSV(&c); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(c.String()), "\n")
	if lines[0] != "server,tool,total,allow,deny,ask_allow,ask_deny,errors,avg_ms" || lines[1] != "fs,delete_file,2,0,2,0,0,0," || !strings.Contains(c.String(), "pastebin.com,0,2,[fs]") {
		t.Fatalf("csv:\n%s", c.String())
	}
	empty := BuildReport(nil, Filter{}, time.Now())
	if !strings.Contains(empty.Text(), "0 events from 0 file") {
		t.Fatalf("empty text: %s", empty.Text())
	}
}

func TestShortDur(t *testing.T) {
	for d, want := range map[time.Duration]string{24 * time.Hour: "1d", 7 * 24 * time.Hour: "7d", 90 * time.Minute: "1h30m", time.Hour: "1h", 5 * time.Minute: "5m", 0: "0m"} {
		if got := shortDur(d); got != want {
			t.Errorf("shortDur(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestBucketFor(t *testing.T) {
	for span, want := range map[time.Duration]time.Duration{
		time.Hour: 5 * time.Minute, 24 * time.Hour: time.Hour, 7 * 24 * time.Hour: 24 * time.Hour, 365 * 24 * time.Hour: 7 * 24 * time.Hour,
	} {
		if got := bucketFor(span); got != want {
			t.Errorf("bucketFor(%s) = %s, want %s", span, got, want)
		}
	}
	if tl, _ := timeline(nil, time.Now(), time.Now().Add(-time.Hour)); len(tl) != 0 {
		t.Error("inverted range must be empty")
	}
}
