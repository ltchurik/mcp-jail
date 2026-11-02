package ui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
)

func writeLog(t *testing.T, path string, server string, n int, start time.Time) {
	t.Helper()
	l, err := audit.Open(path, server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	for i := 0; i < n; i++ {
		dec := "allow"
		if i%3 == 0 {
			dec = "deny"
		}
		l.Log(audit.Event{Kind: "tool_call", Tool: "t" + string(rune('a'+i%5)), Decision: dec, Reason: "r"})
	}
	_ = start
}

func TestReadEventsFilterLimitSkip(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.jsonl")
	b := filepath.Join(dir, "b.jsonl")
	writeLog(t, a, "alpha", 9, time.Now())
	writeLog(t, b, "beta", 4, time.Now())
	// garbage lines are skipped, not fatal
	f, _ := os.OpenFile(b, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("not json\n\n{\"kind\":\"no_ts\"}\n")
	_ = f.Close()

	evs, skipped := ReadEvents([]string{a, b, filepath.Join(dir, "missing.jsonl")}, Filter{}, 0)
	if len(evs) != 13 || skipped != 2 {
		t.Fatalf("got %d events, %d skipped", len(evs), skipped)
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].Time.After(evs[i-1].Time) {
			t.Fatal("not newest first")
		}
	}
	evs, _ = ReadEvents([]string{a, b}, Filter{Server: "beta"}, 100)
	if len(evs) != 4 {
		t.Fatalf("server filter: %d", len(evs))
	}
	evs, _ = ReadEvents([]string{a, b}, Filter{Decision: "deny"}, 100)
	if len(evs) != 3+2 {
		t.Fatalf("decision filter: %d", len(evs))
	}
	evs, _ = ReadEvents([]string{a, b}, Filter{Tool: "ta", Server: "alpha"}, 100)
	if len(evs) != 2 {
		t.Fatalf("tool filter: %d", len(evs))
	}
	evs, _ = ReadEvents([]string{a, b}, Filter{Query: "ALPHA"}, 100)
	if len(evs) != 9 {
		t.Fatalf("query filter: %d", len(evs))
	}
	evs, _ = ReadEvents([]string{a, b}, Filter{}, 5)
	if len(evs) != 5 {
		t.Fatalf("limit: %d", len(evs))
	}
	evs, _ = ReadEvents([]string{a}, Filter{Since: time.Now().Add(time.Hour)}, 5)
	if len(evs) != 0 {
		t.Fatalf("since in the future: %d", len(evs))
	}
	evs, _ = ReadEvents([]string{a}, Filter{Until: time.Now().Add(-time.Hour)}, 5)
	if len(evs) != 0 {
		t.Fatalf("until in the past: %d", len(evs))
	}
}

func TestTailer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	writeLog(t, p, "s", 2, time.Now())
	later := filepath.Join(dir, "later.jsonl")
	tl := NewTailer(func() []string { return []string{p, later} })
	if got := tl.Poll(); len(got) != 0 {
		t.Fatalf("existing lines must not be replayed: %d", len(got))
	}
	writeLog(t, p, "s", 3, time.Now())
	writeLog(t, later, "l", 1, time.Now())
	got := tl.Poll()
	if len(got) != 4 {
		t.Fatalf("want 4 new events, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Time.Before(got[i-1].Time) {
			t.Fatal("not oldest first")
		}
	}
	// a partial line is held back until its newline arrives
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"ts":"2026-01-01T00:00:00Z","server":"s","kind":"tool_call","tool":"half"`)
	_ = f.Close()
	if got := tl.Poll(); len(got) != 0 {
		t.Fatalf("partial line delivered: %+v", got)
	}
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(",\"decision\":\"allow\"}\n")
	_ = f.Close()
	got = tl.Poll()
	if len(got) != 1 || got[0].Tool != "half" || got[0].Decision != "allow" {
		t.Fatalf("joined partial line: %+v", got)
	}
	// truncation restarts from the beginning
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeLog(t, p, "s", 1, time.Now())
	if got := tl.Poll(); len(got) != 1 {
		t.Fatalf("after truncate: %d", len(got))
	}
}
