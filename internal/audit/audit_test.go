package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogClipsAttackerChosenFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, err := Open(path, "srv")
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("é", 5000)
	l.Log(Event{Kind: "tool_result", Tool: long, Error: long, Reason: long, Host: long, Args: json.RawMessage(`"` + strings.Repeat("x", 100<<10) + `"`)})
	l.Log(Event{Kind: "ok", Tool: "short"})
	_ = l.Close()
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	if len(lines[0]) > 16<<10 {
		t.Fatalf("line too long: %d", len(lines[0]))
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("not valid JSON after clipping: %v", err)
	}
	if !strings.HasSuffix(e.Tool, "bytes]") || !strings.Contains(e.Tool, "…[+") || len(e.Tool) > maxField+32 {
		t.Fatalf("tool: %q", e.Tool[len(e.Tool)-40:])
	}
	var args map[string]any
	if err := json.Unmarshal(e.Args, &args); err != nil || args["truncated"] != true {
		t.Fatalf("args: %s %v", e.Args, err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil || e.Tool != "short" {
		t.Fatalf("second line: %s %v", lines[1], err)
	}
}
