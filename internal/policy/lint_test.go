package policy

import (
	"strings"
	"testing"
)

func TestLint(t *testing.T) {
	p := Default()
	p.Filesystem.ReadOnly = []string{"/home/u/projects"}
	p.Filesystem.ReadWrite = []string{"/home/u/projects/scratch"}
	p.Tools.Rules = map[string]Rule{
		"write_file": {Decision: Allow, Args: map[string]ArgConstraint{"path": {Under: []string{"/home/u/projects"}}}},
		"read_file":  {Decision: Allow, Args: map[string]ArgConstraint{"path": {Under: []string{"/home/u/projects"}}}},
		"save":       {Decision: Allow, Args: map[string]ArgConstraint{"path": {Under: []string{"/home/u/projects/scratch/out"}}}},
		"fetch_to":   {Decision: Ask, Args: map[string]ArgConstraint{"dest": {Under: []string{"/var/data"}}}},
		"delete":     {Decision: Deny, Args: map[string]ArgConstraint{"path": {Under: []string{"/etc"}}}},
		"fetch":      {Decision: Allow, Args: map[string]ArgConstraint{"url": {Host: []string{"network.allow"}}}},
	}
	got := p.Lint()
	want := []string{
		"tools.rules[fetch_to].args.dest: /var/data is not shared into the jail",
		"tools.rules[read_file].args.path: /home/u/projects is read-only inside the jail",
		"tools.rules[write_file].args.path: /home/u/projects is read-only inside the jail",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d warnings, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("warning %d = %q, want prefix %q", i, got[i], want[i])
		}
	}
	for _, w := range got {
		if strings.Contains(w, "delete") || strings.Contains(w, "save") || strings.Contains(w, "fetch]") {
			t.Errorf("unexpected warning %q", w)
		}
	}

	p.Sandbox.Disabled = true
	if w := p.Lint(); w != nil {
		t.Errorf("disabled sandbox: got %v, want none", w)
	}
	p.Sandbox.Disabled = false
	p.Server.URL = "https://mcp.example.com/mcp"
	if w := p.Lint(); w != nil {
		t.Errorf("remote server: got %v, want none", w)
	}
}

func TestCovered(t *testing.T) {
	dirs := []string{"/a/b", "/c/"}
	for path, want := range map[string]bool{"/a/b": true, "/a/b/x": true, "/a/bc": false, "/c/d": true, "/c": true, "/": false} {
		if got := covered(path, dirs); got != want {
			t.Errorf("covered(%q) = %v, want %v", path, got, want)
		}
	}
}
