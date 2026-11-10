package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yml")
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil { //nolint:gosec // group-readable on purpose: SetRule must keep the mode
		t.Fatal(err)
	}
	return p
}

func TestSetRuleKeepsCommentsAndOrder(t *testing.T) {
	tmp, quoted := "/tmp", "/tmp" // an absolute path on this OS, and how the writer spells it
	if runtime.GOOS == "windows" {
		tmp, quoted = `C:\tmp`, `'C:\tmp'`
	}
	p := writeTemp(t, `# my policy
name: demo

network:
  mode: none   # no egress

tools:
  # defaults first
  default: ask
  rules:
    "read_*": allow   # cheap
    delete_file: ask
    write_file:
      decision: ask
      args:
        path: { under: [`+tmp+`] }

lock: { enabled: false }
`)
	for _, c := range []struct {
		tool string
		d    Decision
	}{
		{"delete_file", Deny},   // scalar in place
		{"write_file", Allow},   // mapping keeps args
		{"send_*", Deny},        // new glob, quoted
		{"create_issue", Allow}, // new plain
	} {
		if err := SetRule(p, c.tool, c.d); err != nil {
			t.Fatalf("SetRule(%s): %v", c.tool, err)
		}
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	for _, want := range []string{
		"# my policy\n", "mode: none # no egress\n", "  # defaults first\n", `"read_*": allow # cheap`,
		"    delete_file: deny\n", "      decision: allow\n      args:\n        path: {under: [" + quoted + "]}\n",
		`    "send_*": deny` + "\n", "    create_issue: allow\n", "lock: {enabled: false}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if i, j := strings.Index(got, "name:"), strings.Index(got, "tools:"); i > j {
		t.Errorf("key order changed:\n%s", got)
	}
	if st, _ := os.Stat(p); runtime.GOOS != "windows" && st.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", st.Mode().Perm())
	}
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Decide("delete_file") != Deny || pol.Decide("write_file") != Allow || pol.Decide("send_mail") != Deny || pol.Decide("create_issue") != Allow || pol.Decide("read_x") != Allow {
		t.Errorf("decisions after edit: %+v", pol.Tools.Rules)
	}
	if len(pol.Tools.Rules["write_file"].Args) != 1 {
		t.Errorf("args lost: %+v", pol.Tools.Rules["write_file"])
	}
}

func TestSetRuleCreatesSections(t *testing.T) {
	for _, text := range []string{
		"name: demo\n",
		"name: demo\ntools:\n  default: deny\n",
		"name: demo\ntools:\n  default: deny\n  rules:\n",
		"name: demo\ntools: { default: deny }\n",
	} {
		p := writeTemp(t, text)
		if err := SetRule(p, "x", Allow); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		pol, err := Load(p)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if pol.Decide("x") != Allow || pol.Decide("y") != pol.Tools.Default {
			t.Errorf("%q: %+v", text, pol.Tools)
		}
	}
}

func TestSetRuleRefusesBadInput(t *testing.T) {
	p := writeTemp(t, "name: demo\nnetwork: { mode: allowlist, allow: [a.example] }\n")
	before, _ := os.ReadFile(p)
	cases := []struct {
		tool string
		d    Decision
	}{
		{"", Allow}, {"a b", Allow}, {"a\nb: allow", Deny}, {strings.Repeat("x", 129), Allow}, {"ok", Decision("maybe")},
	}
	for _, c := range cases {
		if err := SetRule(p, c.tool, c.d); err == nil {
			t.Errorf("SetRule(%q,%q) accepted", c.tool, c.d)
		}
	}
	if err := SetRule(filepath.Join(t.TempDir(), "missing.yml"), "x", Allow); err == nil {
		t.Error("missing file accepted")
	}
	// a list at the top level is not a policy
	if err := SetRule(writeTemp(t, "- a\n- b\n"), "x", Allow); err == nil {
		t.Error("sequence accepted")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Errorf("file changed by refused edits:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), ".policy.yml.x")); err == nil {
		t.Error("temp file left behind")
	}
}

func TestLiteralTool(t *testing.T) {
	cases := map[string]string{"read_file": "read_file", "*": "[*]", "a?b": "a[?]b", "[x]": "[[]x]", `a\b`: `a[\]b`}
	for in, want := range cases {
		if got := LiteralTool(in); got != want {
			t.Errorf("LiteralTool(%q) = %q, want %q", in, got, want)
		}
	}
	p := Default()
	p.Tools.Default = Deny
	p.Tools.Rules = map[string]Rule{LiteralTool("*"): {Decision: Allow}, LiteralTool("a?b"): {Decision: Allow}}
	if p.Decide("*") != Allow || p.Decide("a?b") != Allow || p.Decide("anything") != Deny || p.Decide("axb") != Deny {
		t.Fatalf("escaped rules: %+v", p.Tools.Rules)
	}
}

func TestSetRuleFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yml")
	if err := os.WriteFile(target, []byte("name: demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "policy.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := SetRule(link, "x", Allow); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	b, _ := os.ReadFile(target)
	if !strings.Contains(string(b), "x: allow") {
		t.Fatalf("target not updated:\n%s", b)
	}
}

func TestSetRuleConcurrentEditsAllLand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte("name: t\ntools:\n  default: ask\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) { errs <- SetRule(path, fmt.Sprintf("tool_%d", i), Allow) }(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tools.Rules) != n {
		t.Fatalf("got %d rules, want %d: %v", len(p.Tools.Rules), n, p.Tools.Rules)
	}
}
