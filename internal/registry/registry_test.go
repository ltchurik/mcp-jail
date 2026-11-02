package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegisterListPrune(t *testing.T) {
	t.Setenv("MCP_JAIL_HOME", filepath.Join(t.TempDir(), "locks"))
	unreg, err := Register(Entry{Name: "fs server", Policy: "/p.yml", Audit: "/a.jsonl", Command: []string{"npx", "x"}, How: "bwrap", Network: "none", Default: "deny", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	live, err := List()
	if err != nil || len(live) != 1 {
		t.Fatalf("List: %v %+v", err, live)
	}
	e := live[0]
	if e.PID != os.Getpid() || e.Name != "fs server" || e.How != "bwrap" || !e.Lock || e.StartedAt.IsZero() {
		t.Fatalf("entry: %+v", e)
	}
	if got := filepath.Base(e.path); !strings.HasPrefix(got, "fs_server-") || !strings.HasSuffix(got, "."+strconv.Itoa(e.PID)+".json") {
		t.Fatalf("file name %q", got)
	}

	// a stale entry (pid that cannot exist) and a corrupt file are skipped by List and removed by Prune
	stale := Entry{Name: "old", PID: 1 << 30, StartedAt: time.Now().Add(-time.Hour)}
	b, _ := json.Marshal(stale)
	if err := os.WriteFile(filepath.Join(Dir(), "old.1073741824.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(), "junk.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, _ = List()
	if len(live) != 1 {
		t.Fatalf("stale listed: %+v", live)
	}
	n, err := Prune()
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	live, _ = List()
	if len(live) != 1 {
		t.Fatalf("prune removed the live entry: %+v", live)
	}

	known, err := ListKnown()
	if err != nil || len(known) != 1 || known[0].Name != "fs server" || known[0].Audit != "/a.jsonl" {
		t.Fatalf("ListKnown: %v %+v", err, known)
	}

	unreg()
	live, _ = List()
	if len(live) != 0 {
		t.Fatalf("still listed after unregister: %+v", live)
	}
	known, _ = ListKnown()
	if len(known) != 1 {
		t.Fatalf("known must survive exit: %+v", known)
	}
	if err := Forget("fs server"); err != nil {
		t.Fatal(err)
	}
	known, _ = ListKnown()
	if len(known) != 0 {
		t.Fatalf("Forget: %+v", known)
	}
	if err := Forget("never"); err != nil {
		t.Fatalf("Forget of unknown must be nil: %v", err)
	}
}

func TestEmptyDir(t *testing.T) {
	t.Setenv("MCP_JAIL_HOME", filepath.Join(t.TempDir(), "nope", "locks"))
	if l, err := List(); err != nil || len(l) != 0 {
		t.Fatalf("List on missing dir: %v %v", l, err)
	}
	if n, err := Prune(); err != nil || n != 0 {
		t.Fatalf("Prune on missing dir: %d %v", n, err)
	}
	if k, err := ListKnown(); err != nil || len(k) != 0 {
		t.Fatalf("ListKnown on missing dir: %v %v", k, err)
	}
	if _, err := Register(Entry{}); err == nil {
		t.Fatal("empty name must fail")
	}
}

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{"": "server", "ok-1.2_x": "ok-1.2_x"} {
		if got := safe(in); got != want {
			t.Errorf("safe(%q) = %q, want %q", in, got, want)
		}
	}
	// names that sanitise alike get distinct files
	a, b := safe("a b"), safe("a/b")
	if a == b || !strings.HasPrefix(a, "a_b-") || len(a) != len("a_b-")+8 {
		t.Errorf("safe(\"a b\") = %q, safe(\"a/b\") = %q", a, b)
	}
	if got := safe("../x"); strings.ContainsAny(got, "/\\") || got == ".._x" {
		t.Errorf("safe(\"../x\") = %q", got)
	}
}
