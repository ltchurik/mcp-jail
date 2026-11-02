package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

func TestExplain(t *testing.T) {
	p := policy.Default()
	p.Name = "x"
	p.Filesystem.ReadOnly = []string{"/srv/ro"}
	p.Filesystem.ReadWrite = []string{"/srv/rw"}
	p.Network.Mode = policy.NetAllowlist
	p.Network.Allow = []string{"api.example.com"}
	p.Sandbox.Env = []string{"PATH"}

	plan := Explain(p, Spec{})
	switch runtime.GOOS {
	case "linux":
		if plan.Kind != "bwrap" || len(plan.Base) == 0 || !plan.Hard {
			t.Fatalf("linux plan: %+v", plan)
		}
	case "darwin":
		if plan.Kind != "sandbox-exec" || len(plan.Hidden) == 0 || !plan.Hard {
			t.Fatalf("darwin plan: %+v", plan)
		}
	default:
		if plan.Kind != "none" || plan.Hard {
			t.Fatalf("plan on %s: %+v", runtime.GOOS, plan)
		}
	}
	if len(plan.ReadOnly) != 1 || plan.ReadOnly[0] != "/srv/ro" || len(plan.ReadWrite) != 1 || !plan.Tmp {
		t.Fatalf("filesystem: %+v", plan)
	}
	if plan.Network != "allowlist" || len(plan.Allow) != 1 || len(plan.Env) != 1 || plan.Env[0] != "PATH" {
		t.Fatalf("network/env: %+v", plan)
	}

	// a server binary outside the base mounts gets its toolchain prefix
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		root := t.TempDir()
		bin := filepath.Join(root, "tc", "bin")
		if err := os.MkdirAll(bin, 0o750); err != nil {
			t.Fatal(err)
		}
		writeExec(t, filepath.Join(bin, "srv"))
		plan = Explain(p, Spec{Command: []string{filepath.Join(bin, "srv")}})
		want, _ := filepath.EvalSymlinks(filepath.Join(root, "tc"))
		if plan.Toolchain != want {
			t.Fatalf("toolchain = %q, want %q (%+v)", plan.Toolchain, want, plan.Notes)
		}
	}

	// an under: rule wider than the mounts is reported as a note
	p.Tools.Rules = map[string]policy.Rule{"write_file": {Decision: policy.Allow, Args: map[string]policy.ArgConstraint{"path": {Under: []string{"/srv/ro"}}}}}
	plan = Explain(p, Spec{})
	found := false
	for _, n := range plan.Notes {
		found = found || strings.HasPrefix(n, "tools.rules[write_file].args.path: /srv/ro is read-only inside the jail")
	}
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !found {
		t.Fatalf("lint note missing: %v", plan.Notes)
	}

	p.Network.Mode = policy.NetNone
	p.Sandbox.Disabled = true
	plan = Explain(p, Spec{})
	if plan.Kind != "disabled" || plan.Hard || len(plan.Allow) != 0 || len(plan.Notes) == 0 {
		t.Fatalf("disabled plan: %+v", plan)
	}

	p.Server.URL = "https://mcp.example.com/mcp"
	plan = Explain(p, Spec{})
	if plan.Kind != "remote" || plan.ReadOnly != nil || plan.Env != nil {
		t.Fatalf("remote plan: %+v", plan)
	}
}
