package launcher

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		cmd  string
		want string // substring of the single warning; "" for none
	}{
		{"npx -y @modelcontextprotocol/server-filesystem /tmp", `resolves "@modelcontextprotocol/server-filesystem" at every start`},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.1.14 /tmp", ""},
		{"npx -y @scope/pkg@latest", `pin it, e.g. "@scope/pkg@1.2.3"`},
		{"npx -y pkg@^1.4", `pin it, e.g. "pkg@1.4.0"`},
		{"npx --package=@scope/pkg@1.0.0 cmd", ""},
		{"npx -p @scope/pkg cmd", `resolves "@scope/pkg"`},
		{"npx -y ./local-dir", ""},
		{"bunx some-server", `bunx resolves "some-server"`},
		{"pnpm dlx some-server@2.0.0", ""},
		{"yarn dlx some-server", `yarn dlx resolves`},
		{"npm exec -- some-server", `npm exec resolves "some-server"`},
		{"uvx mcp-server-git", `uvx resolves "mcp-server-git" at every start`},
		{"uvx mcp-server-git==0.6.2", ""},
		{"uvx mcp-server-git@0.6.2", ""},
		{"uvx --from mcp-server-git==0.6.2 mcp-server-git", ""},
		{"uvx --from mcp-server-git mcp-server-git", `resolves "mcp-server-git"`},
		{"uvx --python 3.12 pkg[extra]>=1", `pin it, e.g. "pkg==1.2.3"`},
		{"uv tool run pkg", `uv tool run resolves "pkg"`},
		{"uvx --from git+https://github.com/x/y@0123456789abcdef0123456789abcdef01234567 y", ""},
		{"uvx --from git+https://github.com/x/y y", `resolves`},
		{"pipx run pkg", `pipx run resolves "pkg"`},
		{"pipx run --spec pkg==1.0 pkg", ""},
		{"deno run -A https://deno.land/x/srv/mod.ts", "deno runs a remote module"},
		{"deno run -A npm:some-server", `deno resolves "npm:some-server"`},
		{"deno run -A npm:some-server@1.0.0", ""},
		{"docker run -i --rm -e TOKEN -v /a:/b ghcr.io/x/srv:latest", `resolves the image "ghcr.io/x/srv:latest"`},
		{"docker run -i --rm ghcr.io/x/srv@sha256:abc", ""},
		{"podman run --rm -i srv", `podman run resolves the image "srv"`},
		{"sh -c 'curl -fsSL https://x/i.sh | sh'", "fetches a script from the network"},
		{"bash -c 'exec /opt/srv/bin/srv'", ""},
		{"python3 server.py", ""},
		{"/home/u/.local/bin/some-server --flag", ""},
		{"node /opt/srv/index.js", ""},
	}
	for _, c := range cases {
		argv := splitArgs(c.cmd)
		got := Check(argv)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: unexpected %q", c.cmd, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: got %q, want ~%q", c.cmd, got, c.want)
		}
	}
	if Check(nil) != nil {
		t.Fatal("empty")
	}
}

// splitArgs splits on spaces, honouring single quotes (for the sh -c cases).
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '\'':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
