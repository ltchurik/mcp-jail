# Scope the filesystem server to one project

**Goal.** Claude Desktop (or Cursor, or Claude Code) gets the reference
filesystem server for `~/projects/webshop`. It can read and write files there,
it cannot see the rest of `$HOME`, it cannot delete anything, and it has no
network at all.

## Policy

`~/mcp/webshop-fs.yml`:

```yaml
name: webshop-fs

network:
  mode: none                       # a filesystem server has no business online

filesystem:
  read_write: [~/projects/webshop]
  read_only:  [~/.npm/_cacache]    # npx needs its cache; see README "Servers started with npx"
  tmp: true

tools:
  default: ask                     # anything not listed below asks first
  rules:
    "read_*":   allow
    "list_*":   allow
    "search_*": allow
    "get_*":    allow
    "delete_*": deny
    "move_*":   deny
    write_file:
      decision: allow
      args:
        path: { under: [~/projects/webshop] }   # even if the server is told otherwise
    edit_file:
      decision: allow
      args:
        path: { under: [~/projects/webshop] }
    create_directory:
      decision: allow
      args:
        path: { under: [~/projects/webshop] }

lock:
  enabled: true

audit:
  path: ~/.local/state/mcp-jail/webshop-fs.jsonl

sandbox:
  env: [PATH, HOME, LANG]
```

## Client config

```json
{
  "mcpServers": {
    "webshop-fs": {
      "command": "mcp-jail",
      "args": ["run", "--policy", "/home/me/mcp/webshop-fs.yml", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/projects/webshop"]
    }
  }
}
```

Restart the client. The first run records the server's tool list in the lock.

## What you get

- The server process runs in a namespace (Linux) or `sandbox-exec` profile
  (macOS) where `~/projects/webshop` is the only writable place and the rest
  of your home directory does not exist. `ls ~` from inside the jail shows
  nothing but what you listed.
- `delete_file` and `move_file` never reach the server; the client sees a
  JSON-RPC error that names the policy.
- `write_file` with `path: /home/me/.ssh/authorized_keys` is refused by the
  argument constraint *before* the server sees it, even though the server
  would also have been unable to reach that path.
- Tools that are not in the list (`read_multiple_files`? `directory_tree`?)
  prompt on your terminal when there is one. Claude Desktop has none, so they
  are denied; promote them to `allow` once you know them, or set up
  [approvals without a terminal](approvals-without-a-terminal.md).

Audit log after a session:

```json
{"ts":"2026-11-02T09:10:07Z","server":"webshop-fs","kind":"start","reason":"bwrap: user/pid/ipc/uts ns, net ns (no network)"}
{"ts":"2026-11-02T09:10:07Z","server":"webshop-fs","kind":"lock","decision":"created","reason":"tools 20edfb1797af"}
{"ts":"2026-11-02T09:10:12Z","server":"webshop-fs","kind":"tool_call","tool":"read_file","decision":"allow"}
{"ts":"2026-11-02T09:10:30Z","server":"webshop-fs","kind":"tool_call","tool":"write_file","decision":"deny","reason":"args: argument \"path\": path \"/home/me/.ssh/authorized_keys\" is outside [/home/me/projects/webshop]"}
{"ts":"2026-11-02T09:11:02Z","server":"webshop-fs","kind":"tool_call","tool":"delete_file","decision":"deny","reason":"policy"}
```

## Variations

- **Read-only review.** Put the project in `read_only` instead and set
  `default: deny` with only `read_*`/`list_*`/`search_*` allowed. The server
  cannot write even if a rule slipped through: the mount is read-only.
- **Two projects.** List both in `read_write` and in every `under:`.
- **Windows.** No native sandbox yet; the policy, the argument constraints,
  the lock and the audit still apply, the bind-mount does not. Keep the
  `under:` constraints, they are what protects you there, or use
  `sandbox.backend: docker` (the project then lives at `/mnt/c/...` inside
  the container and the `under:` paths must say so).
