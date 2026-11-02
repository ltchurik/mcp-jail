# mcp-jail

**Run any MCP server in a jail: egress allowlist, filesystem scope, per-tool policy, rug-pull lock, audit log.**

Static scanners tell you a server *looks* suspicious. `mcp-jail` makes sure it *can't do* anything your policy doesn't allow — at runtime, for any server, in any language, without touching its code.

```
Claude / Cursor / Claude Code ──stdio──▶ mcp-jail ──stdio──▶ MCP server (in a jail)
                                           │
                                   policy · lock · audit
```

## Why

An MCP server is arbitrary code you let an AI agent drive. Today it is installed with `npx -y` and gets your whole home directory, your whole network and every tool it feels like advertising. Three things go wrong:

- **Tool poisoning** — a tool description quietly tells the model to read `~/.ssh/id_rsa` first.
- **Rug pull** — the server is clean on day one and changes its tool descriptions after you trusted it.
- **Exfiltration** — a "weather" server posts your files to a domain you never heard of.

Scanners pattern-match descriptions and produce [mostly false positives](https://appsecsanta.com/research/mcp-server-security-audit-2026). `mcp-jail` takes the infrastructure approach instead: namespaces, bind-mounts, an egress allowlist and a hash lock.

## Install

```sh
go install github.com/ltchurik/mcp-jail/cmd/mcp-jail@latest
# Linux sandboxing needs bubblewrap:
sudo apt install bubblewrap      # Debian/Ubuntu
sudo dnf install bubblewrap      # Fedora
```

Or grab a static binary from [Releases](https://github.com/ltchurik/mcp-jail/releases).

## Quick start

```sh
mcp-jail init --policy fs.yml     # writes a commented starter policy
$EDITOR fs.yml
```

Then wrap the server in your client config. Claude Desktop / Cursor / Claude Code all take the same shape:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-jail",
      "args": ["run", "--policy", "/home/me/mcp/fs.yml", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/projects"]
    }
  }
}
```

That's it. The client talks to `mcp-jail`; the server never sees your real machine.

## Policy

```yaml
name: filesystem            # used for lock + audit file names

network:
  mode: none                # none | allowlist | all
  allow:                    # allowlist mode only
    - api.github.com
    - "*.githubusercontent.com"

filesystem:
  read_only:  [~/projects]
  read_write: [~/projects/scratch]
  tmp: true                 # private /tmp

tools:
  default: ask              # allow | deny | ask
  rules:
    "read_*":   allow
    "list_*":   allow
    "delete_*": deny

lock:
  enabled: true             # refuse to run if tool definitions change

audit:
  path: ~/.local/state/mcp-jail/filesystem.jsonl
  args: false               # log tool arguments too (may contain secrets)

sandbox:
  disabled: false           # true = policy/lock/audit only, no namespaces
  env: [PATH, HOME, LANG]   # env vars passed into the jail
```

### What each layer does

| Layer | Mechanism | Hard or cooperative |
|---|---|---|
| `network.mode: none` | Separate network namespace, no interfaces | **Hard** |
| `network.mode: allowlist` (Linux) | Empty network namespace + in-jail shim: fake DNS, transparent :80/:443 (Host/SNI) and an `HTTP_PROXY` on :3128, all relayed through a Unix socket to a host-side filter. Nothing else leaves the jail — see [Hard egress allowlist](#hard-egress-allowlist) | **Hard** |
| `network.mode: allowlist` (macOS, `sandbox.disabled`) | `HTTP_PROXY`/`HTTPS_PROXY` → local filtering proxy; non-listed hosts get 403 | Cooperative (honoured by every mainstream HTTP client; a server that ignores the proxy variables is not stopped) |
| `filesystem.*` | bubblewrap bind-mounts; nothing else from `$HOME` is visible | **Hard** |
| `tools.rules` | `tools/call` is answered with a JSON-RPC error before it reaches the server | **Hard** |
| `tools: ask` | Prompt on `/dev/tty`; no tty ⇒ denied | **Hard** |
| `lock` | SHA-256 of canonical `tools/list`; mismatch ⇒ `tools/list` and all `tools/call` fail until approved. A `tools/call` sent before (or racing) `tools/list` is held until the list is verified, or refused | **Hard** |
| `audit` | JSONL: every call, decision, duration, blocked host | — |

Exact tool names beat globs; among globs the longest pattern wins. Globs use `filepath.Match` syntax.

## Hard egress allowlist

On Linux with the sandbox on, `network.mode: allowlist` is enforced by the kernel, not by the server's good manners:

```
jail (netns: lo only)                          host (mcp-jail process)
┌───────────────────────────────────────┐      ┌──────────────────────────┐
│ server ──DNS──▶ shim :53  (allow→127.0.0.1, else NXDOMAIN)              │
│        ──HTTP─▶ shim :80  (Host)   ──┐ │      │                          │
│        ──TLS──▶ shim :443 (SNI)    ──┼─┼─unix─┼─▶ relay: network.allow? ─▶ internet
│        ──PROXY▶ shim :3128 (CONNECT)─┘ │      │         audit log       │
└───────────────────────────────────────┘      └──────────────────────────┘
```

- The jail is created with `--unshare-net`, so there is no route anywhere. The only way out is the Unix socket the shim talks to.
- The shim is `mcp-jail` itself, re-executed inside the jail. It resolves every allowed name to `127.0.0.1` and sniffs the real destination from the `Host` header or the TLS SNI; the host-side relay re-checks it against `network.allow` and is the one that dials. Both decisions are audited (`kind: net`, `kind: dns`).
- Servers that honour `HTTP_PROXY` use the proxy on :3128 (set automatically, including `NODE_USE_ENV_PROXY=1` for Node's `fetch`). Servers that don't still work for plain HTTP and HTTPS through the transparent listeners.
- Anything else — raw TCP to an IP, UDP, a port other than 80/443 without the proxy, a host that isn't listed — fails with `ENETUNREACH`, `NXDOMAIN` or a 403.
- Needs unprivileged user namespaces (same requirement as bubblewrap itself) and bubblewrap ≥ 0.5 for `--cap-add`. No `CAP_NET_ADMIN`, no pasta/slirp4netns, no iptables. If the jail cannot be set up, mcp-jail refuses to start rather than falling back to the cooperative proxy.

Inside the jail the shim briefly runs as the user namespace's root so it can bind the privileged ports; the server itself is started in a nested user namespace under your normal uid/gid with no capabilities.

## Rug-pull lock

First run records the tool set:

```
[mcp-jail] lock: recorded 11 tools (5dc4bc0b04d6)
```

If the server later changes any tool name, description or schema:

```
[mcp-jail] RUG-PULL: tool definitions changed: added=[] removed=[] changed=[read_file]
[mcp-jail]           inspect with `mcp-jail diff filesystem`, accept with `mcp-jail approve filesystem`
```

The client sees an error instead of a tool list, and every `tools/call` is refused until you look:

```sh
mcp-jail diff filesystem      # which tools changed
mcp-jail approve filesystem   # accept the new set
mcp-jail locks                # overview of all locks
mcp-jail reset filesystem     # forget everything
```

Locks live in `$XDG_CONFIG_HOME/mcp-jail/locks/` (override with `MCP_JAIL_HOME`).

## Servers started with `npx` / `uvx`

The jail only shows the paths in `filesystem.*`, plus the toolchain the server binary lives in (resolved through `PATH` and symlinks: `/usr/local`, `~/.nvm/versions/node/vX`, a venv). Package *caches* are not included by default — `npx -y` writes to `~/.npm/_npx` and `uvx` to `~/.cache/uv`, so add them:

```yaml
filesystem:
  read_write: [~/.npm/_npx]      # npx
  read_only:  [~/.npm/_cacache]  # npx, optional
  # read_write: [~/.cache/uv]    # uvx
```

Or install the server once (`npm i -g`) and point `command` at the binary; then nothing beyond the toolchain is needed.

## Audit log

One JSON object per line:

```json
{"ts":"2026-11-02T00:31:48Z","server":"filesystem","kind":"tool_call","tool":"read_file","decision":"allow"}
{"ts":"2026-11-02T00:31:48Z","server":"filesystem","kind":"tool_call","tool":"delete_file","decision":"deny","reason":"policy"}
{"ts":"2026-11-02T00:31:49Z","server":"filesystem","kind":"net","host":"pastebin.com","decision":"blocked"}
{"ts":"2026-11-02T00:31:49Z","server":"filesystem","kind":"lock","decision":"blocked","reason":"changed=[read_file]"}
```

Pipe it into whatever you already use: `jq`, Loki, Vector, a cron job that mails you `decision=="blocked"` lines.

## Platform support

| OS | Sandbox | Policy / lock / audit |
|---|---|---|
| Linux | bubblewrap (user, PID, IPC, UTS, net namespaces) | ✓ |
| macOS | not yet — runs unsandboxed with a warning | ✓ |
| Windows | not yet | ✓ (WSL recommended) |

`sandbox.disabled: true` gives the same behaviour on Linux if you don't want bubblewrap.

## Try it

```sh
make build
cd examples
../bin/mcp-jail run --policy echo-policy.yml -- python3 echo-server.py
```

Paste JSON-RPC lines on stdin; `delete_file` is refused, `read_file` passes, `probe` reports what the server can see, and the second run after editing a description in `echo-server.py` trips the lock. `scripts/e2e.sh` runs the whole scenario — including the bubblewrap jail on Linux — and is what CI runs.

## Development

```sh
make lint   # go vet + golangci-lint
make test   # unit tests (-race)
make e2e    # build + scripts/e2e.sh
scripts/e2e-docker.sh   # the Linux e2e (bubblewrap + hard egress) from macOS, in a privileged container
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilities: [SECURITY.md](SECURITY.md).

## Roadmap

- [x] Hard egress allowlist on Linux (v0.2)
- [ ] macOS sandbox via `sandbox-exec` profiles
- [ ] `ask` via webhook/approval inbox for headless use
- [ ] Streamable HTTP transport (wrap remote servers the same way)
- [ ] Per-tool argument constraints (`path` must be under X, `url` host must be in allowlist)
- [ ] `mcp-jail wrap` — rewrite an existing client config in place

## Non-goals

- Deciding whether a server is *trustworthy*. Use a scanner for that; `mcp-jail` limits the blast radius whatever the verdict.
- Protecting against a hostile MCP *client*.

## License

Apache-2.0
