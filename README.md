# mcp-jail

**Run any MCP server in a jail.** Egress allowlist, filesystem scope, per-tool policy, rug-pull lock, audit log, and a local dashboard to watch and approve what your servers do.

[![CI](https://github.com/ltchurik/mcp-jail/actions/workflows/ci.yml/badge.svg)](https://github.com/ltchurik/mcp-jail/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ltchurik/mcp-jail?display_name=tag&color=2f5fd0)](https://github.com/ltchurik/mcp-jail/releases/latest)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8)](go.mod)
[![License](https://img.shields.io/github/license/ltchurik/mcp-jail?color=1f8a4c)](LICENSE)

Static scanners tell you a server *looks* suspicious. `mcp-jail` makes sure it *can't do* anything your policy doesn't allow: at runtime, for any server, in any language, without touching its code.

```
Claude / Cursor / Claude Code ──stdio──▶ mcp-jail ──stdio──▶ MCP server (in a jail)
                                           │
                                   policy · lock · audit
                                           │
                                      mcp-jail ui
```

<p align="center">
  <img src="docs/dashboard-overview.jpg" alt="mcp-jail dashboard: a pending approval for github create_issue, server cards with lock state and a rug-pull waiting for approval, a 24-hour report with decisions over time, calls per tool, hosts reached or blocked and the reasons things were refused" width="100%">
  <br>
  <sub><code>mcp-jail ui</code>: approve a headless call, catch a rug-pull, see what every server did in the last 24 hours.</sub>
</p>

## Contents

- [Why](#why)
- [Install](#install)
- [Quick start](#quick-start)
- [Dashboard](#dashboard)
- [Policy](#policy)
- [What each layer does](#what-each-layer-does)
- [Hard egress allowlist](#hard-egress-allowlist)
- [Headless approvals](#headless-approvals)
- [Rug-pull lock](#rug-pull-lock)
- [Servers started with npx / uvx](#servers-started-with-npx--uvx)
- [Audit log](#audit-log)
- [Platform support](#platform-support)
- [Use cases](#use-cases)
- [Development](#development)
- [Roadmap](#roadmap)

## Why

An MCP server is arbitrary code you let an AI agent drive. Today it is installed with `npx -y` and gets your whole home directory, your whole network and every tool it feels like advertising. Three things go wrong:

- **Tool poisoning.** A tool description quietly tells the model to read `~/.ssh/id_rsa` first.
- **Rug pull.** The server is clean on day one and changes its tool descriptions after you trusted it.
- **Exfiltration.** A "weather" server posts your files to a domain you never heard of.

Scanners pattern-match descriptions and produce [mostly false positives](https://appsecsanta.com/research/mcp-server-security-audit-2026). `mcp-jail` takes the infrastructure approach instead: namespaces, bind-mounts, an egress allowlist and a hash lock. Whatever the verdict on a server, the blast radius is what the policy says.

| | |
|---|---|
| **Hard boundaries** | Linux namespaces via bubblewrap, `sandbox-exec` on macOS, a kernel-enforced egress allowlist. Not an `HTTP_PROXY` the server may ignore. |
| **Per-tool policy** | `allow` / `deny` / `ask` per tool with glob rules, plus constraints on arguments: a path must stay under a directory, a URL host must be on the allowlist. |
| **Rug-pull lock** | Tools, prompts, resources and templates are hashed on first run. A change is refused until you look at the diff and approve it. |
| **Audit and dashboard** | Every decision is a JSONL line. `mcp-jail ui` shows servers, pending approvals, a report for any range and the live event stream. |
| **Zero friction** | One binary, no dependencies beyond bubblewrap on Linux. `mcp-jail wrap` rewrites your client config in one go. |

## Install

```sh
go install github.com/ltchurik/mcp-jail/cmd/mcp-jail@latest
```

Or download a static binary for Linux or macOS (amd64, arm64) from [Releases](https://github.com/ltchurik/mcp-jail/releases); `checksums.txt` is attached. Every archive carries a build provenance attestation, so you can check that it was built by the release workflow from this repository before running it:

```sh
gh attestation verify mcp-jail_<version>_linux_amd64.tar.gz --repo ltchurik/mcp-jail
```

Linux sandboxing needs bubblewrap:

```sh
sudo apt install bubblewrap      # Debian / Ubuntu
sudo dnf install bubblewrap      # Fedora
```

## Quick start

**1. Write a policy.** `init` writes a commented starter you can edit:

```sh
mcp-jail init --policy fs.yml
$EDITOR fs.yml
```

**2. Wrap the server in your client config.** Claude Desktop, Cursor and Claude Code all take the same shape:

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

The client talks to `mcp-jail`; the server never sees your real machine.

**Or let `mcp-jail` rewrite an existing config:**

```sh
mcp-jail wrap ~/Library/Application\ Support/Claude/claude_desktop_config.json   # Claude Desktop
mcp-jail wrap ~/.cursor/mcp.json                                                  # Cursor
mcp-jail wrap .mcp.json                                                           # Claude Code (project)
```

Every stdio server in `mcpServers` is rerouted through `mcp-jail run` and gets a starter policy in `~/.config/mcp-jail/policies/<name>.yml`: network `none`, the directories named on the command line writable, npx/uvx caches, the server's `env` keys passed through, `ask` for unknown tools. Remote (`url`) servers get a policy with `server.url` and their credential headers moved to the entry's `env` (see [Remote servers](#remote-servers-streamable-http)). The original file is kept as `.bak`; legacy SSE servers and servers already wrapped are left alone, and existing policies are never overwritten without `--force`. `--dry-run` prints the result instead of writing it. Review the policies, then restart the client.

**3. Watch it.**

```sh
mcp-jail ui --open
```

## Dashboard

```sh
mcp-jail ps                     # running jails: name, pid, uptime, sandbox, network, command (secrets in it shown as ***)
mcp-jail ui                     # prints http://127.0.0.1:PORT/?token=…  (--open launches the browser)
mcp-jail ui --audit old.jsonl   # also show an audit log from somewhere else
mcp-jail report --since 7d      # the same aggregation as text; --json, --csv, --server NAME
```

`mcp-jail ui` is a local page over everything the other commands know.

**Overview.** A card per server that ever ran through `mcp-jail run`, running or not: sandbox, network mode, tools default, lock sections, the last 24 hours of decisions, a **Stop** button on a running jail (confirmed in place; the jail sends its server SIGTERM and exits, with a `stop` event in the audit log), and a **Pending change** box when a rug-pull was caught, with an **Approve** button that does what `mcp-jail approve` does. Below it the **report** for the chosen range: decisions over time, calls per tool with how many were refused, hosts reached or blocked, the reasons things were refused, lock events, with CSV and JSON export.

**Waiting for your decision.** Headless `ask` calls (Claude Desktop and Cursor have no terminal) appear at the top of the page with their arguments and a countdown. **Allow** sends the call on, **Deny** refuses it, the deadline refuses it. **Always allow** / **Always deny** first write the rule into the policy file, then answer. See [Headless approvals](#headless-approvals).

**Events.** The audit logs, live: filter by server, kind, decision, time range or text, click a row for the full JSON, and watch new lines arrive as they are written. Denies, blocks and lock events pop up as notifications on either tab. A `tool_call` row offers **Always allow** / **Always deny** for that tool: a confirmed click writes `tools.rules.<tool>: allow|deny` into that server's policy file, keeping its comments and order, and a running jail takes the new rule into use at once (a `reload` event marks the moment). Only the `tools` and `ask` sections can change under a running server; sandbox, network and lock settings need a restart.

<p align="center">
  <img src="docs/dashboard-events.jpg" alt="mcp-jail dashboard, Events tab: the audit log as a live table with filters, showing allowed and denied tool calls, a blocked lock change and the sandbox each server started with" width="100%">
</p>

Built to be boring: plain HTML, CSS and JavaScript embedded in the binary, no framework, nothing fetched from the internet. It binds to the loopback interface only and refuses any other `--listen` address. Every request needs the random token from the printed URL (exchanged for an `HttpOnly; SameSite=Strict` cookie on first visit); foreign `Host` headers and cross-site fetches are rejected, and a write additionally needs a custom request header that only a same-origin script can set. The dashboard changes nothing about enforcement: the proxy decides, the page watches and relays your clicks.

Running jails register themselves in `~/.config/mcp-jail/run/`, next to the locks, and talk to the page over a user-only Unix socket; entries whose process is gone are pruned automatically.

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
    write_file:               # a rule may also constrain arguments
      decision: allow
      args:
        path: { under: [~/projects] }        # absolute, inside one of these
    fetch:
      decision: allow
      args:
        url: { host: [network.allow] }       # host in network.allow (or list patterns)

ask:                        # how `ask` is answered without a terminal
  timeout: 60s              # how long to wait for the dashboard (mcp-jail ui)
  webhook:
    url: https://approvals.example.internal/mcp-jail
    timeout: 60s            # no answer in time = deny
    headers: { Authorization: "Bearer ${APPROVER_TOKEN}" }

lock:
  enabled: true             # refuse to run if tool definitions change

audit:
  path: ~/.local/state/mcp-jail/filesystem.jsonl
  args: false               # log tool arguments too (may contain secrets)

sandbox:
  disabled: false           # true = policy/lock/audit only, no namespaces
  env: [PATH, HOME, LANG]   # env vars passed into the jail
```

Exact tool names beat globs; among globs the longest pattern wins. Globs use `filepath.Match` syntax. Argument constraints apply to the rule that matched; string and list-of-string arguments are checked element by element.

## What each layer does

| Layer | Mechanism | Hard or cooperative |
|---|---|---|
| `network.mode: none` | Separate network namespace, no interfaces | **Hard** |
| `network.mode: allowlist` (Linux) | Empty network namespace + in-jail shim: fake DNS, transparent :80/:443 (Host/SNI) and an `HTTP_PROXY` on :3128, all relayed through a Unix socket to a host-side filter. Nothing else leaves the jail, see [Hard egress allowlist](#hard-egress-allowlist) | **Hard** |
| `network.mode: allowlist` (macOS) | `HTTP_PROXY`/`HTTPS_PROXY` → local filtering proxy, and the `sandbox-exec` profile lets the server open **only** that loopback port | **Hard** for the network (HTTP(S) via proxy only); a server that ignores `HTTP_PROXY` has no network at all |
| `network.mode: allowlist` (`sandbox.disabled`) | the same proxy, nothing stops a server from ignoring it | Cooperative |
| `filesystem.*` | Linux: bubblewrap bind-mounts; nothing else from `$HOME` is visible. macOS: `sandbox-exec` denies `/Users`, the per-user temp dir and all writes, then re-allows the listed paths | **Hard** |
| `tools.rules` | `tools/call` is answered with a JSON-RPC error before it reaches the server | **Hard** |
| `tools.rules.*.args` | Argument constraints: `under` (absolute path inside a directory, `..` cleaned first) and `host` (URL or `host:port` matching patterns or `network.allow`). A constrained argument that is missing (unless `optional: true`), of the wrong type or out of bounds ⇒ denied | **Hard** (on the request; the sandbox is the backstop for what the server does on its own) |
| `tools: ask` | Prompt on `/dev/tty`; without a tty, wait up to `ask.timeout` for an open dashboard and/or POST to `ask.webhook` and wait for `{"decision":"allow"}`; nobody to ask, timeout, error or any other answer ⇒ denied | **Hard** |
| `lock` | SHA-256 of canonical `tools/list`, `prompts/list`, `resources/list` and `resources/templates/list`, each locked separately; a mismatch ⇒ that list and its uses (`tools/call`, `prompts/get`, `resources/read`) fail until approved. A use sent before (or racing) its list is held until the list is verified, or refused | **Hard** |
| `server.url` | Remote server over Streamable HTTP: guarded dialer (special address ranges refused), `https` outside localhost, no redirects, strict parsing of every answer; policy, lock, `ask` and audit as above | **Hard** (there is no server process to sandbox) |
| `audit` | JSONL: every call, decision, duration, blocked host | — |

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
- What an allowed name resolves to is checked as well (relay and `HTTP_PROXY` filter alike): a loopback, private, link-local or otherwise non-public address is refused unless that literal address is itself in `network.allow`. Whoever controls the DNS of `api.example.com` cannot point the jail at `127.0.0.1` or `10.0.0.0/8` to reach the host's own services.
- Servers that honour `HTTP_PROXY` use the proxy on :3128 (set automatically, including `NODE_USE_ENV_PROXY=1` for Node's `fetch`). Servers that don't still work for plain HTTP and HTTPS through the transparent listeners.
- Anything else (raw TCP to an IP, UDP, a port other than 80/443 without the proxy, a host that isn't listed) fails with `ENETUNREACH`, `NXDOMAIN` or a 403.
- Needs unprivileged user namespaces (same requirement as bubblewrap itself) and bubblewrap ≥ 0.5 for `--cap-add`. No `CAP_NET_ADMIN`, no pasta/slirp4netns, no iptables. If the jail cannot be set up, mcp-jail refuses to start rather than falling back to the cooperative proxy.

Inside the jail the shim briefly runs as the user namespace's root so it can bind the privileged ports; the server itself is started in a nested user namespace under your normal uid/gid with no capabilities.

## Headless approvals

Claude Desktop and Cursor start servers without a terminal, so `ask` would always deny. Two things can answer instead:

- **The dashboard.** While `mcp-jail ui` is open in a browser, every headless `ask` shows up at the top of the page with the arguments and **Allow** / **Deny** buttons, and the jail waits up to `ask.timeout` (default 60s) for the click. No dashboard open ⇒ the call is denied at once, as before; dashboard open but nobody clicks ⇒ denied at the deadline. The jail and the page talk over a user-only Unix socket next to the lock files.
- **A webhook.** Configure `ask.webhook` and mcp-jail POSTs each pending call:

```json
{"server":"filesystem","tool":"write_file","arguments":{"path":"/home/me/projects/a.txt"},
 "ts":"2026-11-02T10:00:00Z","text":"[mcp-jail] filesystem wants to call write_file {\"path\":...}"}
```

The endpoint has `timeout` to answer `{"decision":"allow"}` (optionally `{"decision":"deny","reason":"..."}`). Anything else (a timeout, a non-200 status, a redirect, a body that is not a decision, a connection error) denies the call, and the reason lands in the audit log and in the error the client sees. Because the payload carries `text`, a Slack or Mattermost incoming webhook URL works as a notification channel out of the box; it answers `ok`, which is not a decision, so on its own that is a deny. With the dashboard open as well, a non-decision from the webhook leaves the call waiting for the page until the deadline: Slack pings you, you click Allow. An explicit webhook `deny` is final. A terminal, when there is one, still takes precedence over both. The URL must be `https`, except for a listener on localhost; the payload carries the full tool arguments, so point it only at an endpoint you trust with them.

## Rug-pull lock

First run records each list the client asks for. Tools, prompts, resources and resource templates are locked independently, so a server that only has tools never trips over the others:

```
[mcp-jail] lock: recorded 11 tools (5dc4bc0b04d6)
[mcp-jail] lock: recorded 2 prompts (9f1c0a7e3b44)
```

If the server later changes any name, description, schema, prompt text or resource URI:

```
[mcp-jail] RUG-PULL: tools changed: added=[] removed=[] changed=[read_file]
[mcp-jail]           inspect with `mcp-jail diff filesystem`, accept with `mcp-jail approve filesystem`
```

The client sees an error instead of that list, and every use of it (`tools/call`, `prompts/get`, `resources/read`) is refused until you look. The other lists keep working if they are unchanged.

A `tools/call` or `prompts/get` for a name that the verified list does not contain is refused too, so a server cannot act on a tool the client never saw through the lock. A list the server pages (`nextCursor`) is forwarded page by page and verified as a whole once the last page is in; calls between pages are refused rather than parked.

```sh
mcp-jail diff filesystem      # what changed, per section
mcp-jail approve filesystem   # accept the new set (or click Approve in the dashboard)
mcp-jail locks                # overview of all locks
mcp-jail reset filesystem     # forget everything
```

Locks live in `$XDG_CONFIG_HOME/mcp-jail/locks/` (override with `MCP_JAIL_HOME`).

## Remote servers (Streamable HTTP)

A server you reach over HTTP instead of starting locally gets the same policy, lock, `ask` and audit; only the sandbox has nothing to do, because the jail itself is the only thing talking to the server. Put the URL in the policy instead of a command:

```yaml
name: linear
server:
  url: https://mcp.linear.app/mcp
  headers: { Authorization: "Bearer ${LINEAR_TOKEN}" }   # ${VAR} comes from the environment
tools: { default: ask, rules: { "list_*": allow, "get_*": allow } }
lock: { enabled: true }
```

```json
{ "mcpServers": { "linear": { "command": "mcp-jail", "args": ["run", "--policy", "/home/me/mcp/linear.yml"],
                              "env": { "LINEAR_TOKEN": "lin_api_…" } } } }
```

The client keeps talking stdio to `mcp-jail`; the jail speaks [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) to the server: one `POST` per message, JSON or SSE answers, the `Mcp-Session-Id` and `MCP-Protocol-Version` headers, a standing `GET` stream for server-initiated messages, `DELETE` on exit. What is enforced on top:

- `https` only, except for `localhost`; redirects are refused, so the headers never travel to another host; names that resolve into loopback, link-local or private ranges are refused unless you typed that address
- every server message goes through the same strict JSON-RPC parser, lock and policy as a local server's; a `tools/call` the policy denies never leaves your machine
- an HTTP error, an unusable body or an expired session is answered to the client as JSON-RPC error `-32005` and audited; the jail never re-initializes a session on its own
- `mcp-jail wrap` converts `{"type": "http", "url": …, "headers": …}` entries: headers that look like credentials move to the entry's `env` and the policy references them as `${NAME}`, so the token stays where the client already kept it

Not covered yet: OAuth flows (use a token), the legacy SSE transport, and resuming a `POST` stream that broke mid-answer (the request gets `-32005`).

## Servers started with npx / uvx

The jail only shows the paths in `filesystem.*`, plus the toolchain the server binary lives in (resolved through `PATH` and symlinks: `/usr/local`, `~/.nvm/versions/node/vX`, a venv). Package *caches* are not included by default: `npx -y` writes to `~/.npm/_npx` and `uvx` to `~/.cache/uv`, so add them:

```yaml
filesystem:
  read_write: [~/.npm/_npx]      # npx
  read_only:  [~/.npm/_cacache]  # npx, optional
  # read_write: [~/.cache/uv]    # uvx
```

Or install the server once (`npm i -g`) and point `command` at the binary; then nothing beyond the toolchain is needed.

## Audit log

One JSON object per line, written by the proxy on the host, never by the server:

```json
{"ts":"2026-11-02T00:31:48Z","server":"filesystem","kind":"tool_call","tool":"read_file","decision":"allow"}
{"ts":"2026-11-02T00:31:48Z","server":"filesystem","kind":"tool_call","tool":"delete_file","decision":"deny","reason":"policy"}
{"ts":"2026-11-02T00:31:49Z","server":"filesystem","kind":"net","host":"pastebin.com","decision":"blocked"}
{"ts":"2026-11-02T00:31:49Z","server":"filesystem","kind":"lock","decision":"blocked","reason":"changed=[read_file]"}
```

Pipe it into whatever you already use: `jq`, Loki, Vector, a cron job that mails you `decision=="blocked"` lines, or `mcp-jail report --since 7d` for the weekly summary.

## Platform support

| OS | Sandbox | Policy / lock / audit / dashboard |
|---|---|---|
| Linux | bubblewrap (user, PID, IPC, UTS, net namespaces); hard egress allowlist | ✓ |
| macOS | `sandbox-exec` profile generated from the policy: home and per-user temp hidden except listed paths, writes only to `read_write` and a private `TMPDIR`, network none / proxy-only / all | ✓ |
| Windows | not yet | ✓ (WSL recommended) |
| Remote server (`server.url`) | none needed: the jail is the only process talking to the server, over a guarded HTTPS client | ✓ |

`sandbox.disabled: true` runs the server without any of this; policy, lock, audit and the dashboard still apply.

macOS notes: `sandbox-exec` is deprecated by Apple but still ships and works on current releases. The profile is an *allow by default, hide the sensitive trees* design: the server keeps access to system frameworks and its toolchain, but `/Users`, `$HOME`, the per-user temp dir and (with `filesystem.tmp: true`) `/tmp` are invisible unless listed, and nothing outside `filesystem.read_write` is writable. There is no PID or mount isolation and no transparent egress (a server that ignores `HTTP_PROXY` simply has no network in allowlist mode).

## Use cases

Worked scenarios with a complete policy each, in [`use-cases/`](use-cases/README.md):

- [Scope the filesystem server to one project](use-cases/filesystem-server-for-one-project.md)
- [Try an unknown server safely](use-cases/try-an-unknown-server.md)
- [Let a server reach exactly one API](use-cases/api-server-with-an-egress-allowlist.md)
- [Keep a web-fetch tool on a leash](use-cases/fetch-tool-with-host-constraints.md)
- [Catch a rug-pull](use-cases/catch-a-rug-pull.md)
- [Approve dangerous calls from Slack or a web form](use-cases/approvals-without-a-terminal.md)
- [Wrap every server your client already has](use-cases/wrap-an-existing-client-config.md)
- [Watch, report and hand over](use-cases/monitor-report-and-hand-over.md)
- [Jail a remote server over Streamable HTTP](use-cases/remote-server-over-streamable-http.md)

## Development

```sh
make build              # bin/mcp-jail
make lint               # go vet + golangci-lint
make test               # unit tests (-race)
make e2e                # build + scripts/e2e.sh (bubblewrap on Linux, sandbox-exec on macOS)
scripts/e2e-docker.sh   # the Linux e2e, including hard egress, from macOS in a privileged container
```

Try it by hand with the example server:

```sh
make build
cd examples
../bin/mcp-jail run --policy echo-policy.yml -- python3 echo-server.py
```

Paste JSON-RPC lines on stdin: `delete_file` is refused, `read_file` passes, `probe` reports what the server can see, and a second run after editing a description in `echo-server.py` trips the lock.

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilities: [SECURITY.md](SECURITY.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## Roadmap

- [x] Hard egress allowlist on Linux (v0.2)
- [x] macOS sandbox via `sandbox-exec` profiles (v0.2)
- [x] `ask` via webhook for headless use (v0.2)
- [x] Prompts and resources in the rug-pull lock (v0.2)
- [x] Per-tool argument constraints (v0.2)
- [x] `mcp-jail wrap`: rewrite an existing client config in place (v0.2)
- [x] Dashboard: monitor, reports, lock approval and `ask` answers (v0.3)
- [x] Promote a rule to allow/deny and stop a jail from the dashboard (v0.4)
- [x] Streamable HTTP transport: jail remote servers the same way (v0.5)
- [ ] Windows sandbox

## Non-goals

- Deciding whether a server is *trustworthy*. Use a scanner for that; `mcp-jail` limits the blast radius whatever the verdict.
- Protecting against a hostile MCP *client*.

## License

Apache-2.0
