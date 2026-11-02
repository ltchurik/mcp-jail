# Changelog

## Unreleased

### Added

- The dashboard can **promote a rule**: *Always allow* / *Always deny* on a
  pending ask and on any `tool_call` event write `tools.rules.<tool>` into
  the server's policy file (comments and key order preserved, atomic
  replace, never written if the result would not load) and a running jail
  reloads its `tools` and `ask` sections at once over the control socket
  (`POST /reload`), auditing a `reload` event. `POST
  /api/servers/{name}/rules` with `{"tool","decision"}`; the response says
  whether the rule is live or applies on the next start.
- The dashboard can **stop a jail**: a confirmed *Stop* on a running
  server's card (`POST /api/servers/{name}/stop`) asks the jail over its
  control socket to send its server SIGTERM (SIGKILL after 5s if it stays)
  and exit; the audit log gets a `stop` event with reason `dashboard`. The
  page never signals a pid itself. `mcp-jail run` now also escalates to
  SIGKILL when a server ignores the SIGTERM relayed from Ctrl-C.

### Changed

- README rewritten with dashboard screenshots, a feature table and a table
  of contents.
- Dashboard: paths under the home directory are shown as `~/…` on server
  cards; a long sandbox badge no longer pushes the server name out of view;
  the pending-ask arguments box is taller.
- Release notes no longer list commit authors.

## v0.3.0 — 2026-11-02

The dashboard release: see what your jails do, approve what they ask for,
all from one local page. Policies written for v0.2 keep working; the only
new key is `ask.timeout`.

### Added

- **`mcp-jail ui`**: a local dashboard listing every server that ran through
  `mcp-jail run` (running or not) with its sandbox, network mode, lock
  sections, pending changes and the last 24h of decisions, plus a live,
  filterable audit event view streamed over server-sent events. Loopback
  only, token-protected (random token exchanged for an `HttpOnly;
  SameSite=Strict` cookie), no external assets, a strict CSP, foreign `Host`
  headers and cross-site fetches refused.
- The dashboard can **answer `ask` decisions** for headless clients: a jail
  without a terminal waits up to the new `ask.timeout` (default 60s) while a
  dashboard is open and shows the call at the top of the page with Allow /
  Deny. Each `run` opens a user-only control socket in the registry
  directory; `ask_allow` / `ask_deny` carry the reason `dashboard`. A webhook
  that returns no decision (Slack's `ok`) no longer ends the wait when a
  dashboard is open; an explicit webhook deny does.
- The dashboard can **approve a pending lock change** (`POST
  /api/servers/{name}/approve`, same as `mcp-jail approve`). Writes need the
  token plus a custom `X-Mcp-Jail` header and a same-origin fetch.
- **`mcp-jail report`** and the dashboard's report panel: decisions over
  time, calls per tool (most refused first) with average duration, hosts
  reached or blocked, top refusal reasons and lock events for a time range;
  `--json`, `--csv`, `--server`, `--audit`. The same data is served at
  `/api/report` (`format=json|csv|text`).
- **`mcp-jail ps`**: list running jails. `run` now registers itself in
  `~/.config/mcp-jail/run/` (or `$MCP_JAIL_HOME/run`) for the lifetime of
  the process.
- **`use-cases/`**: eight worked scenarios with complete policies, linked
  from the README.
- Vulnerabilities are reported as GitHub issues with the `security` label
  (or a private advisory for exploit details); the e-mail contact is gone.

### Changed

- A non-zero server exit is propagated after the audit log is closed and the
  registry entry removed (previously `run` exited immediately).

## v0.2.0 — 2026-11-02

Security hardening across every layer; policies written for v0.1 keep working.

### Added

- **Hard egress allowlist on Linux.** `network.mode: allowlist` is enforced by
  the kernel: the jail has an empty network namespace and `mcp-jail`
  re-executes itself inside it as a shim that resolves allowed names to
  loopback, sniffs `Host`/SNI on :80/:443, serves an `HTTP_PROXY` on :3128 and
  relays everything over a Unix socket to the host, which re-checks
  `network.allow`, dials and audits. Servers that ignore `HTTP_PROXY` still
  work for HTTP(S); everything else fails with `ENETUNREACH`/`NXDOMAIN`. No
  `CAP_NET_ADMIN`, pasta or iptables.
- **macOS sandbox** via `sandbox-exec`: `/Users`, `$HOME` and the per-user temp
  dir hidden except for the policy's paths, writes only to `read_write` and a
  private `TMPDIR`, network none / proxy-port-only / all.
- **Prompts, resources and resource templates in the rug-pull lock**, each as
  its own section; `prompts/get` and `resources/read` are gated like
  `tools/call`. Lock files from v0.1 load unchanged.
- **Per-argument constraints** in tool rules: `path: { under: [...] }` and
  `url: { host: [...] }` (patterns or `network.allow`); missing, mistyped or
  out-of-bounds arguments are refused.
- **`mcp-jail wrap <client-config.json>`** reroutes every stdio server in
  `mcpServers` through `mcp-jail run` and writes a starter policy per server.
- **`ask.webhook`**: headless approvals by POSTing the pending call to an HTTP
  endpoint that answers `{"decision":"allow"}` within a timeout; anything else
  denies.
- `scripts/e2e-docker.sh` runs the Linux e2e (bubblewrap, hard egress) from
  macOS in a privileged container.
- Audit log: new `kind` values `dns`, `prompt`, `resource`; `net` events now
  come from the egress relay.

### Changed

- `tools.rules` values may be a mapping (`decision` + `args`) as well as a bare
  decision.
- Lock messages and `mcp-jail diff`/`approve`/`locks` output are per section
  (`tools`, `prompts`, `resources`, `resource_templates`).
- The cooperative `HTTP_PROXY` filter is used only when the sandbox is off (or
  on Windows); `NODE_USE_ENV_PROXY=1` is set so Node's `fetch` honours it.

### Fixed

- `scripts/e2e.sh` runs on macOS (BSD `sed`, bash 3.2).

## v0.1.0

Initial release: bubblewrap jail on Linux, cooperative egress proxy, per-tool
policy with `ask`, rug-pull lock for tools, JSONL audit log.
