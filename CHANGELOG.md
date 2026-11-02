# Changelog

## Unreleased

### Added

- **`mcp-jail ui`**: a local dashboard listing every server that ran through
  `mcp-jail run` (running or not) with its sandbox, network mode, lock
  sections, pending changes and the last 24h of decisions, plus a live,
  filterable audit event view streamed over server-sent events. Loopback
  only, token-protected, no external assets, read-only.
- **`mcp-jail report`** and the dashboard's report panel: decisions over
  time, calls per tool (most refused first) with average duration, hosts
  reached or blocked, top refusal reasons and lock events for a time range;
  `--json`, `--csv`, `--server`, `--audit`. The same data is served at
  `/api/report` (`format=json|csv|text`).
- **`mcp-jail ps`**: list running jails. `run` now registers itself in
  `~/.config/mcp-jail/run/` (or `$MCP_JAIL_HOME/run`) for the lifetime of
  the process.

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
