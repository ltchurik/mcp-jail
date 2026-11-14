# Changelog

## v0.9.1 — 2026-11-14

Fix for the hard egress allowlist on Ubuntu 26.04, where AppArmor confines bubblewrap: the jail no longer needs any capability. Also a social preview banner at the top of the README.

### Fixed

- The hard egress allowlist on Ubuntu 26.04 (and any system whose AppArmor
  confines bubblewrap): the shim could not bind :53 (`permission denied`)
  because the `unpriv_bwrap` profile strips every capability from what
  bubblewrap runs, `--cap-add` included. The jail no longer asks for any:
  bubblewrap writes `0` into the jail's own
  `net.ipv4.ip_unprivileged_port_start` before it executes the shim, which
  then binds its ports as your normal uid and starts the server as a plain
  child. The server's nested user namespace is gone: writing its id maps
  needs `CAP_SYS_ADMIN` over the new namespace, which the same profile
  denies, and it protected nothing once the shim itself is unprivileged.
  Found by CI when `ubuntu-latest` moved to 26.04.

### Changed

- The README opens with a social preview banner (`docs/social-preview.jpg`,
  1280×640): what mcp-jail does, the stdio path through the jail, the
  layers and the sandbox per platform.

## v0.9.0 — 2026-11-11

Windows: binaries in every release, the test suite on Windows in CI, the Docker backend working on a Windows host, and a native sandbox: `sandbox.backend: appcontainer` runs the server as an AppContainer process with the policy's directories granted for the run and the network capabilities the mode calls for.

### Added

- Windows native sandbox: `sandbox.backend: appcontainer` (what `auto` picks
  on Windows) runs the server as an AppContainer process. The policy's
  directories are granted to the container's SID for the run (`icacls`
  entries, removed at exit, stale ones removed at the next start), the
  toolchain and working directories read-only, mcp-jail's own files denied;
  `network.mode: none` is a process without network capabilities, `all`
  grants them; `allowlist` and `exec.allow` are refused. The container has a
  private home and temp under `%LOCALAPPDATA%\Packages`. `sandbox.disabled`
  on Windows now works too (there is no `env -i`): the same launcher scrubs
  the environment and ties the server to the jail. `doctor`, `show` and
  `wrap` know the backend.
- Windows binaries (`windows_amd64`, `windows_arm64`, as `.zip`) in every
  release, attested like the tarballs; the test suite runs on Windows in CI.

### Fixed

- The Docker backend on a Windows host: the container ran as `--user -1:-1`
  (there is no uid; it is `nobody` now), a drive path was mounted at its
  `C:\...` spelling inside the Linux container and the drive colon was
  taken for a mount separator (paths are mounted at `/mnt/<drive>/...`, with
  a note in `show` and `run`), `/tmp` was shared from a host without one
  (the host temp dir is), and the per-user socket directory under the temp
  dir carried the uid `-1`.

## v0.8.1 — 2026-11-10

Follow-ups to v0.8.0: a pending change can be approved item by item and a running jail tells the client when that happened; `mcp-jail doctor` explains what a host can do; the Docker backend warns about an unpinned image and pulls a missing one quietly; the `initialize` instructions join the lock; budgets reload with the policy.

### Added

- `mcp-jail approve <name> --only tools:a,prompts:b` (a bare key means
  tools) records only those items of a pending change and leaves the rest
  pending; the dashboard's Pending box lists the items with checkboxes and
  sends the ticked ones. A pending section written under `lock.scope: item`
  is flagged `held` in `diff`, `show` and the dashboard.
- A running jail with a pending change watches its lock and, once the
  change is approved elsewhere (CLI, dashboard, another terminal), sends
  the client `notifications/tools/list_changed` (prompts / resources
  likewise), so the client lists again without a restart; audit `lock` /
  `notified`. `lock.notify: false` turns it off; `show` says so.
- `mcp-jail doctor [--json]`: what this host can do, with a hint per
  problem: bubblewrap (version, the three user-namespace knobs, a probe
  jail), `sandbox-exec`, docker or podman and whether a daemon answers,
  the state directory; exit 1 when no sandbox at all is usable.
- A `sandbox.image` named by tag rather than digest is warned about like a
  floating `npx` package (`run` audits `policy` / `warn`, `show` notes it,
  `wrap --image` writes the warning header). A missing image is pulled
  quietly before the server starts (one log line); a failed pull refuses
  the start.
- The `initialize` result's `instructions` are locked and linted like a
  list, as a single item named `instructions`: recorded on first contact
  (`lock.first` applies), refused with `-32002` on the `initialize`
  response when they change, approved with `mcp-jail approve` (or `--only
  instructions:instructions`); `diff`, `show`, `locks` and the dashboard
  show the section.
- `limits` are reloaded with `tools`, `ask` and `server_requests`: an
  existing budget keeps its balance (clamped to the new cap), a new one
  starts full, a zero rate removes one; the `reload` audit line names the
  rates.

## v0.8.0 — 2026-11-10

Two answers to the questions a Docker-sandboxing post raised about mcp-jail: a lock that copes with servers whose tool list legitimately changes, and a container backend for hosts without bubblewrap, Windows included. Existing policies and locks keep working unchanged.

### Added

- `lock.scope: item`: a lock mode for servers whose tool list legitimately
  varies. Items whose hash still matches the lock are forwarded and usable;
  the added or changed ones are filtered out of the list (page by page),
  held as pending, linted, and refused on use until `mcp-jail approve` or
  the dashboard records the new list. The audit log carries `lock` /
  `review` with the names; a pure removal is a `warn`. First contact still
  follows `lock.first` for the whole list; resource templates stay
  list-scoped. `mcp-jail show` prints the scope. Default stays `list`.
- `sandbox.backend: docker` (and `sandbox.image`): run the server in a
  container (docker, or podman) with the policy's paths bind-mounted at
  their host paths, every capability dropped, `no-new-privileges`, a
  read-only root, a private `/tmp` and `HOME=/tmp` (a passed-through HOME
  would point at a path that does not exist there). `network.mode: none` is
  a container without a network; `allowlist` is hard on a Linux host (the
  egress relay is mounted into the container, mcp-jail is the in-container
  shim) and refused elsewhere, never downgraded. The image is derived from
  npx / bunx / uvx / python when omitted. The first sandbox on Windows.
  `sandbox.backend` also names `bwrap`, `sandbox-exec` and `none`
  explicitly (`auto` stays the default); `mcp-jail wrap --backend --image`;
  `mcp-jail show` prints the image.

## v0.7.1 — 2026-11-09

### Added

- `CITATION.cff` with the software metadata (author, ORCID, licence,
  repository) so GitHub offers "Cite this repository" and Zenodo archives
  each release with a DOI.

## v0.7.0 — 2026-11-07

What a server *says* and *returns* is now checked, not only what it may call: content lint on definitions and results, a policy for server-initiated requests, budgets, credential detection, and a warning for launchers that fetch their program at start. Existing policies keep working unchanged; the new defaults are `warn`.

### Added

- `lint.lists`: content heuristics on every tools, prompts or resources list
  the lock has yet to approve (first contact or a change): hidden markup and
  invisible characters, text addressed to the model, sensitive paths,
  fetch-and-run and exfiltration phrases, base64 blobs, and tool names
  recorded for another server on this machine (shadowing). Findings go to
  stderr and the audit log (`kind: lint`), are kept with the pending or
  recorded section, and are shown by `mcp-jail diff` (`! lint`), `mcp-jail
  show`, the dashboard and the terminal review. `warn` (default) reports;
  `deny` holds a first-contact list with findings for review regardless of
  `lock.first`; `lint.ignore` drops rules.
- `mcp-jail run`, `show` and `wrap` warn about a launcher that resolves its
  program at every start instead of pinning it: an npx / bunx / pnpm dlx /
  yarn dlx package without an exact version, a uvx / pipx package without
  `==`, a deno remote module, a docker image without a digest, `sh -c "curl …
  | sh"`. The warning shows the pinned form; `wrap` writes it into the policy
  header; `run` audits it (`policy` / `warn`).
- `tools.secrets`: a `tools/call` argument that looks like a credential (AWS
  access key, PEM private key, JWT, GitHub / GitLab / Slack / Google / OpenAI
  / Anthropic / Stripe / SendGrid / npm / PyPI tokens, `Bearer …`,
  `user:password@` in a URL, `password = …`, or the value of a
  secret-looking variable in mcp-jail's own environment) is audited (`kind:
  secret`, default `warn`), refused (`deny`), or asked about even under an
  allow rule (`ask`; the terminal prompt and the webhook carry the reason as
  `note`). The audit names the rule, the argument path and the length, never
  the value. A rule's own `secrets:` overrides; `tools.secrets_ignore` drops
  rules.
- `limits`: token-bucket budgets per window. `calls` (tools/call overall),
  `tools` (per exact name or glob), `args_bytes` (bytes of tools/call
  arguments) deny a call with error `-32007` before it reaches the server,
  audited as `deny` with `reason: limit: …`; a refused call is not charged.
  `egress_bytes` is enforced on the Linux relay, the `HTTP_PROXY` filter and
  every POST to a remote server: a connection past its budget ends (`net` /
  `blocked`). `mcp-jail show` lists the budgets.
- `lint.results`: the same content heuristics on what the server returns
  (`tools/call` results, `resources/read` contents, `prompts/get` messages,
  `notifications/message`), limited to the rules that make sense for data
  (hidden characters, hidden markup, text addressed to the model). `warn`
  (default) audits each finding and forwards the result; `deny` answers the
  client with error `-32006` instead, drops the notification, and refuses a
  result too large to scan.
- `server_requests`: requests the server sends to the client
  (`sampling/createMessage`, `elicitation/create`, `roots/list`, `ping`) are
  decided like tool calls (exact method or glob, allow / deny / ask); a
  denied or unapproved one is answered to the server with a JSON-RPC error
  and never reaches the client, audited as `server_request`. Default: `ping`
  and `roots/list` allowed, everything else denied. Until now every
  server-initiated request was forwarded unchecked. `mcp-jail show` prints
  the section as `from server`; the dashboard's kind filter knows
  `server_request` and `lint`.
- Every jail starts with `DO_NOT_TRACK=1`, `NO_UPDATE_NOTIFIER=1` and
  `npm_config_update_notifier=false`, so a launcher does not phone home or
  look for a newer version on its own. `sandbox.env` accepts `NAME=value` to
  set a variable (`npm_config_ignore_scripts=true`); an entry with the same
  name overrides a default. `mcp-jail show` lists them under `env`.

### Changed

- README and SECURITY state that the macOS profile restricts file and network
  operations only: Mach IPC, `sysctl` and other system services stay reachable.
- The README title names the author; the roadmap lists the v0.6 items.

## v0.6.1 — 2026-11-03

### Fixed

- The README's sample policy allowed `write_file` under `~/projects` while only
  `~/projects/scratch` was writable; the sample now keeps `under:` inside
  `read_write`.
- `mcp-jail show` lists, and `mcp-jail run` prints and audits (`policy` /
  `warn`), every `args.under` directory that is not inside `read_write` (a
  write there fails inside the jail as a filesystem error, not as denied by
  policy) or not inside any mount at all.
- The `tool_result` audit event records a result with `isError: true` (its
  first text line), not only JSON-RPC errors, so a call that failed inside
  the jail no longer looks like a clean `allow`.
- Remote servers: the `initialize` answer is handed to the client before the
  server-initiated stream is opened, so a notification from that stream can
  no longer arrive ahead of it.

## v0.6.0 — 2026-11-02

Two gaps raised by early readers: trust on first contact, and what a launcher may exec. Existing policies keep working unchanged.

### Added

- `lock.first: review`: a tools, prompts or resources list the lock has never
  recorded is refused until someone approves it, instead of being trusted on
  first contact. On a terminal the catalog is printed and `y` records it; with
  the dashboard open the jail waits up to `ask.timeout` for **Approve** or
  `mcp-jail approve`; with nobody to ask the list is refused and kept pending.
  Nothing is recorded before the approve. Default stays `record`.
- `mcp-jail show <name>` / `show --policy FILE -- <command>`: the effective
  jail of a server (sandbox kind, every visible path and how, masked state,
  network mode and enforcement, env, tools, lock sections and pending items,
  audit), as text or `--json`, without starting anything.
- `mcp-jail diff` labels a section that was never recorded; the dashboard shows
  a first-contact review as "First contact: review before use" with its own
  Approve button, also for a server that has no lock file yet.
- `exec.allow` / `exec.sha256`: pin the executables a launcher (npx, uvx, a
  thin npm package) may exec outside the system paths. Linux binds each file
  read-only on its own, so unlisted siblings do not exist in the jail; macOS
  denies `process-exec` under the hidden trees and re-allows the listed files
  and the directories the policy shares. A pinned digest is checked before
  start; a mismatch, a missing file, `sandbox.disabled` or a platform without
  a sandbox refuses to start. `mcp-jail show` reports each pin's state.

## v0.5.0 — 2026-11-02

Remote MCP servers can now be jailed too. Existing policies keep working unchanged.

### Added

- Streamable HTTP transport: a policy with `server.url` (and optional
  `server.headers`, `${VAR}` expanded) jails a remote MCP server. The client
  keeps talking stdio to `mcp-jail`; the jail speaks Streamable HTTP to the
  server (POST per message, JSON or SSE answers, `Mcp-Session-Id`,
  `MCP-Protocol-Version`, a standing GET stream, DELETE on exit) and applies
  policy, argument constraints, `ask`, lock and audit exactly as for a local
  server. `https` is required outside localhost, redirects are refused, special
  address ranges are refused unless written literally, headers never leave
  `server.url`. HTTP errors, unusable bodies and expired sessions reach the
  client as JSON-RPC error `-32005` and the audit log as `protocol` events.
- `mcp-jail wrap` converts `{"type": "http", "url": …, "headers": …}` entries:
  credential-looking headers move to the entry's `env`, the policy references
  them as `${NAME}`. Legacy `type: sse` entries are left alone.
- `examples/echo-http-server.py`, a small Streamable HTTP server for trying
  this out; the e2e suite runs the remote path and the HTTP `wrap` on both CI
  platforms.

### Changed

- After one side of the proxy closes, in-flight answers are still forwarded
  for up to two seconds, so a client that shuts its input right after its
  last request (scripts, one-shot tools) gets the answers.

## v0.4.1 — 2026-11-02

Closes everything the v0.4.0 security review left open. No policy changes needed.

### Security

- Rug-pull lock: a `tools/call` or `prompts/get` for a name that the verified
  list does not contain is refused (the lock had checked the list hash, not that
  a use was in the list). Paged lists (`nextCursor`) are collected and verified
  whole on the last page instead of tripping a false rug-pull; a continuation
  with a cursor the server never issued, or more than 10 000 items, taints the
  section; a call between pages is refused rather than parked.
- Proxy: the requests waiting for a server answer are bounded (1024). Past that
  the oldest is dropped, audited and answered with error `-32004`, so a server
  that stops answering cannot grow the proxy without bound.
- Registry: the server command is recorded with credentials redacted (values of
  token/key/password/auth flags and `KEY=VALUE` pairs, URL passwords, tokens with
  a well-known prefix), so `mcp-jail ps` and the dashboard no longer show them.
  Run and `known/` file names of servers with unusual names carry a short hash,
  so two names that sanitise alike cannot overwrite each other's entry.
- Dashboard rule promotion: policy edits take an advisory lock on the policy's
  directory, so two concurrent promotions cannot lose a rule.
- CI and release: every GitHub Action is pinned to a commit; release archives
  and `checksums.txt` carry a build provenance attestation
  (`gh attestation verify <file> --repo ltchurik/mcp-jail`); the sandbox-exec
  end-to-end scenarios run in CI on macOS.

### Fixed

- Control socket close waited at most one second for in-flight requests, which
  flaked in CI; it now waits up to five seconds and then cuts the connection.

## v0.4.0 — 2026-11-02

Promote rules and stop jails from the dashboard, and a hardening release: an internal
security review of the proxy, the sandboxes, the egress paths and the
dashboard, with every high and medium finding fixed (see *Security*
below). Policies written for v0.3 keep working; `ask.webhook.url` must now
be `https` unless it points at localhost, and a jail started from your home
directory no longer shares it as the working directory.

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

### Security

Findings of an internal security review, all fixed:

- **Case-variant and duplicate JSON keys** (`Method`, `NAME`, `Arguments`,
  `paramſ`…) could carry a second value past the policy: Go's JSON decoder
  matched them case-insensitively while servers read the exact key. The
  proxy now parses the envelope and `tools/call` params strictly (single
  object, exact keys, each at most once, no trailing data) and answers
  anything else with `-32600` / `-32602` instead of forwarding it. Batches
  (arrays) are refused the same way.
- **Non-canonical response ids** (`7.0`, `7e0` for request `7`) let a server's
  list response slip past the rug-pull lock. Ids are now correlated by
  canonical value; a response to an id the proxy never forwarded is dropped
  and audited (`kind: protocol`), and a list that was in flight at that
  moment is refused rather than left pending.
- A `tools/call`, `prompts/get` or `resources/read` sent as a notification
  (no id) was forwarded unchecked; it is now dropped and audited. Lines the
  proxy cannot parse are no longer forwarded in either direction.
- Two tool (prompt, resource) definitions under one name now fail the lock
  instead of hashing as one.
- Two glob rules of equal length matching the same tool no longer pick a
  winner by map order: the stricter decision wins (deny > ask > allow).
- Audit fields chosen by a server or client (`tool`, `reason`, `error`,
  `host`) are clipped to 2 KiB and `args` to 64 KiB, and the dashboard /
  `report` reader skips an oversized line instead of stopping at it, so one
  huge error message cannot hide the events after it. The terminal `ask`
  prompt strips control characters from the tool name and arguments.
- The convenience binds for the working directory and the server's
  toolchain could expose the whole home directory or `/` read-only (a jail
  started from `~`, or by a GUI client with cwd `/`; a binary in `~/bin`),
  which on macOS also cancelled the home-hiding rules. Such a directory is
  no longer shared: the server starts in `/` and the sandbox description
  (`ps`, dashboard, `start` event) says `cwd not shared (home)`; the
  toolchain bind falls back to the binary's own directory.
- mcp-jail's own state (policy file, audit log, lock and registry
  directories, the control socket) is now masked inside the jail even when
  a `read_write`/`read_only` path or a convenience bind would cover it:
  `--tmpfs` / `/dev/null` binds on Linux, trailing `deny file*` and `deny
  network*` rules on macOS (a server could otherwise approve its own asks
  or rewrite its policy and ask for a reload).
- The audit log is opened with `O_NOFOLLOW` and must be a regular file.
- The control-socket fallback directory under `$TMPDIR` must be a private
  directory owned by the user, never a symlink or someone else's.
- `name` in a policy may not contain path separators or control
  characters (it names lock, registry and socket files); control characters
  are rejected in paths and hosts and neutralised in the macOS profile.

- The egress relay (Linux) and the `HTTP_PROXY` filter now check what an
  allowed name resolves to: a loopback, private, link-local, CGNAT,
  multicast or unspecified address is refused unless that literal address
  is in `network.allow`. Before, whoever ran the DNS of an allowed host could
  point the jail at the host's own loopback or LAN services. The filter's
  upstream transport no longer honours the host's `HTTP_PROXY`.
- `ask.webhook.url` must be `https` unless it names localhost; the webhook
  client no longer follows redirects, so the configured headers go to the
  configured URL only and a 3xx is a deny.
- Dashboard: a tool name promoted to a rule is escaped so a server that
  names a tool `*` cannot turn *Always allow* into a rule for every tool;
  `Origin` is parsed instead of prefix-matched; ask ids in URLs are
  validated; a symlinked policy file is edited at its target.
- CSV export prefixes cells starting with `=`, `+`, `-`, `@` with an
  apostrophe (spreadsheet formula injection from server-chosen names).
- `mcp-jail wrap` no longer puts `/` or the home directory into
  `read_write`; an already-wrapped entry's note shows the command.
- The dashboard counts as attached for 12s after its last poll (was 5s).

### Changed

- Toolchain: Go 1.27 (`go.mod`, CI, release builds), golangci-lint v2.15 in
  CI, and a `govulncheck` job on every push and pull request. The only
  dependency, `gopkg.in/yaml.v3`, is at its latest release (v3.0.1) with no
  known vulnerabilities.
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
