# Security Policy

mcp-jail is a security boundary, so bugs in it matter more than usual.

## Reporting

Report vulnerabilities as GitHub issues on
https://github.com/ltchurik/mcp-jail/issues with the `security` label.
If the report contains a working exploit or details you would rather not
publish before a fix exists, use **Security → Report a vulnerability** on the
same repository instead; it opens a private advisory with the same workflow.

Include: the policy you used, the server command, your OS and bubblewrap
version, and the smallest reproduction you have. You will get an
acknowledgement within 72 hours and a fix or a timeline within 14 days.

## Scope

In scope — anything that lets a jailed server do what the policy says it can't:

- escaping the filesystem scope or the network namespace
- a `tools/call` reaching the server despite a `deny` / unanswered `ask`
  (including an `ask.webhook` that timed out, failed or answered anything
  but `{"decision":"allow"}`, and an `ask` answered through the control
  socket by anything other than the same user's dashboard)
- a changed tool, prompt or resource set passing the rug-pull lock
- tampering with or suppressing the audit log from inside the jail
- reading `mcp-jail ui` without its token, or from another machine; making
  it approve a lock change from a page you did not open yourself (CSRF)

Known limitations, documented in the README and **not** vulnerabilities:

- `network.mode: allowlist` is hard on Linux (transparent) and on macOS
  (proxy port only) with the sandbox on. With `sandbox.disabled: true`, or on
  Windows, it relies on `HTTP_PROXY` and a server that ignores it is not
  stopped; use `mode: none` there
- in the hard allowlist the relay dials whatever an allowed name resolves to
  on the host, except loopback, link-local, private and other special ranges,
  which are refused unless the literal address is in `network.allow`
- the macOS sandbox scopes the filesystem and the network only: no PID or
  mount isolation, system locations outside `/Users` stay readable, and Mach
  IPC, `sysctl` and other system services are not restricted
- the Windows AppContainer scopes the filesystem (through access-control
  entries for the container SID on the policy's directories, present while
  the jail runs) and the network (none / all) only: no PID isolation,
  Windows and Program Files stay readable, `allowlist` is refused there
- a hostile MCP *client* is out of scope

## Supported versions

Only the latest release receives fixes.
