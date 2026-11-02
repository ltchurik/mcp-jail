# Security Policy

mcp-jail is a security boundary, so bugs in it matter more than usual.

## Reporting

Please do **not** open a public issue for a vulnerability.

Use GitHub's private reporting: **Security → Report a vulnerability** on
https://github.com/ltchurik/mcp-jail, or e-mail ltchurik@gmail.com with
`[mcp-jail]` in the subject.

Include: the policy you used, the server command, your OS and bubblewrap
version, and the smallest reproduction you have. You will get an
acknowledgement within 72 hours and a fix or a timeline within 14 days.

## Scope

In scope — anything that lets a jailed server do what the policy says it can't:

- escaping the filesystem scope or the network namespace
- a `tools/call` reaching the server despite a `deny` / unanswered `ask`
  (including an `ask.webhook` that timed out, failed or answered anything
  but `{"decision":"allow"}`)
- a changed tool, prompt or resource set passing the rug-pull lock
- tampering with or suppressing the audit log from inside the jail

Known limitations, documented in the README and **not** vulnerabilities:

- `network.mode: allowlist` is hard on Linux (transparent) and on macOS
  (proxy port only) with the sandbox on. With `sandbox.disabled: true`, or on
  Windows, it relies on `HTTP_PROXY` and a server that ignores it is not
  stopped; use `mode: none` there
- in the hard allowlist the relay dials whatever an allowed name resolves to
  on the host, including private addresses; choose `network.allow` accordingly
- the macOS sandbox scopes the filesystem and the network only: no PID or
  mount isolation, and system locations outside `/Users` stay readable
- no sandbox on Windows yet; policy, lock and audit still apply
- a hostile MCP *client* is out of scope

## Supported versions

Only the latest release receives fixes.
