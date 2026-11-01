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
- a changed tool set passing the rug-pull lock
- tampering with or suppressing the audit log from inside the jail

Known limitations, documented in the README and **not** vulnerabilities:

- `network.mode: allowlist` is cooperative (it relies on `HTTP_PROXY`); use
  `mode: none` for a hard guarantee until the netns+pasta backend lands
- no sandbox on macOS/Windows yet; policy, lock and audit still apply
- a hostile MCP *client* is out of scope

## Supported versions

Only the latest release receives fixes.
