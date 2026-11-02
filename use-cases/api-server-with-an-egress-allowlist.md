# Let a server reach exactly one API

**Goal.** The GitHub MCP server needs `api.github.com` and a token. It must
not be able to send that token anywhere else, and it must not browse your
disk.

## Policy

`~/mcp/github.yml`:

```yaml
name: github

network:
  mode: allowlist
  allow:
    - api.github.com
    - "*.githubusercontent.com"     # raw file contents and release assets

filesystem:
  read_write: [~/.npm/_npx]
  read_only:  [~/.npm/_cacache]
  tmp: true

tools:
  default: ask
  rules:
    "get_*":     allow
    "list_*":    allow
    "search_*":  allow
    create_issue: allow
    create_pull_request: ask
    "delete_*":  deny
    "*_repository": deny          # create/delete/fork repositories: not from an agent

lock:
  enabled: true

audit:
  path: ~/.local/state/mcp-jail/github.jsonl

sandbox:
  env: [PATH, HOME, LANG, GITHUB_PERSONAL_ACCESS_TOKEN]   # the token goes in, nothing else
```

Export the token in the environment the client starts from (or in the
client's `env` block); `sandbox.env` is the list of variables that cross
into the jail, everything else in your environment stays outside.

## What happens on the wire

On **Linux** the jail has an empty network namespace. `mcp-jail` runs a tiny
shim inside it: DNS answers for `api.github.com` point to the shim, HTTPS
connections are matched on their SNI and relayed through a Unix socket to a
host-side filter, which dials the real host. A connection to `pastebin.com`
gets `NXDOMAIN`; a connection to a raw IP has nowhere to go. No capability,
no proxy environment variable the server could ignore.

On **macOS** the `sandbox-exec` profile allows outbound traffic to one
loopback port only: the filtering `HTTP_PROXY`. A server that honours the
proxy variables (Node, Python `requests`, `curl` do) reaches the allowlist; a
server that ignores them reaches nothing.

```json
{"ts":"2026-11-02T12:00:01Z","server":"github","kind":"net","host":"api.github.com","decision":"allow"}
{"ts":"2026-11-02T12:00:09Z","server":"github","kind":"dns","host":"pastebin.com","decision":"blocked"}
```

The dashboard's **Network** panel lists the hosts, allowed and blocked, per
server; a blocked host that is not a typo is the moment to look at the
server's source.

## Variations

- **Self-hosted GitLab / Jira.** Replace the hosts. Wildcards are suffix
  matches: `"*.example.com"` matches `git.example.com`, not `example.com`.
- **Private addresses.** The relay dials whatever an allowed name resolves
  to, including `10.0.0.0/8`. Do not allow a name you do not control.
- **Token in a file instead.** Put it in a directory under `read_only` and
  pass the path; nothing else in `$HOME` is mounted.
