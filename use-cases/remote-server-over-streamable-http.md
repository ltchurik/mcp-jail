# Jail a remote server over Streamable HTTP

**You want to…** use a hosted MCP server, say Linear's, from Claude Code or
Cursor, but with the same guard rails you have for local servers: deny the
destructive tools, ask before the rest, notice when the tool list changes,
keep a log. And you would rather not paste the API token into a policy file
that lives in your dotfiles.

**Layers that do the work:** `server.url`, `server.headers` with `${VAR}`,
`tools.rules`, `lock`, `audit`; `wrap` for an existing `type: http` entry.

## Policy

```yaml
name: linear
server:
  url: https://mcp.linear.app/mcp
  headers:
    Authorization: "Bearer ${LINEAR_TOKEN}"   # read from the environment at start

tools:
  default: ask
  rules:
    "list_*": allow
    "get_*": allow
    "search_*": allow
    "create_*": ask
    "delete_*": deny
    "archive_*": deny

lock: { enabled: true }
audit: { path: ~/.local/state/mcp-jail/linear.jsonl }
```

There is no `sandbox`, `filesystem` or `network` section: nothing runs on
your machine except `mcp-jail`, and it talks to that one URL only.

## Client config

Claude Code (`.mcp.json`) or Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "linear": {
      "command": "mcp-jail",
      "args": ["run", "--policy", "/home/me/mcp/linear.yml"],
      "env": { "LINEAR_TOKEN": "lin_api_…" }
    }
  }
}
```

The token stays in the client config, where it already was, and reaches the
policy through `${LINEAR_TOKEN}`. Or let `wrap` do the conversion from the
entry you have today:

```sh
mcp-jail wrap .mcp.json
#   wrapped  linear   -> ~/.config/mcp-jail/policies/linear.yml (remote; LINEAR_AUTHORIZATION kept in the client config env)
```

`{"type": "http", "url": "https://mcp.linear.app/mcp", "headers": {"Authorization": "Bearer …"}}`
becomes the `command`/`args`/`env` shape above, with the header value moved
to `env.LINEAR_AUTHORIZATION` and the policy referring to it.

## What you will see

```
[mcp-jail] linear: remote (streamable http) | net=none tools.default=ask lock=true
[mcp-jail] lock: recorded 23 tools (0b7f3e1c9a2d)
[mcp-jail] deny tools/call delete_issue (policy)
```

In the audit log a denied call never left your machine, and a transport
problem is visible as its own line:

```json
{"ts":"…","server":"linear","kind":"tool_call","tool":"delete_issue","decision":"deny","reason":"policy"}
{"ts":"…","server":"linear","kind":"protocol","decision":"blocked","reason":"remote returned HTTP 401"}
```

The client sees the second case as JSON-RPC error `-32005` with the same
text. An expired session (`404` from the server) is reported the same way;
restart the client to start a new one, the jail does not re-initialize on
its own.

## Rules the transport enforces

- `https` is required, except for `localhost` (a server you run for
  development); a URL with `user:password@` is refused, use `server.headers`
- redirects are not followed, so the headers never go to another host; a
  name that resolves into loopback, link-local or private ranges is refused
  unless you wrote that literal address in `server.url`
- the headers in the policy are sent to `server.url` and nowhere else;
  `Mcp-Session-Id`, `MCP-Protocol-Version`, `Accept` and friends are set by
  the jail and cannot be overridden from the policy
- every answer, whether a JSON body or an SSE event, goes through the same
  strict parser, lock and listed-name checks as a local server's output

## Trying it without a hosted server

`examples/echo-http-server.py` is a tiny Streamable HTTP server for local
experiments:

```sh
python3 examples/echo-http-server.py 8765 &
cat > echo.yml <<YML
name: echo-http
server: { url: http://127.0.0.1:8765/mcp }
tools: { default: deny, rules: { "read_*": allow } }
YML
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
               '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
               '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}}' \
  | mcp-jail run --policy echo.yml
```
