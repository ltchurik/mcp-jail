# Approve dangerous calls from Slack or a web form

**Goal.** `tools.default: ask` is the right default, but Claude Desktop and
Cursor start servers without a terminal, and a CI agent has nobody at the
keyboard. You still want a human in the loop for `write_*` and `send_*`, and
a safe answer when no human shows up.

## Policy

```yaml
tools:
  default: deny
  rules:
    "read_*": allow
    "list_*": allow
    send_email: ask
    "write_*":  ask

ask:
  webhook:
    url: https://approvals.internal.example/mcp-jail
    timeout: 120s                       # nobody answered ⇒ deny
    headers:
      Authorization: "Bearer ${MCP_JAIL_WEBHOOK_TOKEN}"   # expanded from the environment
```

For each `ask` decision without a terminal, `mcp-jail` POSTs:

```json
{"server":"mail","tool":"send_email",
 "arguments":{"to":"cfo@example.com","subject":"Q3 numbers"},
 "ts":"2026-11-02T14:00:00Z",
 "text":"[mcp-jail] mail wants to call send_email {\"to\":\"cfo@example.com\",…}"}
```

and waits up to `timeout` for `{"decision":"allow"}`. A `deny`, a timeout, a
non-200, a body that is not a decision, a connection error: all deny, with
the reason in the audit log and in the error the model sees.

## The smallest approver

Twenty lines of Python that show the request and wait for a key:

```python
import json, sys, threading, http.server as h

class Approver(h.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        print(f"\n{body['text']}\nallow? [y/N] ", end="", flush=True)
        ans = sys.stdin.readline().strip().lower()
        out = json.dumps({"decision": "allow" if ans == "y" else "deny"}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

h.ThreadingHTTPServer(("127.0.0.1", 8765), Approver).serve_forever()
```

`url: http://127.0.0.1:8765/`, run it in a terminal next to Claude Desktop.

## Slack

Point `url` at a Slack (or Mattermost) incoming webhook. Slack posts the
`text` field to the channel and answers `ok`, which is not a decision, so the
call is **denied** but you are **told**. That is the right shape for a
first version: nothing happens silently. To say yes from Slack, put a small
service in front that posts the message with an *Approve* button and answers
the pending `mcp-jail` request when someone clicks; the interaction payload
has everything you need to correlate (server, tool, timestamp).

## CI

In a pipeline there is nobody to ask. Keep `ask` for the things that must
not run unattended and let the timeout deny them; the job output will show
`not approved (webhook: timeout after 120s)` and the report lists them:

```sh
mcp-jail report --since 1h --server mail | grep -A3 "deny / block reasons"
```

Anything that *should* run unattended gets an explicit `allow` with
`args` constraints, not a broader default.
