# Try an unknown server safely

**Goal.** Someone recommends `npx -y some-mcp-server`. You want to see what it
does before it gets your files, your tokens or an internet connection.

## Policy

`~/mcp/trial.yml`:

```yaml
name: trial

network:
  mode: none

filesystem:
  read_write: [~/.npm/_npx]        # npx unpacks the package here
  read_only:  [~/.npm/_cacache]
  tmp: true

tools:
  default: ask                     # you decide, call by call, on the terminal

lock:
  enabled: true
  first: review                    # show me the tool list before anything is recorded

audit:
  path: ~/.local/state/mcp-jail/trial.jsonl
  args: true                       # log arguments too: this is a trial, not production

sandbox:
  env: [PATH, HOME, LANG]
```

## Run it from a terminal first

Any MCP client can drive it, but a terminal is the most instructive: `ask`
prompts you for every call, so you learn the tool names and the arguments the
model sends.

```sh
mcp-jail run --policy ~/mcp/trial.yml -- npx -y some-mcp-server
```

The first thing you see is the catalog: every tool with the first line of
its description, and a question. Nothing is recorded until you answer `y`;
a `n` leaves the list pending, `mcp-jail diff trial` shows it again and
`mcp-jail approve trial` records it later.

```
[mcp-jail] trial: 4 tools seen for the first time (5dc4bc0b04d6)
  fetch_page  —  Fetch a documentation page
  run_shell  —  Run a shell command
  search_docs  —  Search the documentation index
  …
  record these tools and allow their use? [y/N]
```

Point Claude Code at it (`claude mcp add trial -- mcp-jail run --policy
~/mcp/trial.yml -- npx -y some-mcp-server`) and work with it for an hour.
`mcp-jail show trial` tells you at any time what the jail enforces and what
the server can still reach.

## Then read the report

```sh
mcp-jail report --since 2h --server trial
```

```
server                    calls  allow   deny    ask  blocked  last event
trial                        41     38      0      3        0  2026-11-02 11:40:12

tool                         server            total  allow   deny    ask  avg ms
search_docs                  trial                24     24      0      0   212.0
fetch_page                   trial                 9      7      0      2  1830.5
run_shell                    trial                 1      0      0      1
```

Things to look for:

- **Tools you did not expect** (`run_shell` on a documentation server?). The
  tool list is in the lock file, `mcp-jail locks` prints the count and hash;
  `cat ~/.config/mcp-jail/locks/trial.lock.json` has the names.
- **Network it wanted.** With `mode: none` the server may error; the errors
  land in `tool_result` events (`"error":…`). Switch to `allowlist` with the
  hosts it needs, never to `all` just to make the errors go away.
- **Arguments.** With `audit.args: true` the dashboard's event drawer shows
  what the model sent. Turn it off again before using the server for real.

## Promote or drop

If you keep it: copy the policy, set `default: deny`, allow the tools you saw
and liked, add `args.under`/`args.host` where a tool takes paths or URLs, and
switch `audit.args` off. If you drop it: `mcp-jail reset trial` forgets the
lock, and the trial left nothing on your machine outside `~/.npm/_npx`.
