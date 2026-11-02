# Watch, report and hand over

**Goal.** Three people on the team run agents with MCP servers. You want to
know what those servers did today, show a reviewer what was refused and
why, and keep the raw events in the log system you already have.

## Right now: `ps` and `ui`

```sh
mcp-jail ps
```

```
webshop-fs           pid 48213   up 2h14m3s   bwrap: user/pid/ipc/uts ns, net ns (no network) net=none      tools.default=ask   npx -y @modelcontextprotocol/server-filesystem /home/me/projects/webshop
github               pid 48300   up 2h13m40s  bwrap: user/pid/ipc/uts ns, net ns + egress allowlist (hard) net=allowlist tools.default=ask   npx -y @modelcontextprotocol/server-github
```

```sh
mcp-jail ui --open
```

The dashboard is a local page (loopback only; the URL carries a one-time
token). **Overview** has a card per server, running or not: sandbox, network
mode, lock sections and a **Pending change** box when a rug-pull was caught,
plus the report for the chosen range. Headless `ask` calls appear at the
top with Allow / Deny while the page is open. **Events** is the audit log, live:
filter by server, kind, decision or text, click a row for the full JSON,
and watch denies and blocks arrive as toasts. Leave it open on a second
screen.

## This week: `report`

```sh
mcp-jail report --since 7d
```

```
mcp-jail report  2026-10-26 09:00 → 2026-11-02 09:00  (7d)
3182 events from 3 file(s)
decisions:  allow 2841  deny 37  ask_allow 12  ask_deny 4  blocked 9

server                    calls  allow   deny    ask  blocked  last event
fetch                       412    398      9      0        9  2026-11-02 08:41:10
github                     1204   1190      6      8        0  2026-11-02 08:58:02
webshop-fs                 1237   1253     22      8        0  2026-11-02 08:59:45

tool                         server            total  allow   deny    ask  avg ms
write_file                   webshop-fs           71     49     22      0    14.2
fetch                        fetch               407    398      9      0  1320.7
…
host                                      allowed  blocked  servers
docs.python.org                               388        0  [fetch]
www.googletagmanager.com                        0        7  [fetch]
…
top deny / block reasons:
     22  args: argument "path": path "/home/me/projects/webshop/../.env" is outside [/home/me/projects/webshop]
      9  network: www.googletagmanager.com
```

`--server NAME` narrows it, `--json` is for scripts, `--csv` is the per-tool
and per-host tables for a spreadsheet, `--audit FILE` adds a log from a
machine that is not this one. The dashboard's report panel is the same data
with charts and the CSV/JSON buttons.

A Monday cron that mails the weekly report:

```
0 8 * * 1  mcp-jail report --since 7d | mail -s "mcp-jail weekly" security@example.com
```

## For good: the JSONL audit log

`audit.path` is one JSON object per line, append-only, written by the proxy
on the host, not by the server. Ship it like any other log:

```sh
# Vector / Promtail / Filebeat: tail ~/.local/state/mcp-jail/*.jsonl
# jq: the denies of the day
jq -c 'select(.decision=="deny" or .decision=="blocked")' ~/.local/state/mcp-jail/*.jsonl
```

Every record carries `server`, `kind` (`tool_call`, `tool_result`, `net`,
`dns`, `lock`, `start`, `exit`), the decision and a human-readable `reason`.
Arguments are included only with `audit.args: true`; they may hold secrets,
so keep that off in shared setups and look at the drawer in the dashboard
when you need them for a day.

## Hand-over checklist

- the policy files (`~/.config/mcp-jail/policies/` if `wrap` made them)
- the lock files (`~/.config/mcp-jail/locks/*.lock.json`): the tool sets
  you approved, with hashes
- `mcp-jail report --since 30d --json > handover.json`
