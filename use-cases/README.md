# Use cases

What people actually do with `mcp-jail`, one scenario per file. Each one has
a goal, a complete policy you can copy, the commands to run and what you will
see in the audit log or the dashboard when it works.

| Scenario | You want to… | Layers that do the work |
|---|---|---|
| [Scope the filesystem server to one project](filesystem-server-for-one-project.md) | let Claude Desktop or Cursor read and write *one* directory and nothing else | `filesystem`, `tools.rules` + `args.under`, `network: none` |
| [Try an unknown server safely](try-an-unknown-server.md) | run a server from npm or PyPI you have never seen before, without giving it your home directory or the internet | `network: none`, `filesystem.tmp`, `audit.args`, `report` |
| [Let a server reach exactly one API](api-server-with-an-egress-allowlist.md) | give a GitHub/Jira/… server its API host and its token, and nothing else to talk to | `network: allowlist`, `sandbox.env`, `args.host` |
| [Keep a web-fetch tool on a leash](fetch-tool-with-host-constraints.md) | allow `fetch`-style tools only for hosts you listed, both at the URL and on the wire | `args.host: [network.allow]`, hard egress |
| [Catch a rug-pull](catch-a-rug-pull.md) | notice when a server's tools, prompts or resources change after you trusted them, and decide before anything runs | `lock`, `diff`, `approve` |
| [Approve dangerous calls from Slack or a web form](approvals-without-a-terminal.md) | keep `ask` useful in Claude Desktop and in CI, where there is no terminal | `ask.webhook`, timeout ⇒ deny |
| [Wrap every server your client already has](wrap-an-existing-client-config.md) | jail all of `claude_desktop_config.json` / `.cursor/mcp.json` / `.mcp.json` in one go | `wrap`, generated policies |
| [Watch, report and hand over](monitor-report-and-hand-over.md) | see what your servers did today, export it for a review, or ship it to your log pipeline | `ps`, `ui`, `report`, JSONL audit |

The policies here are deliberately strict. Loosen them one key at a time and
let the audit log tell you what the server really needs: every refusal has a
`reason`, and `mcp-jail report` lists the most frequent ones.

Something missing? Open an issue with the server, the client and what you
wanted it to do, or send a pull request with a new file in this directory.
