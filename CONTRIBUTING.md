# Contributing

Issues and PRs welcome. Keep it small; one change per PR.

## Dev loop

```sh
make lint    # go vet + golangci-lint
make test
make build   # bin/mcp-jail
cd examples && ../bin/mcp-jail run --policy echo-policy.yml -- python3 echo-server.py
```

Go 1.24+. Standard library only, plus `gopkg.in/yaml.v3` — please don't add
dependencies without an issue first; a security tool should be auditable.

## Ground rules

- Every enforcement path (policy decision, lock, netproxy) needs a test.
- Fail closed. If something can't be checked, deny and log it.
- Keep the `--` passthrough byte-exact: the proxy must never rewrite a
  message it isn't enforcing on.
- Commit messages: `type: summary` (`feat`, `fix`, `docs`, `test`, `ci`, `refactor`).

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) — not a public issue.
