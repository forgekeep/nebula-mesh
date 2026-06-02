# Contributing

Thanks for considering a contribution to nebula-mesh.

## Quick checks before opening a PR

```sh
go mod tidy
make lint          # pinned golangci-lint (.tools/)
make test          # go test -race ./...
make gosec         # standalone gosec security audit
make govulncheck   # reachable-vulnerability scan
```

All must pass — `make ci` runs the full set, and CI runs the same.
Security tooling (`gosec`, `govulncheck`) is pinned in the `Makefile`; gosec
exclusions mirror `.golangci.yml` (the canonical rationale).

## Workflow

1. **Open an issue first** for non-trivial changes — features, breaking API changes, refactors. Drive-by bug fixes can skip this.
2. **Branch from `main`.** Keep branches short-lived.
3. **One logical change per PR.** Easier to review, easier to revert.
4. **Tests are required** for new behavior and bug fixes. Integration tests live under `tests/integration`.
5. **Conventional commits** (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`). One-line subjects, body for the why.

## Style

- Standard `gofmt` + `golangci-lint` (config: `.golangci.yml`).
- Errors: prefer sentinels (`var ErrX = errors.New(...)`) over `fmt.Errorf` for cases callers branch on.
- No log-and-return — handle the error or return it, not both.
- Internal-only code lives under `internal/`. The module exports nothing today.

## Reporting bugs

Open an issue with:
- nebula-mesh version (commit SHA or release tag)
- OS / arch
- `nebula-mgmt`/`nebula-agent` log excerpt with `log_level: debug`
- minimal repro steps

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) — please do not open public issues for security reports.
