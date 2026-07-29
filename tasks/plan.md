# Implementation Plan: Faster PR Test Gate

## Overview

Reduce PR feedback time without removing coverage. The current Linux gate takes
7 minutes 32 seconds; `go test -race -count=1 ./...` accounts for 6 minutes
20 seconds. Run the three slow packages and the remaining package set on separate
runners, keep static and security checks independent, and retain the existing
required check names.

## Baseline and target

- Baseline run: <https://github.com/forgekeep/nebula-mesh/actions/runs/30443098717>
- `build / test / lint`: 7:32
- `test (race)`: 6:20
- Target: required PR checks complete in 5 minutes or less on a representative
  uncached run.
- Constraint: every package returned by `go list ./...` must run once with
  `-race -count=1`.

## Architecture decisions

- Use four race shards: `internal/web`, `internal/store`, `internal/api`, and
  every remaining package. These are the slowest measured packages and
  isolating them minimizes the critical path.
- Generate the remainder from `go list ./...` and explicitly exclude only the
  three dedicated packages. New packages therefore enter CI automatically.
- Run build, vet, lint, gosec, and govulncheck independently from race tests.
- Add a small aggregate job named `build / test / lint`. Branch protection keeps
  the same required context and the aggregate fails if any dependency fails or
  is cancelled.
- Start `docker build` independently of the Linux test gate. It does not consume
  test artifacts, so the current dependency only adds latency.

## Task list

### Phase 1: Define and validate sharding

- [x] Add deterministic commands for the web, store, API, and remainder shards.
- [x] Prove that the union contains every module package exactly once.
- [x] Run every shard locally with `-race -count=1`.

### Checkpoint: Coverage

- [x] No package is missing or duplicated.
- [x] All four race shards pass locally.

### Phase 2: Restructure the workflow

- [x] Move vet, build, lint, gosec, and govulncheck into an independent job.
- [x] Add parallel race jobs for the four validated shards.
- [x] Replace the current required Linux job with an aggregate gate named
      `build / test / lint`.
- [x] Remove the unnecessary Docker dependency while retaining the check name
      `docker build`.

### Checkpoint: Workflow

- [x] Workflow syntax is valid.
- [x] Every dependency failure or cancellation makes the aggregate gate fail.
- [x] Windows and scheduled workflows remain unchanged.

### Phase 3: Measure the PR

- [x] Run the repository's complete local CI command.
- [ ] Open a dedicated PR and wait for every required check.
- [ ] Record the PR run duration and compare it with the 7:32 baseline.

### Checkpoint: Complete

- [ ] Required PR checks pass.
- [ ] Race coverage is unchanged.
- [ ] Required check names remain compatible with branch protection.
- [ ] PR gate meets the 5-minute target or the measured result and remaining
      bottleneck are documented before merge.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| A package is omitted from the remainder shard | High | Derive the package set from `go list ./...` and test set equality locally. |
| Aggregate job passes after a failed dependency | High | Use `if: always()` and explicitly validate every `needs.*.result`. |
| More runners increase Actions usage | Medium | Limit sharding to the three measured slow packages plus one remainder job. |
| Cached and uncached timings differ | Medium | Compare end-to-end wall-clock on the PR and retain the exact baseline run. |

## Open questions

- None. The implementation preserves coverage and existing required check names.
