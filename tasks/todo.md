# Faster PR Test Gate

## Task 1: Define race shards

**Description:** Define dedicated race commands for `internal/web` and
`internal/store`, plus a generated remainder containing every other module
package.

**Acceptance criteria:**

- [x] The three package sets are mutually exclusive.
- [x] Their union equals `go list ./...`.
- [x] New packages enter the remainder automatically.

**Verification:**

- [x] Compare sorted expected and actual package lists.
- [x] Run all shards with `go test -race -count=1`.

**Dependencies:** None

**Files likely touched:**

- `.github/workflows/ci.yml`

**Estimated scope:** Small

## Task 2: Parallelize the PR gate

**Description:** Run static/security checks and the three race shards in
parallel, then aggregate their results under the existing required check name.

**Acceptance criteria:**

- [x] Static and security checks retain their current commands.
- [x] Each race shard is a separate GitHub Actions job.
- [x] `build / test / lint` fails when any dependency fails or is cancelled.

**Verification:**

- [x] Validate workflow syntax.
- [ ] Inspect the PR job graph and all job conclusions.

**Dependencies:** Task 1

**Files likely touched:**

- `.github/workflows/ci.yml`

**Estimated scope:** Small

## Task 3: Remove Docker serialization

**Description:** Start `docker build` concurrently because it consumes no output
from the Linux test job.

**Acceptance criteria:**

- [x] The `docker build` check name is unchanged.
- [x] Docker starts without waiting for race tests.

**Verification:**

- [ ] Confirm timestamps in the PR Actions run.
- [ ] Confirm the Docker job passes.

**Dependencies:** None

**Files likely touched:**

- `.github/workflows/ci.yml`

**Estimated scope:** Extra small

## Task 4: Verify and measure

**Description:** Prove local correctness and compare the dedicated PR with the
7:32 baseline.

**Acceptance criteria:**

- [x] Full local CI passes.
- [ ] Every required GitHub check passes.
- [ ] The PR gate completes in 4 minutes or less, or the remaining bottleneck is
      documented before merge.

**Verification:**

- [x] Run `make ci`.
- [ ] Read back the PR checks and job timestamps with `gh`.

**Dependencies:** Tasks 1-3

**Files likely touched:**

- `.github/workflows/ci.yml`
- `tasks/plan.md`
- `tasks/todo.md`

**Estimated scope:** Small

## Checkpoint: Human approval

- [x] Review and approve this plan before workflow implementation.
