---
name: issue-driven-delivery
description: >-
  Decompose a design/plan doc into atomic GitHub issues, then implement each one
  with paired Opus subagents (an implementer and an independent reviewer) working
  in git worktrees, parallelizing only mutually-exclusive tasks, and merging via
  squashed PRs that auto-close their issue. Use when the user says things like
  "break PLAN.md into tasks and ship them", "implement this design issue by issue",
  "drive these tasks with subagents and PRs", or otherwise wants Claude-code-first,
  one-issue-one-PR delivery of a multi-task plan on GitHub.
---

# Issue-driven delivery

A repeatable loop for turning a design doc into shipped, reviewed code. One feature = one issue = one PR. Every task is implemented by an Opus subagent and independently verified by a second Opus subagent before merge. The orchestrator (you) never writes feature code directly — you decompose, dispatch, review the reviews, and merge.

## When to use

- The user has a plan/design doc (e.g. `PLAN.md`) and wants it built out task by task on GitHub.
- The user asks for subagent-driven implementation with review gates and PR merges.
- Work splits into ≥3 tasks where tracking, parallelism, and review gates pay off.

Do **not** use for a single small change — just do it directly.

## Roles

- **Orchestrator (you):** decompose, create issues, create worktrees, dispatch subagents, merge PRs, resolve conflicts, track progress. Never implements features yourself.
- **Implementer subagent (Opus):** implements exactly one task with unit + e2e tests, opens a PR. One per task.
- **Reviewer subagent (Opus):** independently re-runs the acceptance checks (does *not* trust the implementer's report), then posts an LGTM or requests changes. A fresh agent per review.

## Phase 0 — Setup (once)

1. Confirm toolchain is present (language compiler, `gh auth status`, `git`). Install what's missing.
2. Create the repo if needed: `gh repo create <owner>/<name> --public --source=. --remote=origin --push`.
3. Create labels: `task`, one per phase (e.g. `phase-1-foundation`), and `needs-review`.
4. **Pre-install shared dependencies in one commit on `main`** *and reference them from real code* (see Gotchas — a bare `go get` is undone by `go mod tidy`). This stops parallel agents from colliding on dependency-manifest files.

## Phase 1 — Decompose into atomic issues

Read the plan. Carve it into the smallest tasks that each deliver a testable unit. For each task write a GitHub issue containing:

- **Title:** `T<NN>: <imperative summary>`
- **Goal:** one sentence.
- **Scope:** exact files/packages, function signatures, and behavior. Be specific enough that an implementer needs no further design decisions.
- **Acceptance criteria:** a checklist the reviewer can mechanically verify (commands to run + expected results).
- **Files touched:** so you can spot overlap for parallelization.
- **Depends on:** other T<NN> tasks.

Batch-create with `gh issue create`. Record the dependency graph — it drives ordering and parallelism.

## Phase 2 — Implement loop

Process tasks in dependency order. For each task (or batch of mutually-exclusive tasks):

1. **Worktree:** `git worktree add /workspace/.claude/worktrees/t<NN>-<slug> -b t<NN>-<slug> main`
   (`.claude/worktrees/` is gitignored.)
2. **Dispatch implementer** via the Agent tool, `model: opus`, with `run_in_background: true` when parallelizing. The prompt must include: the working directory (the worktree path), the full issue scope, acceptance criteria, test requirements (unit + gated e2e), and exact delivery steps (stage explicit paths, commit message ending in `Closes #<issue>`, push branch, open PR). Tell it to verify every acceptance criterion locally before opening the PR and to report PR URL + per-criterion evidence.
3. **Dispatch reviewer** (fresh Opus agent) once the PR exists. It creates its own review worktree from `origin/<branch>`, re-runs every acceptance check independently, may write its own scratch test, then posts `gh pr review <n> --comment` ("LGTM") or `--request-changes` with specific fixes. It cleans up its worktree.
4. **On request-changes:** dispatch a small fix agent against the *same* branch/worktree with the reviewer's exact feedback, then re-review.
5. **On LGTM:** merge.

## Parallelization rule

Run tasks concurrently **only if they are mutually exclusive** — no shared source files and no shared dependency manifest changes. Different packages/directories are the safe unit. Launch parallel implementers in a single message (multiple Agent calls with `run_in_background: true`); you're notified as each finishes. Serialize anything that touches the same files. When in doubt, serialize.

## Merge + close

```bash
gh pr merge <n> --repo <owner>/<name> --squash --delete-branch
git fetch origin main && git pull --ff-only origin main
git worktree remove /workspace/.claude/worktrees/t<NN>-<slug> --force
```

Verify the issue auto-closed (`gh issue view <n> --json state`). If not, close it manually.

The loop is done when every task issue is **closed** via a merged PR, and `go build ./... && go test ./... -race` (or the project's equivalent) is green on `main`.

## Tracking

Use TaskCreate/TaskUpdate to mirror progress: one tracking task per T<NN> (implement+review+merge), marked `in_progress` on dispatch and `completed` on merge. Keeps the run auditable across the long-running loop.

## Gotchas (learned the hard way)

- **`cd` does not persist between Bash tool calls.** Put `cd <dir> && …` in the *same* command, or use `git -C <dir>`. A multi-step rebase resolution must be one chained command.
- **`go mod tidy` removes unused requires.** Pre-installing a dep only sticks if real code imports it. Either add the import in the same commit or accept that each implementer adds its own dep (then expect manifest conflicts at merge).
- **Parallel agents in the same package can pick the same symbol name** (e.g. two `var dialFn`). Tell each implementer a unique name, or reconcile during the second merge. A duplicate package-level declaration is a build break that tests on an isolated branch won't catch.
- **GitHub blocks self-approval.** When the bot authored the PR, reviewers must use `gh pr review --comment` with explicit "LGTM" text, not `--approve`.
- **Only `Closes/Fixes/Resolves #N` auto-close issues.** "Implements #N" does not. Verify state after merge.
- **Rebase, don't merge-commit, to resolve drift.** When `main` moved under a feature branch: `cd <worktree> && git fetch origin main && git rebase origin/main`, resolve manifest conflicts by taking `main`'s version then re-running the dep install + tidy, then `git push --force-with-lease`.
- **Reviewers must reproduce, not trust.** The reviewer re-runs acceptance checks from a clean checkout and writes an independent smoke test; it never relies on the implementer's claims.
- **Keep cross-task contracts consistent.** File paths, interfaces, and config keys agreed in one task must match the consumers in later tasks — call this out explicitly in reviewer prompts (it caught a real path-mismatch bug here).

## Subagent prompt skeletons

**Implementer:**
> You are implementing Issue #<n> (T<NN>) of <repo>. Work only in `<worktree-path>` (branch `t<NN>-<slug>` off main). [Project context]. [Exact scope from the issue]. [Acceptance criteria]. Write unit tests; add an e2e test gated behind an env/build flag if real infra is needed. Verify every acceptance criterion locally. Then: stage explicit paths, commit with `Closes #<n>`, push `-u origin t<NN>-<slug>`, open a PR with summary + test plan. Report the PR URL and per-criterion pass/fail evidence.

**Reviewer:**
> Senior reviewer for <repo>. Review PR #<n>. Create a review worktree from `origin/t<NN>-<slug>`. Read the issue and the diff. Independently re-run every acceptance check; write your own scratch smoke test. Verify [task-specific correctness/security points]. Post `gh pr review <n> --comment` with "LGTM" if all pass, else `--request-changes` with specific line-level fixes. Remove your worktree. Report verdict + per-criterion evidence + blockers.
