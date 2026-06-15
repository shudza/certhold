# certhold

Certificate-based SSH access manager for private networks. A single Go binary (the **manager**) runs an SSH CA and onboards **peers** with one pasted `curl … | bash`. Peers run no daemon — just OpenSSH plus a few files. Access is group-based: a cert names the groups a peer belongs to, and each peer declares which groups it accepts inbound SSH from.

Read `README.md` and `docs/architecture.md` before non-trivial work.

## Layout

- `cmd/certhold/` — entrypoint
- `internal/cli/` — cobra commands: `init`, `enroll`, `update`, `revoke`, `rekey`, `list`, `group` (create/show/rename/delete/allow/disallow), `serve`, `install`, `tui`
- `internal/ops/` — mutating business logic shared by CLI and TUI (enroll mint, group CRUD, update/revoke/rekey, events, `SessionUnlocker` for passphrase session)
- `internal/ca/` — SSH certificate authority
- `internal/db/` — SQLite state (`modernc.org/sqlite`, pure-Go, no cgo)
- `internal/httpserver/` — `/enroll`, `/pull/{token}`, `/rev`, `/healthz`
- `internal/sshpush/` — pushes config/certs to peers over SSH
- `internal/peerfiles/` — peer file layout, Host blocks, refresh bundles
- `internal/token/`, `internal/passphrase/`, `internal/clientcli/` (pure-bash `certhold-cli`), `internal/tui/` (bubbletea)
- `docs/` — architecture, data-model, security, usage, peer-file-layout, maintenance
- `test/e2e/` — docker-compose live-SSH suite (build-tag gated)

## Key concepts

- **Peers vs client-style peers**: normal peers accept inbound SSH and are dialed by the manager. Client-style peers (`enroll --client`, e.g. laptops) accept no inbound; the manager never dials them — they self-fetch renewed certs via `certhold-cli refresh` against `/pull/{token}`.
- **Groups are principals** on the cert; membership and allowed-inbound are edited centrally and pushed.
- **`fleet_rev`** tracks fleet config revision for staleness checks.
- Manager state lives in SQLite; the CA private key is passphrase-protected with a session unlocker.

## Build & test

- `make build` → `./bin/certhold`
- `make test` — unit tests (`go test ./...`); never runs e2e
- `make vet`, `make static` (cross-compiled stripped binaries → `./dist`)
- `make e2e` — docker-compose suite, build tag `e2e`, needs Docker daemon
- `make e2e-systemd` — host-mutating install test, tag `e2e_systemd`, needs systemd + passwordless sudo

Go 1.25. TUI uses charmbracelet (bubbletea/bubbles/lipgloss); CLI uses cobra.

## Conventions

- Each command/test file is paired (`enroll.go` + `enroll_test.go`); add tests alongside.
- Mutating logic goes in `internal/ops/` so CLI and TUI share one path — don't duplicate it in `internal/cli/`.
- Comments only for workarounds/unconventional code.
- **Docs describe behavior, not code internals.** `README.md` = *what it does* (keep the architecture/ascii section); `docs/*` stay compact and avoid quoting code or file/line refs that drift as code changes. Don't create parallel duplicates (there is no top-level `USAGE.md` — usage lives in `docs/usage.md`).
- **Read the whole spec/plan/file before acting** — skimming once dropped an entire section (user/root scoping) and required a redo.

## Gotchas (learned the hard way)

- **Green tests have shipped real bugs** (e.g. `init` not seeding the active CA version, so the DB reported uninitialized — "how was this ever able to pass any tests?"; the trust-root lockout below). After touching `init`/`enroll`/CA/serve, manually run the real binary and a peer-to-peer `ssh` — unit tests miss integration breakage.
- **CA trust-root lockout**: rekey/revoke flows can lock the manager out of its own fleet — a green test suite missed this once. Reason about who can still authenticate after a trust-root change; lean on the review gate.
- **Install payload must not embed the tarball**: `/enroll/<token>.sh` returns only a short bash script that *fetches* the binary tarball from its own endpoint — never inline the tarball into the served script (corrected repeatedly).
- **User-vs-root scoping is real**: `init --mode user` resolves a target user that differs per peer (laptop user ≠ root), so the enrolling peer reports it back during enrollment — don't assume root. Getting target-user detection wrong shipped twice.
- **Enroll is HTTPS with a self-signed cert**: `curl` the enroll URL with `https://` (and `-k`/pinned trust as documented); `http://` yields `SSL routines::wrong version number`.
- **Secrets in tests**: no tty in CI — inject CA passphrases via env vars or func-literals, never an interactive prompt.
- **e2e peer auth**: alpine `adduser -D` leaves a locked shadow password (`!`); OpenSSH without PAM refuses cert auth for locked accounts — peers must `passwd -d <user>`.
- **Running e2e here**: Docker is installable on this VM (passwordless sudo + systemd); run via `sg docker -c '…'`, and Bash calls touching the daemon need `dangerouslyDisableSandbox: true`.
- **Shell cwd is `/workspace` (= main branch)**: when verifying a worktree, `cd` into it inside the *same* compound command, else git/grep runs against main. `grep -c` returning 0 exits 1 and short-circuits `&&` chains.
- **Always re-run gates before merging** (build/vet/gofmt/test/`-race`) — don't trust a relayed "approved"; verify in the worktree yourself.

## Delivery

One feature = one GitHub issue = one squashed PR (auto-closes its issue), built in a git worktree. Commit/PR titles follow `T##: summary (#PR)`. See git log for the established style.
