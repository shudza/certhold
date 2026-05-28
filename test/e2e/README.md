# certhold end-to-end test suite

A **real** end-to-end suite that exercises certhold's actual SSH trust behavior
against live OpenSSH `sshd` in containers — the part unit tests cannot cover
(they stub the pusher). It drives the full lifecycle (`enroll`, `update`,
`group allow/disallow`, `revoke`, `rekey`) and asserts on **real `ssh` exit
codes**, including peer→peer inbound trust.

## What it is

- A Go test gated behind the `e2e` build tag (`//go:build e2e`). The default
  `go build ./...` / `go test ./...` / `make test` never compile or run it.
- It orchestrates `docker compose` purely via `os/exec` — **zero new `go.mod`
  dependencies** (no testcontainers, no docker SDK).

## Prerequisites

- A working **Docker daemon** and the **`docker compose`** v2 CLI on `PATH`.
- Outbound network access for the image builds (`golang:1.25-alpine`,
  `alpine:3.20`).

It **cannot** run in an environment without Docker (e.g. the CI sandbox used by
the implementer/reviewer). On such a host only the static checks are meaningful:

```
gofmt -l test/
go vet -tags e2e ./test/e2e/...
go build -tags e2e ./test/e2e/...
```

## How to run

From the repo root:

```
make e2e
```

which is:

```
go test -tags e2e -count=1 -timeout 20m ./test/e2e/...
```

`TestMain` runs `docker compose up --build -d` before the suite and always
`docker compose down -v --remove-orphans` afterwards (even on failure/timeout).
Add `-v` to see the ordered step log:

```
go test -tags e2e -v -count=1 -timeout 20m ./test/e2e/...
```

## Topology

Three services on one user-defined bridge network (service names double as DNS
names); compose project name `certhold-e2e`:

```
            chnet (bridge)
   ┌──────────┬──────────┬──────────┐
   │ manager  │  peer1   │  peer2   │
   │ certhold │  sshd    │  sshd    │
   │ serve    │  (web01) │  (db01)  │
   └──────────┴──────────┴──────────┘
```

- **manager** — multi-stage image: builds `./cmd/certhold` in `golang:1.25-alpine`,
  runs it in `alpine:3.20`. Pushes use Go's `x/crypto/ssh` (no `sshd` needed); it
  also carries `openssh-client` so the harness can `ssh-keyscan` the peers.
- **peer1 / peer2** — `alpine:3.20` + `bash curl tar openssh openssh-client`,
  a `deploy` user, host keys via `ssh-keygen -A`, and `sshd -D -e` in the
  foreground. **`sshd_config` is never modified** — v2 user-mode trust lives
  entirely in `~deploy/.ssh/authorized_keys`, which stock OpenSSH honors.

The peers are enrolled under **names decoupled from their addresses** (`web01`
@ `peer1`, `db01` @ `peer2`) to also exercise the per-peer `address` feature.

## Environment variables (set in `docker-compose.yml`)

| Service | Var | Value | Why |
|---|---|---|---|
| manager | `CERTHOLD_BASE_URL` | `https://manager:8443` | The enroll one-liner must point peers at the `manager` DNS name. |
| manager | `CERTHOLD_CA_PASSPHRASE` | `e2e-ca-pass` | Non-interactive CA passphrase for `init`/`enroll`/`update`/`group`/`revoke`/`rekey`. |
| manager | `CERTHOLD_PEER_PASSPHRASE` | `e2e-ca-pass` | Manager peer-key passphrase for pushes. Same value: `init`'s default branch reuses the CA passphrase for the manager peer key. |
| peer1/2 | `CERTHOLD_NO_PASSPHRASE` | `1` | Leave each installed peer key **unencrypted** so peer→peer `ssh` is non-interactive (an encrypted key would prompt at `/dev/tty`). |

## Scenario sequence (assertions are live `ssh` exit codes)

The single ordered `TestE2E` shares state across `t.Run` steps:

1. **init + serve** — `certhold init --mode user --user deploy --listen-ip 0.0.0.0 --no-prompt`, then `certhold serve` in the background; wait for HTTPS :8443 and both peers' sshd.
2. **enroll web01 → install on peer1** — assert the namespaced identity files, the `cert-authority` line in `authorized_keys`, and the keyed `# BEGIN certhold <key> v2` block in `~/.ssh/config`.
3. **enroll db01 → install on peer2** — same assertions; then **seed the manager's outbound `known_hosts`** (see caveat below).
4. **`update web01`** exits 0 — proves manager cert-auth *into* peer1.
5. **group allow/disallow** — peer1→peer2 is non-zero before `group allow web --on db01`, zero after, non-zero again after `group disallow`.
6. **`update web01 --groups web,db`** — peer1→peer2 becomes zero (web01's cert now carries `db`, which db01 allows).
7. **`revoke db01`** (partial CA rekey) — peer1(new-CA cert)→peer2(db01, still old CA) is non-zero; `update db01` errors.
8. **`rekey`** — `update web01` still exits 0; bonus: an SSH presenting web01's **stashed pre-rekey cert** into peer1 (which rotated to the new CA) fails, proving old certs die.

## Important runtime caveats (read before running `make e2e`)

These are integration assumptions baked into the harness against the real
certhold source. If `make e2e` misbehaves, check these first:

1. **The manager's outbound `known_hosts` is seeded by the harness.**
   `sshpush.Dial` verifies the peer host key strictly via
   `knownhosts.New(self/home/deploy/.ssh/known_hosts)`. After a fresh **v2 user-mode**
   `init`, that file is **empty** (user mode ships no CA-signed host certs, so
   there is no `@cert-authority` seed line). Without seeding, **every**
   manager→peer push (`update`/`group`/`revoke`/`rekey`) would fail host-key
   verification. Step 3 runs `ssh-keyscan peer1 peer2` on the manager and appends
   the keys to that file, keyed by the **dial host** (the enroll `--address`,
   i.e. `peer1`/`peer2`). In a real deployment the operator is expected to seed
   the manager's host trust the same way (documented in
   `docs/maintenance-and-operations.md`).

2. **`deploy` account login.** The peer images create `deploy` with `adduser -D`
   (no password; password field `!`). Stock OpenSSH still allows pubkey/cert auth
   for such an account. If a future base image locks the account harder, cert
   auth could break — adjust `Dockerfile.peer`.

3. **`StrictModes` / permissions.** The install one-liner runs **as `deploy`** and
   creates `~/.ssh` 700 / `authorized_keys` 600; the Dockerfile tightens
   `/home/deploy` to 700 so sshd's `StrictModes` does not reject the keys.

4. **`serve` lifetime.** The test launches `certhold serve` with `setsid … &`
   inside the manager container and polls :8443 for readiness. If the manager
   image's shell lacks `setsid`, switch to `nohup`.

5. **Self-signed TLS.** `certhold serve` presents a self-signed cert; the install
   one-liner uses `curl -k`, and the readiness probe uses `curl -ksS`.
