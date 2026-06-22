# Architecture

## Core model

Certhold has **one trust root and one kind of actor**. It runs an SSH
Certificate Authority (CA); every device on the network — including certhold
itself — is a *peer*. Each peer holds a CA-signed certificate whose principals
name the groups it belongs to, and access is granted purely by principal
matching, enforced natively by OpenSSH. No certhold daemon runs on a peer; the
peer's stock `sshd` does all enforcement against the trusted CA public key.

Three ideas cover the whole system:

- **One CA.** A single ed25519 key pair, generated at `init`. The public half is
  the trusted root distributed to every peer; the private half signs every
  certificate. Rotating it is the [`rekey`](maintenance-and-operations.md#rekey)
  operation.
- **No expiries.** Certificates are issued without an expiration. Revoking trust
  therefore requires an explicit revocation or a CA rotation, never a wait —
  see [revocation](maintenance-and-operations.md#revocation). (Cert TTLs are a
  possible future addition; nothing issues time-bounded certs today.)
- **Nothing resident on peers.** No certhold daemon or service runs on a peer;
  the only runtime dependencies are OpenSSH and `curl`. After onboarding, a
  push-managed peer is just files plus stock `sshd`, with all later changes
  pushed in by certhold over SSH. A [client-style peer](#client-style-peers-and-the-pull-channel)
  additionally keeps `certhold-cli`, a small bash script run on demand (never
  resident) to pull refreshed material from `serve`.

### Certhold is a peer

Certhold has no bespoke authentication mechanism to its peers. At `init` it
self-enrolls and obtains an ordinary CA-signed certificate that additionally
carries a privileged **`manager`** principal. Every push-managed peer is
configured to accept `manager` as a root-equivalent principal, so certhold
authenticates to peers exactly the way peers authenticate to each other: by
presenting a CA-signed cert with a matching principal. (Client-style peers
install no inbound trust line at all, so they accept neither `manager` nor any
group — see [below](#client-style-peers-and-the-pull-channel).)

`manager` is exclusive to certhold's own self-cert — peer certs carry only the
peer's name plus its groups, never `manager`. On the peer side, `manager` is
always listed first in the inbound trust list (the `principals="…"` value on the
`authorized_keys` `cert-authority` line) and cannot be edited away by a group
change. That standing access is what lets certhold SSH into any push-managed
peer to push updates. The blast radius of this arrangement is discussed in
[security.md](security.md).

Every certhold-issued certificate also carries the five standard OpenSSH
permission extensions (`permit-X11-forwarding`, `permit-agent-forwarding`,
`permit-port-forwarding`, `permit-pty`, `permit-user-rc`). Without them a cert
authenticates but every session fails with `PTY allocation request failed` and
forwarding is silently denied.

## Components

The system is two parts: the **certhold** binary on one machine, and the
**peers** it onboards. There is no broker, agent, or sidecar.

```
                                ┌─────────────────────────────────┐
                                │           certhold              │
                                │  ┌──────────┐  ┌────────────┐   │
                                │  │   CLI    │  │ HTTP /enroll│  │
                                │  └────┬─────┘  └─────┬──────┘   │
                                │       │              │          │
                                │  ┌────┴───────────┐  │          │
                                │  │  CA private    │  │          │
                                │  │     key        │  │          │
                                │  └────────────────┘  │          │
                                │  ┌────────────────┐  │          │
                                │  │  SQLite state  │  │          │
                                │  └────────────────┘  │          │
                                └────────┬────────────┬┴──────────┘
                                         │            │
                          ssh (own cert) │            │ https (enroll + pull tokens)
                                         │            │
                ┌────────────────────────┴────────────┴──────────────┐
                │                                                    │
                ▼                                                    ▼
        ┌──────────────┐                                     ┌──────────────┐
        │   peer A     │  ─── sshd (CA-signed) ──────────►   │   peer B     │
        │   peer cert  │     principal match on groups       │   peer cert  │
        └──────────────┘  ◄──────────────────────────────    └──────────────┘
```

**Certhold** is a single static Go binary serving two roles:

- An **administrative CLI** for every operation an operator runs — bootstrapping
  the CA, minting peer credentials, editing groups, and pushing state to peers
  over SSH. See [usage.md](usage.md).
- An **HTTP endpoint** exposed while `certhold serve` is running:
  `GET /enroll/<token>` hands a peer its install bundle during onboarding, and
  `GET /pull/<token>` (plus `GET /pull/<token>/rev`) serves refresh bundles to
  peers that pull updates via `certhold-cli` — see
  [the pull channel](#client-style-peers-and-the-pull-channel). It is a CA-less
  byte-server for both routes: certs are signed by the `enroll`/`update`/`rekey`
  CLI and stored in the database, so the long-running `serve` process never
  holds the CA key.

**Peers** are any Linux host running OpenSSH. A peer runs no certhold daemon;
after onboarding it has a fixed set of files under the target user's `~/.ssh/`
(see [peer-file-layout.md](peer-file-layout.md)) and needs no further
configuration. A push-managed peer's only ongoing relationship with certhold is
inbound: certhold SSHes in as `manager` to push updates when group membership or
trust state changes. A client-style peer's is outbound instead: it fetches its
refreshed material from `serve` on demand.

### Data directory

All manager state lives under one directory (`--data-dir`, default `~/.certhold`):

| Path | Contents |
| --- | --- |
| `ca/ca` | CA ed25519 private key, mode `0600` (passphrase-encrypted at rest by default) |
| `ca/ca.pub` | CA public key — the trusted root distributed to peers |
| `self/` | Certhold's own peer files, mirroring the user-mode peer layout (`self/<home>/.ssh/`) |
| `state.db` | SQLite database of peers, groups, and tokens (`--db`; defaults inside the data dir) |
| `base_url` | Enroll base URL chosen at `init`, reused by `enroll` |

These default into the operator's home, not a system path like `/etc` or `/var`.
The CA key and the manager's own peer key are encrypted at rest by default; see
[security.md](security.md). The SQLite schema is in
[data-model.md](data-model.md).

## The trust model (single, user-level)

Certhold has **one** trust model. A peer's inbound trust lives in a single
`cert-authority` line in the target user's `~/.ssh/authorized_keys` (a
[client-style peer](#client-style-peers-and-the-pull-channel) simply never gets
this line — it has no inbound trust at all):

```
cert-authority,principals="manager,<groups…>" ssh-ed25519 AAAA…CA_PUBKEY…
```

certhold never touches `sshd_config`, never signs host keys, and never reloads
`sshd`. The target user is chosen at `enroll`/`init` with `--user` and recorded
on the peer's row (the `target_user` column). The concrete file set is in
[peer-file-layout.md](peer-file-layout.md).

A single line carries everything a trust decision needs:

| Concern | How the line covers it |
|---|---|
| Which CA is trusted | the `cert-authority` option + the CA key on the line |
| Which principals are allowed | the inline `principals="manager,<groups…>"` option |
| Immediate effect, no reload | `sshd` reads `authorized_keys` per connection |

Granting or revoking a group just rewrites the `principals="…"` value in place;
`manager` is always kept first.

### Managing root is `--user root`

There is **no separate root mode**. To manage `root`, enroll with `--user root`
and run the install one-liner **as root**: the files land in `/root/.ssh/` and
the `cert-authority` line in `/root/.ssh/authorized_keys` grants root logins,
which stock `sshd` honors (`PermitRootLogin prohibit-password` or stricter still
allows pubkey/cert). Managing root is therefore the same flow as any user, run as
root — no `sshd_config` splice, no host certificate, no reload.

### Consequences of the user-level model

Two capabilities that would require editing `sshd_config` are intentionally out
of scope:

- **No host certificates.** certhold does not sign peers' *host* keys, so each
  peer's `known_hosts` starts empty and outbound connections bootstrap host trust
  via **trust-on-first-use** (TOFU). The manager learns each peer's host key
  **automatically at enroll time** (an outbound capture dial run from `serve`
  right after the install), so the first push works with no manual seeding;
  pushes themselves stay strict. See
  [maintenance-and-operations.md](maintenance-and-operations.md#host-key-trust-on-the-push).
- **No native KRL revocation.** `RevokedKeys` is a `sshd_config` directive, so it
  is not used. Instead the **default `revoke`** strips certhold off the (reachable)
  peer — its config block, identity files, and the cert-authority trust line — and
  then deletes its row, a clean decommission. For a **compromised or unreachable**
  peer, `revoke --rekey` does a **partial CA rotation** that reissues to everyone
  except the revoked peer and never contacts it. See
  [revocation](maintenance-and-operations.md#revocation).

### Multiple instances on one peer

Identity files and the inbound/outbound blocks are **namespaced by a per-instance
key** (16 lowercase hex chars in `meta.instance_key`), so several certhold
instances can manage the same peer without colliding. Each owns its own
key-namespaced `cert-authority` line and `config` block; the install appends/
rewrites only its own. See
[peer-file-layout.md](peer-file-layout.md#config--the-keyed-client-block).

## Client-style peers and the pull channel

A **client-style peer** is a configuration of a peer, not a second kind of
actor: it is enrolled with `enroll <name> --no-inbound` (alias `--client`) and
is otherwise an ordinary peer — same CA-signed cert, same name + group
principals, full outbound access to any peer that allows one of its groups. What
the flag changes is the inbound side and the delivery channel:

- **No inbound trust.** The install bundle ships no `cert-authority` line, so
  nothing — other peers or the manager — can SSH into it. It also gets no
  `peer_allowed_groups` rows, and `group allow … --on <client-peer>` is refused.
- **Never dialed.** Every push path skips `inbound=0` peers and prints
  `client peer <name>: changes pending until 'certhold-cli refresh' runs on it`.
- **Pull instead of push.** The peer fetches its own refreshed material from
  `serve` with `certhold-cli`, a small on-demand bash CLI installed at enroll
  time (`~/.local/bin/certhold-cli`).

This is the natural shape for laptops and workstations: machines that should
reach the fleet but expose nothing.

### Push vs pull delivery

| | Push (inbound peers) | Pull (client-style peers) |
|---|---|---|
| Transport | manager SSHes in with its `manager` cert | peer runs `certhold-cli refresh` against `serve` |
| Trigger | each mutating command, immediately | operator-initiated, on the peer |
| Credential | the manager's standing cert | a standing per-peer **pull token** |
| Material delivered | cert, `authorized_keys` line, keyed `config` block | cert + keyed `config` block (public material only) |

Both channels exist for every peer: every enroll mints a pull token and ships
`certhold-cli`, so a push-managed peer can also pull. For client-style peers the
pull channel is the *only* delivery path.

### The pull channel

Every `enroll` mints a standing **pull token**, stores it on the peer's row, and
writes it to the peer's `~/.ssh/certhold_<key>.conf` (mode `0600`).
`certhold-cli refresh` presents it to `GET /pull/<token>` and receives a
**refresh bundle**: the peer's latest signed certificate, the keyed `config`
block (with its `Host` aliases), the current `certhold-cli` script (the CLI
self-updates from it), and a manifest. The bundle contains **public material
only** — never a private key, never a `cert-authority` line.

`serve` stays CA-less on this route too: every (re)sign — `enroll`, `update`,
the `rekey`/`revoke` loop — persists the resulting cert bytes in the database
(`peers.cert`), and `serve` assembles the bundle from that stored, pre-signed
cert plus DB state. Unlike enrollment tokens, pull tokens are not consumed;
they answer until the peer is revoked:

| Condition | Status |
|---|---|
| unknown (or empty) token | `404` |
| peer revoked | `410` |
| peer has no stored cert (pre-feature enrollment) | `409` — re-enroll it or run `certhold update` on the manager |
| otherwise | `200` (`application/gzip`, `Cache-Control: no-store`) |

`GET /pull/<token>/rev` (same `404`/`410` rules) returns the current **fleet
revision** as plain text — a counter in `meta.fleet_rev` bumped once per
successful mutating command. `certhold-cli status` compares it against the
`LAST_REV` recorded at the peer's last refresh to render a cheap staleness
verdict without downloading the bundle.

### Serve lifecycle

This changes what `serve` is for: no longer just an onboarding endpoint hit
once per peer, it is the standing refresh source for every client-style peer.
Keep it running — `sudo certhold install` sets it up as a systemd service
(see [usage.md](usage.md#install)). While `serve` is down, nothing breaks
(certs do not expire); client-style peers just cannot pick up changes.

### Eventual consistency

Pull delivery is operator-initiated, so client-style peers are **eventually
consistent by design**: after a `rekey`, `revoke`, `update`, or group change,
a client-style peer keeps acting on its old material until someone runs
`certhold-cli refresh` on it — after a rekey that means it is locked out of the
fleet until then (see
[maintenance-and-operations.md](maintenance-and-operations.md#client-style-peers-under-rekey-and-revoke)).
The same honesty applies to the `Host` alias blocks on all peers: a reachability
change (a new peer, a changed address or allow-list) lands on each peer's config
at its **next push or pull**, not by broadcast — only peers a command actually
dials get the new block immediately.

## Requirements & compatibility

The effective floor is **OpenSSH 6.5 (2014)**, set by ed25519 keys and certs,
which certhold uses everywhere (peer keys, the CA key, and the `serve` TLS cert).
Everything else it relies on landed earlier:

| Feature | Since | Used by |
|---|---|---|
| `cert-authority` + `principals="…"` options in `authorized_keys` | 5.6 (2010) | the inbound trust line (all peers, including root) |
| ed25519 keys and certificates | 6.5 (2014) | all keys/certs — the binding constraint |

certhold does **not** edit `sshd_config` at all, so it needs neither the
`Include` directive nor a `sshd_config.d/` drop-in (OpenSSH 8.2 / 2020): trust is
expressed entirely in the target user's `~/.ssh/authorized_keys`, which stock
OpenSSH honors per connection with no reload.

### Host tools

A peer needs an OpenSSH server and client plus the utilities the install script
calls:

| Tool | Used for |
|---|---|
| `bash`, `curl`, `tar` (+gzip) | run the install script, fetch and unpack the tarball |
| `id`, `mkdir`, `chmod`, `install` | resolve and lock down `~/.ssh`, place the files |
| `sed`, `cat`, `grep`, `awk` | append the `cert-authority` line and splice the keyed `config` block idempotently |
| `ssh-keygen` | optional peer-key passphrase encryption at install |

`certhold-cli` deliberately stays within the same era of tools: bash, `curl`,
`tar` (+gzip), `sed`, `grep`, `install`, `mktemp`, `cmp`, and `ssh-keygen` (to
print cert details in `status`).

No `systemd` and no `sshd` reload are involved on a peer. The `serve` endpoint
defaults to HTTPS with an auto-generated self-signed cert, so the install
one-liner uses `curl -k`; the certificate's SHA-256 fingerprint is printed at
startup for out-of-band pinning. The enrollment token is the real authentication.

### Distro coverage

Any host shipping OpenSSH 6.5+ is covered — essentially every Linux distribution
still receiving updates: RHEL/CentOS/Rocky/Alma 7+ (6.6.1), Debian 8+ (6.7),
Ubuntu 14.04+ (6.6), Fedora 21+, and current Arch/openSUSE. Because certhold
touches no system config and reloads nothing, there are no systemd or
privilege requirements beyond write access to the target user's home (running the
install as root for `--user root`).
