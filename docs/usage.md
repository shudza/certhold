# Usage

This is the operator reference: how to install certhold, bootstrap the manager,
onboard peers, and the full command surface. For the trust model behind it see
[architecture.md](architecture.md); for day-to-day fleet operations (push,
revoke, rekey) see
[maintenance-and-operations.md](maintenance-and-operations.md).

## Installation

```bash
git clone https://github.com/shudza/certhold && cd certhold
make build                          # → ./bin/certhold
sudo cp ./bin/certhold /usr/local/bin/
```

Building needs Go. A peer needs only OpenSSH 6.5+ and `curl` (see
[architecture.md](architecture.md#requirements--compatibility)).

## Bootstrapping the manager

One-time setup on the manager box:

```bash
certhold init                 # generate the CA, self-enroll, pick the interface peers reach you on
certhold serve --addr :8443   # run the enroll endpoint over HTTPS (self-signed). Leave it running.
```

`init` generates the CA, self-enrolls certhold as its own peer (with the
`manager` principal), prompts once for an at-rest passphrase protecting the CA
and manager keys, picks the network interface peers will use, and persists a
base URL like `https://192.168.1.10:8443`. `serve` then runs the enrollment
endpoint and prints the self-signed cert's SHA-256 fingerprint.

A systemd unit for `serve` is recommended. The `serve` process never holds the
CA key, so it can run as an unprivileged, network-facing service.

### Activating the manager as a peer

`init` writes certhold's own peer files under `<data-dir>/self/`, but does not
install them into the manager host's live SSH config. The manager uses those
files directly for its outbound pushes, so the fleet works without this step —
but to make the manager itself reachable as a peer (or to use the issued cert
for ordinary `ssh` from it), put the self files in place:

- **User mode:** copy the contents of `<data-dir>/self/<home>/.ssh/` into the
  real `~<user>/.ssh/`.
- **Root mode:** splice `<data-dir>/self/etc/ssh/sshd_config_block.conf` and
  `ssh_config_block.conf` into `/etc/ssh/sshd_config` and `/etc/ssh/ssh_config`
  (verbatim, between the `# BEGIN certhold` / `# END certhold` sentinels), copy
  the remaining `self/etc/ssh/` files into `/etc/ssh/`, then reload `sshd`.

## Onboarding a peer

Onboarding is two commands. Run `enroll` on the manager to mint a token; it
prints a single one-liner:

```
$ certhold enroll app1 --groups infra,databases
curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
```

Paste that one-liner on the new peer, as the user who should own the SSH files.
That is the entire peer-side onboarding — the peer contacts no other peer, and
existing peers need no update (they already trust anything the CA signed).

What happens under the hood:

- `enroll` (on the manager) validates inputs, loads and unlocks the CA, generates
  the peer's keypair, signs its certificate (principals = the peer name plus its
  `--groups`), builds the install tarball, and stores it against the token row.
  This **sign-at-mint** step is the only thing that touches the CA key.
- The peer's `curl … | bash` fetches a small install script, then the tarball,
  unpacks it into place, and (in root mode only) splices the `sshd` config and
  reloads. In user mode nothing system-wide changes and there is no reload.

The one-liner is identical for both modes — the mode is recorded on the token,
and the server emits the right script. The `-k` accepts the self-signed TLS
cert; the enrollment token is the real authentication.

### Modes and the install user

- `--mode user` (default) installs under `~<user>/.ssh`; `--mode root` installs
  under `/etc/ssh`. See [architecture.md](architecture.md#operating-modes).
- In user mode the install user is, by default, **reported by the peer** at
  install time (`id -un`) and recorded back on the peer row. Pass
  `enroll --user <name>` to **pin** it: the install request must then match, or
  the server rejects it (the token is preserved, so it can be retried).

### Name vs. address

A peer's `name` is its **identity** (the cert key-id, a principal, the database
primary key); its `address` is **how certhold reaches it over SSH**. They are
decoupled: every push path (`update`, `group`, `rekey`, `revoke`'s fan-out) dials
the recorded address, falling back to the name when none is set. If a peer's name
isn't a resolvable/reachable hostname, pass `enroll --address <host-or-ip>` to
record the dial target up front. Otherwise the address is backfilled from the
source IP seen when the peer fetches its tarball at install (`X-Forwarded-For` is
not trusted, so behind a proxy or NAT use `enroll --address` explicitly).
`update`/`group --host` still override the address for a single invocation.

### Enroll endpoints

`certhold serve` exposes one route with two behaviors, keyed on a `.sh` suffix:

- **`GET /enroll/<token>.sh`** — returns the install script. The token is
  inspected, **not consumed**.
- **`GET /enroll/<token>`** — streams the pre-built tarball and **consumes** the
  token (the stored bundle is cleared in the same step, so it cannot be
  re-downloaded). User-mode requests carry a `?user=` parameter, added by the
  install script.

Status codes:

| Condition | Status |
|---|---|
| missing token | `400` |
| token not found | `404` |
| user mode: missing / invalid / mismatched `?user=` | `400` (token preserved) |
| token already consumed (re-fetch) | `410` |
| otherwise | `200` |

## Command reference

The binary is `certhold` with the subcommands below. Two persistent flags apply
to all of them:

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir` | `~/.certhold` | Holds `ca/`, the manager's own `self/` files, and `base_url`. |
| `--db` | `<data-dir>/state.db` | SQLite state database. Independent of `--data-dir` — set both if you relocate state. |

Passphrases are read no-echo from `/dev/tty`, or from an environment variable
checked first so automation never blocks. No flag ever takes a passphrase value.

| Variable | Used by | Effect |
|---|---|---|
| `CERTHOLD_CA_PASSPHRASE` | init, enroll, update, revoke, rekey | CA-key passphrase, non-interactive. |
| `CERTHOLD_PEER_PASSPHRASE` | update, group, revoke, rekey | Manager peer-key passphrase, non-interactive. |
| `CERTHOLD_BASE_URL` | enroll | Fallback enroll base URL when not pinned by `--base-url` or persisted at `init`. |

Which keys each command unlocks is summarized in
[security.md](security.md#when-the-manager-prompts).

### `init`

```
certhold init [--hostname <name>] [--mode user|root] [--user <name>]
              [--listen-ip <ip>] [--port <port>] [--no-prompt]
              [--no-passphrase] [--separate-passphrases]
```

Generates the CA, self-enrolls the manager, picks the enroll interface, persists
`base_url`. Refuses to overwrite an existing `state.db`. No SSH push.

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | OS hostname | Manager peer name (cert key-id and a principal). |
| `--mode` | `user` | Mode for the manager's own files. |
| `--user` | current OS user (user mode) | Unix user owning the manager's `~/.ssh`. Forced empty in root mode. |
| `--listen-ip` | — | IPv4 peers reach the manager on; skips the interactive interface picker. |
| `--port` | `8443` | Port baked into the persisted base URL. |
| `--no-prompt` | `false` | Fail instead of prompting for the interface (auto-selects a sole candidate). |
| `--no-passphrase` | `false` | Write both keys **unencrypted** after a typed `yes` confirmation. Not recommended — see [security.md](security.md#opt-out-certhold-init---no-passphrase). |
| `--separate-passphrases` | `false` | Prompt for two distinct passphrases (CA and manager key) instead of one shared. |

If exactly one usable (non-loopback, non-virtual) IPv4 interface exists it is
chosen automatically; otherwise `init` prompts unless `--listen-ip` / `--no-prompt`
is given.

### `enroll`

```
certhold enroll <name> --groups <a,b,c> [--base-url URL] [--mode user|root]
                [--user <name>] [--address <host>] [--hostname <name>]
```

Mints a one-time token, signs the peer cert (sign-at-mint), builds and stores the
install tarball, records the peer, and prints the onboarding one-liner. Errors if
a peer of that name already exists. No SSH push — the peer pulls its tarball from
`serve`.

| Flag | Default | Meaning |
|---|---|---|
| `--groups` | — (**required**) | Comma-separated groups for the new peer (≥1, deduped). |
| `--base-url` | persisted / fallback | Enroll base URL for the one-liner. Precedence: flag > `$CERTHOLD_BASE_URL` > the `base_url` persisted by `init` > `https://certhold.home.lan`. |
| `--mode` | `user` | Install mode for the peer's tarball. |
| `--user` | — | Pin the install user (user mode only); a hard constraint at install time. |
| `--address` | — | Network address (host or IP) certhold dials to reach this peer. Defaults to the source IP seen at install, then the peer name. See [Name vs. address](#name-vs-address). |
| `--hostname` | OS hostname | Host label for the root-mode `@cert-authority` entry. |

Unlocks the CA key (to sign); no manager-key prompt, since `enroll` does not push.

### `list`

```
certhold list [--peers | --groups]
```

Reads local state and prints a table. No push, no passphrase. Default (or
`--peers`): `NAME GROUPS ALLOWED REVOKED LAST_KRL`. `--groups`: groups with peer
counts. `GROUPS` is the peer's own membership; `ALLOWED` is who may connect into
it (see [data-model.md](data-model.md)).

### `update`

```
certhold update <name> --groups <a,b,d> [--host HOST]
```

Reissues the peer's cert with a new group set, then SSHes in and pushes the new
cert. Root-mode peers also get an `sshd` reload; user-mode peers do not. Runs a
post-push health check. Errors if the peer is unknown or revoked.

| Flag | Default | Meaning |
|---|---|---|
| `--groups` | — (**required**) | New comma-separated group set. |
| `--host` | the peer name | SSH host to push to. |

Unlocks the CA key (to sign) and the manager peer key (to push).

### `group allow` / `group disallow`

```
certhold group allow    <group> --on <peer> [--host HOST]
certhold group disallow <group> --on <peer> [--host HOST]
```

Changes which groups may **connect into** a peer (its inbound allow-list),
without reissuing the peer's cert. `allow` adds, `disallow` removes; both push
the rewritten trust file and run a health check (root mode also reloads `sshd`).
Idempotent — a no-op exits without pushing. `manager` is always implicit and
cannot be removed.

| Flag | Default | Meaning |
|---|---|---|
| `--on` | — (**required**) | Peer to update. |
| `--host` | value of `--on` | SSH host to connect to. |

Unlocks the manager peer key only (no CA signing).

### `revoke`

```
certhold revoke <name> [--hostname <manager-name>]
```

Marks the peer revoked, then cuts its cert off across the fleet. The mechanism
depends on the revoked peer's mode — root-mode peers get a KRL push, user-mode
peers force a partial CA rekey. Full mechanics and the mixed-fleet caveats are in
[revocation](maintenance-and-operations.md#revocation).

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | OS hostname | Manager's own peer name; used only on the user-mode rekey path. |

Unlocks the CA key and the manager peer key.

### `rekey`

```
certhold rekey [--hostname <name>] [--rotate-passphrase]
```

Rotates the CA: generates a new CA, reissues every non-revoked peer's cert,
pushes the new trust material to each, rotates certhold itself last, then
archives the old CA. See [rekey](maintenance-and-operations.md#rekey) for the
algorithm and its fail-fast recovery semantics.

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | OS hostname | Certhold's own peer name (must match the self row). |
| `--rotate-passphrase` | `false` | Prompt for a fresh CA passphrase for the new key instead of reusing the current one. Affects the CA key only. |

Unlocks the old CA key and the manager peer key; sets the new CA key's
passphrase (reused from the old, or fresh with `--rotate-passphrase`).

### `serve`

```
certhold serve [--addr :8443] [--tls-cert FILE --tls-key FILE]
```

Runs the HTTPS enroll endpoint that peers `curl` during onboarding. Long-running,
graceful shutdown on SIGINT/SIGTERM. TLS is always on: with no explicit cert it
generates a self-signed one and prints its SHA-256 fingerprint. Reads the state
db; never touches the CA key or prompts for a passphrase.

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `:8443` | Listen address. |
| `--tls-cert` / `--tls-key` | — | Use your own TLS cert/key. Must be supplied together. |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `revoke` errors with `ssh-keygen not found` (root-mode peers) | Install `openssh-client` on the manager — KRL generation shells out to `ssh-keygen`. |
| Push fails with `ssh: handshake failed` | The peer's host key changed; update the manager's host-trust file (`known_hosts` / `ca_known_hosts`). |
| `update` / `group` health check fails on a user-mode peer | Inspect the peer's `~<user>/.ssh/authorized_keys` and `id_ed25519-cert.pub`, and check `sshd`'s logs for auth errors. |
| `init` errors `state db already exists` | A `state.db` is already present; move it aside or use a different `--data-dir` / `--db`. |
