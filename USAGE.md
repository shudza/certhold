# Certhold — Usage

A homelab SSH access manager. Run one Go binary on the bastion; every other Linux box just needs OpenSSH and curl.

## Install

```bash
git clone https://github.com/shudza/certhold && cd certhold
make build       # → ./bin/certhold
sudo cp ./bin/certhold /usr/local/bin/
```

## Mode selection

Certhold supports two install layouts:

- **User-mode (default)** — peers install five files under `~<user>/.ssh/`. A single `cert-authority,principals="..."` line in `authorized_keys` handles inbound access. No `/etc/ssh/` edits, no sshd reload. Revoke rotates the CA (skipping the revoked peer) since there is no native KRL.
- **Root-mode (`--mode root`)** — the v1 layout (T01–T14): files in `/etc/ssh/`, sentinel-bracketed sshd_config edits, native KRL revocation, sshd reload on every change.

Both modes coexist on the same manager — each peer row records its own mode. Pick per-peer at `enroll` time (default user-mode); pick for certhold itself at `init` time.

## Quick start

On the manager box (one-time setup):

```bash
certhold init                                    # default: user-mode, --user root
# Detected network interfaces:
#   [1] eth0     192.168.1.205
#   [2] wlan0    10.0.0.7
#
# Which interface should peers reach certhold on? [1-2]: 1
# certhold initialized
#   ...
#   base url:       https://192.168.1.205:8443
certhold serve --addr :8443                      # leave running (systemd unit recommended)
# certhold serve listening (TLS, self-signed) on https://[::]:8443
# cert SHA256: SHA256:abc...
```

Onboard a peer (run on the manager):

```bash
certhold enroll new-vm --groups infra,databases
# prints: curl -kfsSL https://192.168.1.205:8443/enroll/<token>.sh | bash
```

Paste that one-liner on the new peer as the user that should own certhold's SSH files (often a regular user; use `sudo -i` first if you want it owned by root). The install script computes `id -un` at runtime and reports it to the manager, then untars five files into `$HOME/.ssh/`. No `chown`, no root required. No sshd reload; the next inbound SSH connection from another peer matches the new `authorized_keys` line.

## Data layout

After `init`, the manager's state lives under `--data-dir` (default `~/.certhold`):

**User-mode (default):**

```
~/.certhold/
├── ca/                            # CA private + public
├── self/home/<user>/.ssh/         # certhold's own SSH files (user-mode layout)
│   ├── id_ed25519
│   ├── id_ed25519-cert.pub
│   ├── authorized_keys
│   ├── known_hosts
│   └── config
└── state.db                       # SQLite — peers, groups, tokens, KRL version
```

Copy the contents of `self/home/<user>/.ssh/` to the real `~<user>/.ssh/` on the manager.

**Root-mode (`certhold init --mode root`):**

```
~/.certhold/
├── ca/
├── self/etc/ssh/                  # root-mode layout
│   ├── peer_ed25519
│   ├── peer_ed25519-cert.pub
│   ├── ca.pub
│   ├── ca_known_hosts
│   ├── krl
│   ├── auth_principals/root
│   ├── sshd_config_block.conf
│   └── ssh_config_block.conf
└── state.db
```

In root mode, copy the contents of `<data-dir>/self/etc/ssh/sshd_config_block.conf` and `ssh_config_block.conf` into your `/etc/ssh/sshd_config` and `/etc/ssh/ssh_config` (paste verbatim between the `# BEGIN certhold` / `# END certhold` sentinels), and copy the remaining files to `/etc/ssh/`. Reload sshd.

## Commands

### `certhold init`

Bootstrap the manager.

```
certhold init [--hostname <name>] [--mode user|root] [--user <name>]
              [--listen-ip <ip>] [--port <port>] [--no-prompt]
```

- Refuses to overwrite an existing `state.db`.
- `--hostname` overrides `os.Hostname()` for the manager peer's name.
- `--mode` defaults to `user`; pass `--mode root` for the v1 layout.
- `--user` defaults to `root`; ignored when `--mode=root`.
- During init, certhold enumerates local IPv4 interfaces (skipping loopback / `docker*` / `br-*` / `veth*` / `virbr*` / `tun*` / `tap*` / `cni*`) and prompts you to pick the one peers will reach the manager on. Use `--listen-ip <ip>` to skip the prompt (CI / scripted setup). `--port` (default `8443`) is the port baked into the persisted base-url. `--no-prompt` fails fast on ambiguity (multiple candidates, no `--listen-ip`) and auto-selects when there's a single candidate.
- The chosen `https://<ip>:<port>` is written to `<data-dir>/base_url` and echoed in the summary as `base url: …`. `enroll` uses this as its default. Re-init or edit the file by hand to change it.

Example:

```
$ certhold init --listen-ip 192.168.1.205 --no-prompt --mode root
certhold initialized
  data-dir:       /home/admin/.certhold
  db:             /home/admin/.certhold/state.db
  mode:           root
  ca fingerprint: SHA256:...
  self files:     /home/admin/.certhold/self
  base url:       https://192.168.1.205:8443
```

### `certhold serve`

Run the HTTPS enrollment endpoint.

```
certhold serve [--addr :8443] [--tls-cert FILE --tls-key FILE] [--hostname <name>]
```

- Two routes:
  - `GET /enroll/<token>.sh` — returns the install bash script (does **not** consume the token).
  - `GET /enroll/<token>` — returns a gzipped tarball with all peer files; consumes the token.
- Mode-aware: user-mode tokens return a 5-file tarball + `getent`/`chown` script; root-mode tokens return the 6-file tarball + sentinel-block edit script.
- By default, serves over HTTPS with a freshly-generated in-memory self-signed cert. The certificate's SHA-256 fingerprint is printed at startup so you can pin it out-of-band. Pass `--tls-cert`/`--tls-key` together to use your own cert (e.g. from Let's Encrypt or a private CA); passing only one errors out. Plain HTTP is not supported — the install script trusts the cert via `curl -k` because the enrollment token is the real auth.

### `certhold enroll`

Mint an enrollment token and print the onboarding one-liner.

```
certhold enroll <name> --groups a,b,c [--base-url URL] [--mode user|root] [--user <name>]
```

- `--mode` defaults to `user`; pass `--mode root` for the v1 layout.
- `--user` is optional. Omit it and the peer reports its own user via `id -un` at install time. Pass `--user <name>` to pin a specific user — the install request must match or the server returns 400 (token preserved). Ignored when `--mode=root`.
- `--base-url` resolution order: explicit `--base-url` flag > `$CERTHOLD_BASE_URL` env var > `<data-dir>/base_url` (written by `init`) > `https://certhold.home.lan` (legacy fallback).

### `certhold list`

```
certhold list --peers      # NAME | GROUPS | ALLOWED | REVOKED | LAST_KRL
certhold list --groups
```

### `certhold update`

```
certhold update <name> --groups a,b,c [--host HOST]
```

- **User-mode peer**: pushes the new cert to `~<user>/.ssh/id_ed25519-cert.pub` and runs a health check. No sshd reload.
- **Root-mode peer**: pushes to `/etc/ssh/peer_ed25519-cert.pub`, reloads sshd, then runs health check.
- Mode is taken from the peer's DB row — no flag.

### `certhold group allow` / `certhold group disallow`

Manage *incoming* access on a peer.

```
certhold group allow <group> --on <peer> [--host HOST]
certhold group disallow <group> --on <peer> [--host HOST]
```

- Idempotent: re-allowing or disallow-missing exits 0 without pushing.
- `manager` is always implicit and cannot be removed.
- **User-mode peer**: SSH in, `cat` the existing `authorized_keys`, rewrite the matching cert-authority line's `principals="..."` substring, atomic-write back. No sshd reload.
- **Root-mode peer**: rewrites `/etc/ssh/auth_principals/root` and reloads sshd.

### `certhold revoke`

```
certhold revoke <name> [--hostname <manager-name>]
```

- Marks the peer revoked in the DB.
- **User-mode peer**: triggers a partial CA rekey that reissues a new cert + rewrites `authorized_keys` on every other peer (skipping the revoked one). Heavy but correct — there is no native KRL in user-mode. `--hostname` is the manager's own peer name; defaults to `os.Hostname()`.
- **Root-mode peer**: regenerates the KRL binary (`ssh-keygen -k`) and pushes `/etc/ssh/krl` to every non-revoked root-mode peer.
- **Mixed fleets**: a user-mode revoke also rotates the CA for root-mode peers (their rekey branch handles `ca.pub` updates). A root-mode revoke does NOT propagate to user-mode peers — the revoked peer's cert is still trusted by them until the next CA rotation. Use `certhold rekey` if your fleet is mixed and you need both populations to drop a revoked cert immediately.

### `certhold rekey`

```
certhold rekey [--hostname <name>]
```

- Generates a new CA, reissues every peer's cert against it, then per-peer:
  - **User-mode**: pushes a new `authorized_keys` (with the new CA on the cert-authority line) and a new `id_ed25519-cert.pub`. No sshd reload.
  - **Root-mode**: pushes `ca.pub` + the new cert, reloads sshd.
- Certhold's own peer is rekeyed **last** under both modes.

## Concepts

**Peer**: any Linux box with OpenSSH. After enrollment it has a CA-signed cert in either `/etc/ssh/` (root-mode) or `~<user>/.ssh/` (user-mode) and needs no further software.

**Group**: a string. A peer can be a *member* of groups (its cert lists them as principals) and can *allow* groups for incoming SSH (in user-mode, on its `authorized_keys` cert-authority line; in root-mode, in `/etc/ssh/auth_principals/root`).

**`manager` principal**: certhold's own peer has this principal. Every peer's `authorized_keys` (user-mode) or `auth_principals/root` (root-mode) starts with `manager`, giving certhold standing root access for pushes.

**No expiry**: certs are issued without `-V`. Revocation is the kill switch.

## Typical operations

Onboard one peer (user-mode default):

```bash
certhold enroll vm1 --groups infra
# ssh into vm1, paste the printed one-liner
```

Add a peer to a group (membership change):

```bash
certhold update vm1 --groups infra,databases
# user-mode: certhold ssh's into vm1, replaces the cert. No sshd reload.
# root-mode: same, plus systemctl reload sshd.
```

Open one host to a new group (incoming access change):

```bash
certhold group allow databases --on vm1
# user-mode: certhold ssh's into vm1, rewrites the principals="..." substring in authorized_keys. No sshd reload.
# root-mode: certhold ssh's into vm1, edits /etc/ssh/auth_principals/root, reloads sshd.
```

Revoke a peer:

```bash
certhold revoke vm1
# user-mode: rotates the CA; every remaining peer gets a new cert + new CA in authorized_keys / ca.pub.
# root-mode: KRL regenerated; pushed to every remaining root-mode peer.
```

Rotate the CA after a suspected key leak:

```bash
certhold rekey
# every peer gets a new cert; old CA is retired.
```

## Troubleshooting

| Symptom | Likely cause |
|--|--|
| `certhold revoke` errors with `ssh-keygen not found` (root-mode peers only) | Install `openssh-client` on the manager. |
| Push fails with `ssh: handshake failed` | Peer's host key changed — update the manager's `known_hosts` / `ca_known_hosts`. |
| `update`/`group` health check fails on a user-mode peer | Inspect the peer's `~<user>/.ssh/authorized_keys` and `id_ed25519-cert.pub`; check sshd's `journalctl` for auth errors. |
| `init` errors `state db already exists` | `<data-dir>/state.db` exists. Move it aside or use a different `--data-dir`. |

## Design

See `PLAN.md` for the architectural design, data model, blast-radius discussion, and the user-mode vs root-mode trade-offs.
