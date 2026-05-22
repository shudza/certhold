# Certhold — Usage

A homelab SSH access manager. Run one Go binary on the bastion; every other Linux box just needs OpenSSH and curl.

## Install

```bash
git clone https://github.com/shudza/certhold && cd certhold
make build       # → ./bin/certhold
sudo cp ./bin/certhold /usr/local/bin/
```

## Quick start

On the manager box (one-time setup):

```bash
certhold init                                    # generate CA, self-enroll
certhold serve --addr :8443                      # leave running (systemd unit recommended)
```

Onboard a peer (run on the manager):

```bash
certhold enroll new-vm --groups infra,databases
# prints: curl -fsSL https://certhold.home.lan/enroll/<token>.sh | bash
```

Paste that one-liner on the new peer as root. The peer's `sshd` is reloaded and the peer is now reachable by any other peer in `infra` or `databases`.

## Data layout

After `init`, the manager's state lives under `--data-dir` (default `~/.certhold`):

```
~/.certhold/
├── ca/
│   ├── ca                         # CA private key (0600)
│   └── ca.pub                     # CA public key
├── self/etc/ssh/                  # certhold's own SSH files
│   ├── peer_ed25519
│   ├── peer_ed25519-cert.pub
│   ├── ca.pub
│   ├── ca_known_hosts
│   ├── krl
│   ├── auth_principals/root
│   ├── sshd_config.d/certhold.conf
│   └── ssh_config.d/certhold.conf
└── state.db                       # SQLite — peers, groups, tokens, KRL version
```

Copy/symlink the contents of `self/etc/ssh/` to the manager's actual `/etc/ssh/` to make it a real SSH peer, and reload sshd.

## Commands

### `certhold init`

Bootstrap the manager.

```
certhold init [--hostname <name>]
```

- Refuses to overwrite an existing `state.db`.
- `--hostname` overrides `os.Hostname()` for the manager peer's name.

### `certhold serve`

Run the HTTP enrollment endpoint.

```
certhold serve [--addr :8443] [--tls-cert FILE --tls-key FILE] [--hostname <name>]
```

- Two routes:
  - `GET /enroll/<token>.sh` — returns the install bash script (does **not** consume the token).
  - `GET /enroll/<token>` — returns a gzipped tarball with all peer files; consumes the token.
- TLS is optional; omit both flags for plain HTTP (dev only).
- Graceful shutdown on SIGINT/SIGTERM with a 10 s drain.

### `certhold enroll`

Mint an enrollment token and print the onboarding one-liner.

```
certhold enroll <name> --groups a,b,c [--base-url URL]
```

- Token is single-use, 256 bits, URL-safe base64.
- `--base-url` defaults to `$CERTHOLD_BASE_URL` or `https://certhold.home.lan`.
- The printed line is:
  ```
  curl -fsSL <base-url>/enroll/<token>.sh | bash
  ```

### `certhold list`

Inspect state.

```
certhold list --peers      # default: NAME | GROUPS | ALLOWED | REVOKED | LAST_KRL
certhold list --groups     # NAME | PEERS  (count)
```

`--peers` and `--groups` are mutually exclusive.

### `certhold update`

Reissue a peer's cert with new principals; push the new cert over SSH.

```
certhold update <name> --groups a,b,c [--host HOST]
```

- Errors on unknown or revoked peer.
- Push sequence: `WriteFileAtomic(/etc/ssh/peer_ed25519-cert.pub)` → `reload sshd` → health check.
- `--host` defaults to `<name>` (assumes the peer's hostname == the manager's record name).

### `certhold group allow` / `certhold group disallow`

Manage *incoming* access: which groups the peer's `auth_principals/root` accepts.

```
certhold group allow <group> --on <peer> [--host HOST]
certhold group disallow <group> --on <peer> [--host HOST]
```

- Idempotent: re-allowing or disallow-missing exits 0 without pushing.
- `manager` is always implicit and cannot be removed (it's prepended at file render time).
- File pushed: `/etc/ssh/auth_principals/root`, mode 0644.

### `certhold revoke`

Add a peer to the KRL and push the new KRL to every non-revoked peer.

```
certhold revoke <name>
```

- Marks the peer revoked in the DB.
- Regenerates the KRL binary via `ssh-keygen -k` (requires `ssh-keygen` on the manager's PATH).
- Pushes `/etc/ssh/krl` to each non-revoked peer. Per-peer failures are logged but do not abort the operation; `last_krl_version` in the DB is only bumped for successful pushes.

### `certhold rekey`

Rotate the CA. Generates a new CA, reissues every peer's cert against it, pushes `ca.pub` then the new cert to each peer, then swaps the local CA files. Certhold's own peer is rekeyed **last**.

```
certhold rekey [--hostname <name>]
```

- New CA is generated into `<data-dir>/ca.next` first.
- On any per-peer push failure: aborts; old CA stays active; `ca.next` is left on disk for forensics or manual resume.
- On success: old CA dir is moved to `<data-dir>/ca.old.<UTC-timestamp>`; `ca.next` becomes `ca`; DB `ca` table records the new active version.

## Concepts

**Peer**: any Linux box with OpenSSH. After enrollment it has a CA-signed cert in `/etc/ssh/` and needs no further software.

**Group**: a string. A peer can be a *member* of groups (its cert lists them as principals) and can *allow* groups for incoming SSH (its `auth_principals/root` lists them). The two relations are independent — a peer can be in `infra` without accepting incoming `infra` connections.

**`manager` principal**: certhold's own peer has this principal. Every peer's `auth_principals/root` starts with `manager`, which gives certhold standing root access to push updates. This is also the blast-radius cost — see PLAN.md "Blast radius mitigations".

**No expiry**: certs are issued with `ValidBefore = ssh.CertTimeInfinity`. Revocation is the only kill switch; use `certhold revoke` or `certhold rekey`.

## Typical operations

Onboard one peer:

```bash
certhold enroll vm1 --groups infra
# ssh into vm1, paste the printed one-liner
```

Add a peer to a group (membership change):

```bash
certhold update vm1 --groups infra,databases
# certhold ssh's into vm1, replaces the cert, reloads sshd
```

Open one host to a new group (incoming access change):

```bash
certhold group allow databases --on vm1
# certhold ssh's into vm1, edits auth_principals/root, reloads sshd
```

Revoke a peer:

```bash
certhold revoke vm1
# KRL regenerated; pushed to every remaining peer
```

Rotate the CA after a suspected key leak:

```bash
certhold rekey
# every peer gets a new cert + new ca.pub; old CA is retired
```

## Troubleshooting

| Symptom | Likely cause |
|--|--|
| `certhold revoke` errors with `ssh-keygen not found` | Install `openssh-client` on the manager. KRL generation shells out to it. |
| Push fails with `ssh: handshake failed` | Peer's host key changed (re-enrolled?) — update `<data-dir>/self/etc/ssh/ca_known_hosts` or re-init the peer. |
| `update`/`group`/`revoke` works but health check fails | sshd loaded the new config but rejected the new cert. Inspect `sshd -T` and journalctl on the peer. |
| `init` errors `data-dir already initialized` | `<data-dir>/state.db` exists. Move it aside or use a different `--data-dir`. |

## Design

See `PLAN.md` for the full architectural design, data model, and blast-radius discussion.
