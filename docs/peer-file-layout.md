# Peer file layout

The exact files certhold installs on a peer, with permissions and contents. The
layout depends on the peer's [mode](architecture.md#operating-modes). The tarball
is built and signed by `enroll` and delivered once during
[onboarding](usage.md#onboarding-a-peer). Tarball entries are reproducible
(ownership comes from the extracting user, not baked in).

## User mode

Everything lands under `~<target_user>/.ssh/`; certhold makes **no changes to
`sshd_config` and triggers no `sshd` reload**, so an unprivileged operator who
can write their own home can install it. Tarball paths are relative to that
directory.

| File | Mode | Contents |
|---|---|---|
| `id_ed25519` | `0600` | Peer's outbound private key (newly generated per enroll). |
| `id_ed25519-cert.pub` | `0644` | CA-signed user certificate for that key. |
| `authorized_keys` | `0644` | One `cert-authority` line granting inbound access (below). |
| `known_hosts` | `0644` | Outbound host trust; **empty** by default (TOFU). |
| `config` | `0644` | SSH client config (below). |

**`config`** is a fixed template pointing the client at the issued cert/key:

```
Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile ~/.ssh/id_ed25519
    UserKnownHostsFile ~/.ssh/known_hosts
```

**`authorized_keys`** is a single line — `manager` first (always, deduped), then
the peer's groups, followed by the CA public key:

```
cert-authority,principals="manager,infra,databases" ssh-ed25519 AAAA… certhold-ca
```

`manager` is what gives certhold standing inbound access; the group list is what
`group allow`/`disallow` and `update` rewrite in place on a live peer. Because
`sshd` reads `authorized_keys` per connection, these edits need no reload.

**Install script (user mode):** under `set -e`, it resolves the target user
(`id -un`) and home (`$HOME`), creates and `chmod 700`s `~/.ssh`, fetches and
unpacks the tarball (`curl -kfsSL …?user=<user> | tar -xz`), re-asserts `0600` on
the key, then runs the optional [peer-key passphrase
step](security.md#per-peer-passphrases-install-side). It does **not** edit any
system config and does **not** reload `sshd`.

## Root mode

The privileged layout (`--mode root`): the peer becomes a CA-trusting server
whose host key is also CA-signed, and certhold edits `/etc/ssh/sshd_config`.
Installing requires root and triggers an `sshd` reload. Tarball paths are
relative to `/` (the script untars with `tar -xzC /`).

| Path | Mode | Contents |
|---|---|---|
| `/etc/ssh/peer_ed25519` | `0600` | Peer's private key (host key + outbound identity). |
| `/etc/ssh/peer_ed25519-cert.pub` | `0644` | CA-signed certificate (principals = name + groups). |
| `/etc/ssh/ca.pub` | `0644` | CA public key — the trusted user-CA root. |
| `/etc/ssh/krl` | `0644` | Key Revocation List; **empty** at enroll, populated by `revoke`. |
| `/etc/ssh/auth_principals/root` | `0644` | One principal per line, `manager` first (below). |
| `/etc/ssh/ca_known_hosts` | `0644` | A single `@cert-authority <hostname> …` line for outbound SSH. |

**`auth_principals/root`** lists `manager` first, then one line per group:

```
manager
infra
databases
```

This is the root-mode analogue of the user-mode `cert-authority` line — the same
`manager`+groups set, expressed via OpenSSH's `AuthorizedPrincipalsFile`
mechanism. (Certhold does not write `/root/.ssh/authorized_keys`; root login is
granted entirely through `AuthorizedPrincipalsFile` + `TrustedUserCAKeys`.)

### Sentinel config blocks

The two config blocks are **not** tarball files — the install script splices them
into the peer's existing config. Into `/etc/ssh/sshd_config`:

```
# BEGIN certhold
HostKey /etc/ssh/peer_ed25519
HostCertificate /etc/ssh/peer_ed25519-cert.pub
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/krl
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
# END certhold
```

Into `/etc/ssh/ssh_config` (the client counterpart of the user-mode `config`):

```
# BEGIN certhold
Host *
    CertificateFile /etc/ssh/peer_ed25519-cert.pub
    IdentityFile /etc/ssh/peer_ed25519
    UserKnownHostsFile /etc/ssh/ca_known_hosts
# END certhold
```

**Install script (root mode):** under `set -e`, it unpacks the tarball, runs the
optional [peer-key passphrase step](security.md#per-peer-passphrases-install-side),
splices both blocks, then runs `systemctl reload sshd`. Each splice first deletes
any existing `# BEGIN certhold` … `# END certhold` range before appending, so
**re-running is idempotent** — the block is replaced, never stacked. This
sentinel approach (rather than a `sshd_config.d/` drop-in) is what keeps the
OpenSSH floor at 6.5; see
[architecture.md](architecture.md#requirements--compatibility).

### The manager's own files

At `init`, certhold writes the same set for itself under `<data-dir>/self/`,
mirroring the chosen mode. In root mode it additionally emits
`sshd_config_block.conf` and `ssh_config_block.conf` for the operator to splice
into the manager host by hand — `init` does not edit the manager's `sshd_config`
automatically.
