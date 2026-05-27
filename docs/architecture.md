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
- **No agents.** Peers run no certhold software. The only runtime dependencies
  on a peer are OpenSSH and `curl` (used once, at onboarding). After onboarding,
  a peer is just files plus stock `sshd`; all later changes are pushed in by
  certhold over SSH.

### Certhold is a peer

Certhold has no bespoke authentication mechanism to its peers. At `init` it
self-enrolls and obtains an ordinary CA-signed certificate that additionally
carries a privileged **`manager`** principal. Every peer is configured to accept
`manager` as a root-equivalent principal, so certhold authenticates to peers
exactly the way peers authenticate to each other: by presenting a CA-signed cert
with a matching principal.

`manager` is exclusive to certhold's own self-cert — peer certs carry only the
peer's name plus its groups, never `manager`. On the peer side, `manager` is
always listed first in the inbound trust list (the `authorized_keys`
`cert-authority` line in user mode, or `auth_principals/root` in root mode) and
cannot be edited away by a group change. That standing access is what lets
certhold SSH into any enrolled peer to push updates. The blast radius of this
arrangement is discussed in [security.md](security.md).

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
                          ssh (own cert) │            │ https (one-time tokens)
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
- An **HTTP enroll endpoint** (`GET /enroll/<token>`), exposed only while
  `certhold serve` is running and used by a peer exactly once during onboarding.
  It is a CA-less byte-server: certs are signed and bundled by the `enroll` CLI
  at mint time, so the long-running `serve` process never holds the CA key.

**Peers** are any Linux host running OpenSSH. A peer runs no certhold software;
after onboarding it has a fixed set of files (under `~/.ssh/` in the default
user mode, or `/etc/ssh/` in root mode — see
[peer-file-layout.md](peer-file-layout.md)) and needs no further configuration.
Its only ongoing relationship with certhold is inbound: certhold SSHes in as
`manager` to push updates when group membership or trust state changes.

### Data directory

All manager state lives under one directory (`--data-dir`, default `~/.certhold`):

| Path | Contents |
| --- | --- |
| `ca/ca` | CA ed25519 private key, mode `0600` (passphrase-encrypted at rest by default) |
| `ca/ca.pub` | CA public key — the trusted root distributed to peers |
| `self/` | Certhold's own peer files, mirroring the peer layout for the chosen mode |
| `state.db` | SQLite database of peers, groups, and tokens (`--db`; defaults inside the data dir) |
| `base_url` | Enroll base URL chosen at `init`, reused by `enroll` |

These default into the operator's home, not a system path like `/etc` or `/var`.
The CA key and the manager's own peer key are encrypted at rest by default; see
[security.md](security.md). The SQLite schema is in
[data-model.md](data-model.md).

## Operating modes

Each peer is installed in one of two **modes**, chosen at `enroll` (and at `init`
for certhold's own files) with `--mode` and recorded on the peer's database row.
The mode decides where files live, how inbound access is granted, and how
revocation works. **User mode is the default;** opt into root mode with
`--mode root`.

| | User mode (default) | Root mode (`--mode root`) |
|---|---|---|
| File location | `~<user>/.ssh/` | `/etc/ssh/` |
| Inbound access | one `cert-authority,principals="…"` line in `authorized_keys` | `TrustedUserCAKeys` + `AuthorizedPrincipalsFile` + `auth_principals/<user>` |
| `sshd_config` | untouched | sentinel block spliced in |
| `sshd` reload | never (read per-connection) | on every change |
| Privilege to install | unprivileged user's own home | root |
| Outbound host trust | TOFU via per-peer `known_hosts` | `@cert-authority` entry in `ca_known_hosts` |
| Revocation | partial CA rekey (no native KRL) | native KRL push |

Both modes are fully supported across every operation. The concrete file sets
are in [peer-file-layout.md](peer-file-layout.md).

### How user mode replaces root directives

User mode does the same job as root mode — "trust this CA, but only honour a
fixed set of principals" — without touching `sshd_config` or holding root. A
single line in the target user's `~/.ssh/authorized_keys` carries what root mode
splits across three `sshd_config` mechanisms:

```
cert-authority,principals="manager,<groups…>" ssh-ed25519 AAAA…CA_PUBKEY…
```

| Root-mode mechanism | What it does | User-mode equivalent |
|---|---|---|
| `TrustedUserCAKeys` | designates the trusted CA | the `cert-authority` option + the CA key on the line |
| `AuthorizedPrincipalsFile` | points at a per-user principals list | the inline `principals="…"` option |
| `auth_principals/<user>` | the actual allowed-principal list | the comma-separated value inside `principals="…"` |

Because `sshd` reads `authorized_keys` per connection, a user-mode principal
change takes effect immediately with no reload. Granting or revoking a group
just rewrites the `principals="…"` value in place; `manager` is always kept
first.

### What user mode gives up

Operating without root removes two `sshd_config`-only capabilities. Both gaps
are by design:

- **No host certificates.** Root mode signs the peer's host key and ships an
  `@cert-authority` line so peers verify each other's *server* identity through
  the CA. User mode cannot sign host keys, so its `known_hosts` starts empty and
  outbound connections fall back to **trust-on-first-use**.
- **No native KRL revocation.** `RevokedKeys` is a `sshd_config` directive, so it
  is unavailable in user mode. Revocation is instead a CA rotation that reissues
  to everyone except the revoked peer — see
  [revocation](maintenance-and-operations.md#revocation).

## Requirements & compatibility

The effective floor is **OpenSSH 6.5 (2014)**, set by ed25519 keys and certs,
which certhold uses everywhere (peer keys, the CA key, and the `serve` TLS cert).
Everything else it relies on landed earlier:

| Feature | Since | Used by |
|---|---|---|
| Certificate authorities, `TrustedUserCAKeys`, `HostCertificate`, `AuthorizedPrincipalsFile` (incl. `%u`), `@cert-authority` | 5.4 (2010) | root mode |
| `cert-authority` + `principals="…"` options in `authorized_keys` | 5.6 (2010) | user mode (its inbound trust line) |
| Binary KRLs, `RevokedKeys`, `ssh-keygen -k` | 6.0 (2012) | root-mode revocation |
| ed25519 keys and certificates | 6.5 (2014) | all modes — the binding constraint |

Crucially, certhold does **not** need the newer `Include` directive or a
`sshd_config.d/` drop-in directory (OpenSSH 8.2 / 2020). In root mode the install
script appends certhold's directives directly into `/etc/ssh/sshd_config` and
`/etc/ssh/ssh_config`, bracketed by `# BEGIN certhold` / `# END certhold`
sentinel markers — that is what keeps the floor at 6.5 instead of 8.2. User mode
edits no system config at all.

### Host tools

A peer needs an OpenSSH server and client plus the utilities the install script
calls:

| Tool | Used for | Mode |
|---|---|---|
| `bash`, `curl`, `tar` (+gzip) | run the install script, fetch and unpack the tarball | both |
| `ssh-keygen` | optional peer-key passphrase encryption at install | both |
| `id`, `mkdir`, `chmod` | resolve and lock down `~/.ssh` | user only |
| `sed`, `cat`, `systemctl` | splice the sentinel blocks and reload `sshd` | root only |

Root mode assumes a **systemd** host — the reload is `systemctl reload sshd`,
with no fallback. The manager itself additionally needs `ssh-keygen` on `PATH`
(used to build KRLs when revoking a root-mode peer).

The `serve` endpoint defaults to HTTPS with an auto-generated self-signed cert,
so the install one-liner uses `curl -k`; the certificate's SHA-256 fingerprint
is printed at startup for out-of-band pinning. The enrollment token is the real
authentication.

### Distro coverage

Any host shipping OpenSSH 6.5+ is covered — essentially every Linux distribution
still receiving updates: RHEL/CentOS/Rocky/Alma 7+ (6.6.1), Debian 8+ (6.7),
Ubuntu 14.04+ (6.6), Fedora 21+, and current Arch/openSUSE. The remaining
practical constraint for root-mode peers is the systemd `sshd` reload.
