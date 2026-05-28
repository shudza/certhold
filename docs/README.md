# Certhold documentation

Certhold is an SSH access manager for private networks, built around a single SSH
Certificate Authority. Every device — including certhold itself — is a "peer"
holding a CA-signed certificate; access is granted by group-principal matching,
enforced natively by `sshd`.

- [architecture.md](architecture.md) — the trust model (one CA, the `manager`
  principal, no-expiry certs, the single user-level trust model where managing
  root is `--user root`), the two components, the data directory, and OpenSSH/host
  requirements.
- [usage.md](usage.md) — installing, bootstrapping the manager, onboarding peers,
  and the full command reference with flags and environment variables.
- [maintenance-and-operations.md](maintenance-and-operations.md) — the push
  model, and the revocation and CA-rekey procedures (including their failure and
  recovery semantics).
- [data-model.md](data-model.md) — the SQLite schema.
- [peer-file-layout.md](peer-file-layout.md) — the exact files installed on a
  peer under the target user's `~/.ssh/`, and the keyed `config` block.
- [security.md](security.md) — trust-root blast radius, at-rest passphrase
  protection, the prompt matrix, the install-side per-peer passphrase, and
  `--no-passphrase`.
