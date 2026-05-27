# Maintenance & operations

This covers how certhold changes a peer after onboarding — the push mechanism
shared by every operation, then the two heaviest operations, **revocation** and
**rekey**. Command flags are in [usage.md](usage.md); the trust model is in
[architecture.md](architecture.md).

## The push model

Certhold has no agent on the peer. Every state change — a reissued cert, an
updated principals list, a fresh KRL, a rotated CA — is delivered by SSHing into
the peer and writing files. The shape is the same for all commands:

1. Mutate local state (DB and/or CA) first.
2. SSH into the peer using **certhold's own peer cert and key** (the `manager`
   identity minted at `init`). This is the only authentication certhold has to a
   peer — no passwords, no per-peer credentials.
3. Write each file via a **staging path then atomic rename**: the content is
   written to `<target>.staging` beside the target, then `mv -f` (a same-filesystem
   `rename`) moves it into place, so `sshd` never sees a half-written file. On
   error the staging file is removed.
4. **Reload `sshd`** — root-mode peers only. User-mode peers need no reload
   (`authorized_keys` and the referenced cert are read per connection).
5. **Verify** the connection still works with a quick health check.

### Host-key trust on the push

The push connection verifies the peer's host key strictly (not blind
trust-on-first-use). The manager's trust file is seeded at `init` with a single
CA line:

```
@cert-authority * <ca.pub>
```

so the manager trusts any host presenting a host key signed by the certhold CA,
rather than pinning one key per host.

### Encrypted manager key

If the manager's peer key is passphrase-protected at rest, the push prompts for
its passphrase once and reuses it for the whole run (it is zeroed at exit). A
plaintext key never prompts. See [security.md](security.md).

### How commands use it

- **`update`** re-signs the peer's cert and pushes the new `*-cert.pub` (root
  mode also reloads).
- **`group allow`/`disallow`** rewrites the peer's inbound trust list — the
  `auth_principals/root` file (root mode) or the `principals="…"` value in
  `authorized_keys` (user mode) — and pushes it. This is the one command that
  reads remote state (the existing `authorized_keys`) before writing.
- **`revoke`** and **`rekey`** are multi-peer pushes, below.

### No retry queue

Multi-peer operations iterate peers in a plain loop. **There is no automatic
retry queue and no background reconciler.** A peer that is offline during a push
is handled per-command (logged and skipped by `revoke`; fatal for `rekey`), and
the way to catch it up is to **re-run the command manually**. Re-runs are
idempotent — the database tracks per-peer KRL state — but nothing retries on its
own. This is an accepted soft-consistency tradeoff: until an offline peer
receives an update it keeps acting on its old state.

## Revocation

Revoking a peer makes certhold stop trusting that peer's certificate across the
fleet. `certhold revoke <name>` first sets the peer's `revoked` flag (persistent,
before any push, so the manager's view is correct even if a push fails), then
takes one of **two paths depending on the revoked peer's mode**. The revoked peer
itself is never contacted.

### Root-mode peers — KRL push

Root-mode peers carry `RevokedKeys /etc/ssh/krl` from day one (the file ships
empty). On revoke, certhold:

1. Rebuilds the KRL from the **certificate serials** of **all** currently-revoked
   peers (the KRL revokes serials, not keys; `ssh-keygen -k` produces a binary
   KRL tied to the CA public key). An empty serial set yields a valid empty KRL.
2. Allocates a new monotonic KRL version.
3. Pushes the new `/etc/ssh/krl` to every non-revoked root-mode peer (write,
   reload, verify), recording the delivered version per peer.

This is cheap and targeted. Per-peer push failures are logged and skipped; a
skipped peer keeps its old KRL version and **still accepts the revoked cert**
until a later KRL push reaches it (re-running `revoke` is the catch-up — it is
idempotent).

Because revocation keys on the certificate serial, reissuing a cert (`update`,
`rekey`) changes the serial; the KRL is always rebuilt from the live serials of
revoked peers, so it stays correct.

### User-mode peers — partial CA rekey

User-mode peers have no `RevokedKeys` directive and no KRL file — trust lives in
the `cert-authority` line in `authorized_keys`, with nowhere to push a revocation
list. So revoking a user-mode peer instead performs a **partial CA rekey**: it
rotates the entire CA and reissues every other peer, **excluding** the revoked
one. The revoked peer never receives a new cert, and its old cert was signed by
the now-retired CA, so it stops being accepted as the new CA propagates.

This is heavy — revoking one user-mode peer rolls the whole fleet — and, like all
rekeys, **fail-fast** (see below).

### Mixed fleets

The two paths do not bridge:

- A **root-mode revoke** pushes a KRL and skips user-mode peers; they do not learn
  of the revocation through it.
- A **user-mode revoke** triggers a full CA rotation, which in a mixed fleet also
  rolls root-mode peers (they receive the new CA + cert through their rekey
  branch).

If a fleet is mixed and you need both populations to drop a revoked cert
immediately, run `rekey`.

## Rekey

`certhold rekey` is the big-hammer rotation: a brand-new CA, a fresh cert for
**every** non-revoked peer, with certhold's own files rotated last. Reach for it
when the CA key may be compromised, or as periodic hygiene. (User-mode `revoke`
reuses this same engine with the revoked peer excluded.)

### What it does

1. Load the current (old) CA.
2. Generate a new CA into a staging location (`<data-dir>/ca.next`). If that
   already exists, rekey refuses to start — it is the guard against a
   half-finished previous run.
3. For each non-revoked peer except certhold: sign a new cert with the new CA and
   push it (root mode: new `ca.pub` + cert + reload; user mode: rewrite the
   `authorized_keys` `cert-authority` line with the new CA + push the new cert, no
   reload).
4. **Rotate certhold itself last**, writing its own new CA pub + self cert
   locally. Doing self last is what stops certhold from locking itself out
   mid-rotation — every peer still trusts the old-CA manager cert during the loop.
5. Atomically swap the CA directory (old CA archived to `ca.old.<timestamp>`, the
   new CA moved into place) and record a new active CA version.

The directory swap and version bump happen **after** every peer and self are
already on the new CA; until then the old CA is authoritative.

### Failure: fail-fast, not resumable

Rekey is **fail-fast**. The first peer that fails to push aborts the whole
operation immediately — there is **no rollback** of peers already rotated and
**no skip/retry**. It prints the list of peers already moved to the new CA.

A mid-loop abort leaves a **split fleet**: the already-pushed peers trust the new
CA, while certhold and the rest still hold the old CA — so those rotated peers
will reject certhold's (old-CA) manager cert on the next connection. This is a
genuinely degraded state requiring manual recovery.

It is **not automatically resumable.** The staged new CA (`ca.next`) is left on
disk on purpose (for forensics / manual recovery) and blocks the next `rekey`
until removed; removing it and re-running generates a *third* CA rather than
reusing the staged one. Recovery is manual, using the logged list of
already-rotated peers — either finish the rotation by hand (push the staged CA +
matching certs to the remaining peers and self, then swap and bump the version)
or roll the rotated peers back to the old CA.

### Passphrase across rotation

By default the new CA key inherits the old key's at-rest protection: if the old
key was encrypted, the same passphrase is reused (you type it once); if it was
plaintext, the new key is plaintext too. `--rotate-passphrase` prompts for a
fresh CA passphrase for the new key instead. It affects the **CA key only** —
the manager peer key's passphrase is never changed by rekey. See
[security.md](security.md#when-the-manager-prompts).

## Planned, not built

These appear in the design but are **not implemented**; treat them as future
direction:

- **Automatic retry / reconciler** for offline peers. Catch-up is a manual re-run.
- **Resume-from-`ca.next`** after a failed rekey. Recovery is manual.
- Reducing the standing `manager` blast radius (short-TTL per-operation certs,
  force-command) and moving the CA key off the bastion (TPM / hardware token /
  offline root). See [security.md](security.md).
