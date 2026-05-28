# Maintenance & operations

This covers how certhold changes a peer after onboarding — the push mechanism
shared by every operation, then the two heaviest operations, **revocation** and
**rekey**. Command flags are in [usage.md](usage.md); the trust model is in
[architecture.md](architecture.md).

## The push model

Certhold has no agent on the peer. Every state change — a reissued cert, an
updated principals list, a rotated CA — is delivered by SSHing into the peer and
writing files. The shape is the same for all commands:

1. Mutate local state (DB and/or CA) first.
2. SSH into the peer using **certhold's own peer cert and key** (the `manager`
   identity minted at `init`), as the peer's `target_user` (`root` for a
   `--user root` peer). This is the only authentication certhold has to a peer —
   no passwords, no per-peer credentials.
3. Write each file via a **staging path then atomic rename**: the content is
   written to `<target>.staging` beside the target, then `mv -f` (a same-filesystem
   `rename`) moves it into place, so `sshd` never sees a half-written file. On
   error the staging file is removed.
4. **No `sshd` reload.** Trust lives in the target user's `~/.ssh/authorized_keys`
   and the referenced cert, both read by `sshd` per connection, so edits take
   effect immediately.
5. **Verify** the connection still works with a quick health check.

### Host-key trust on the push

The push connection verifies the peer's host key strictly via the manager's own
`known_hosts` (`<data-dir>/self/<home>/.ssh/known_hosts`) — **not** blind
trust-on-first-use. Because certhold does not sign host keys, that file starts
**empty**, so the operator must seed the manager's host trust for the peers it
pushes to, e.g.:

```
ssh-keyscan <peer-address> >> <data-dir>/self/<home>/.ssh/known_hosts
```

keyed by the address the manager dials (the `enroll --address` value, else the
peer name). Without seeding, every push fails host-key verification.

### Encrypted manager key

If the manager's peer key is passphrase-protected at rest, the push prompts for
its passphrase once and reuses it for the whole run (it is zeroed at exit). A
plaintext key never prompts. See [security.md](security.md).

### How commands use it

- **`update`** re-signs the peer's cert and pushes the new `*-cert.pub`.
- **`group allow`/`disallow`** rewrites the `principals="…"` value on the peer's
  `authorized_keys` `cert-authority` line and pushes it. This is the one command
  that reads remote state (the existing `authorized_keys`) before writing.
- **`revoke`** and **`rekey`** are multi-peer pushes, below.

### No retry queue

Multi-peer operations iterate peers in a plain loop. **There is no automatic
retry queue and no background reconciler.** A peer that is offline during a push
is skipped and reported as a *straggler* (`revoke`/`rekey` continue past an
unreachable peer), and the way to catch it up is to **re-run the command
manually**. Re-runs are idempotent — the database tracks per-peer cert serials —
but nothing retries on its own. This is an accepted soft-consistency tradeoff:
until an offline peer receives an update it keeps acting on its old state.

## Revocation

Revoking a peer makes certhold stop trusting that peer's certificate across the
fleet. `certhold revoke <name>` first sets the peer's `revoked` flag (persistent,
before any push, so the manager's view is correct even if a push fails), then
forces a **partial CA rekey**. The revoked peer itself is never contacted.

There is no native KRL (`RevokedKeys` is a `sshd_config` directive certhold never
uses): trust lives entirely in the `cert-authority` line in each peer's
`authorized_keys`, with nowhere to push a revocation list. So revocation is
**always** a partial CA rekey — it rotates the entire CA and reissues every other
peer, **excluding** the revoked one. The revoked peer never receives a new cert,
and its old cert was signed by the now-retired CA, so it stops being accepted as
the new CA propagates.

This reuses the [rekey](#rekey) engine with the revoked peer excluded, so it is
**resilient to unreachable peers** (see below): an offline peer becomes a
reported straggler instead of aborting the revoke. For each peer the rekey
rewrites only **this instance's** `cert-authority` line in `authorized_keys`
(matched by the old CA pubkey) and pushes the namespaced cert — other instances'
lines are preserved.

### Multi-instance peers

A peer can be managed by several certhold instances at once; each owns a separate,
key-namespaced `cert-authority` line and `config` block (see
[peer-file-layout.md](peer-file-layout.md#config--the-keyed-client-block)).
Revoke / rekey from one instance touches only that instance's lines and certs, so
the other instances keep managing the peer uninterrupted.

## Rekey

`certhold rekey` is the big-hammer rotation: a brand-new CA, a fresh cert for
**every** non-revoked peer, with certhold's own files rotated last. Reach for it
when the CA key may be compromised, or as periodic hygiene. (`revoke` reuses this
same engine with the revoked peer excluded.)

### What it does

1. Load the current (old) CA.
2. Generate a new CA into a staging location (`<data-dir>/ca.next`). If that
   already exists, rekey refuses to start — it is the guard against a
   half-finished previous run.
3. For each non-revoked peer except certhold: sign a new cert with the new CA and
   push it — rewrite this instance's `authorized_keys` `cert-authority` line with
   the new CA pubkey and push the new namespaced cert (no `sshd` reload). A peer
   that cannot be reached is skipped and recorded as a straggler (see below)
   rather than aborting the rotation.
4. **Rotate certhold itself last**, writing its own new CA pub + self cert
   locally. Doing self last is what stops certhold from locking itself out
   mid-rotation — every peer still trusts the old-CA manager cert during the loop.
5. Atomically swap the CA directory (old CA archived to `ca.old.<timestamp>`, the
   new CA moved into place) and record a new active CA version.

The directory swap and version bump happen **after** every reachable peer and
self are already on the new CA; until then the old CA is authoritative.

### Unreachable peers: resilient, with reported stragglers

Rekey is **resilient to unreachable peers**. A peer whose push or dial fails
(host down, write/reload/verify failure) is **skipped and recorded as a
straggler**; the rotation continues. After the loop, certhold rotates **itself**
and **completes the CA swap and version bump** even if some peers were skipped, so
the reachable fleet plus the manager all converge on the new CA. The straggler's
DB `cert_serial` is **left untouched** (it still reflects the old cert it is
actually carrying), so a re-run knows it is out of date.

Rekey distinguishes this from a **logic/data error** — a group-lookup failure, an
unparseable `authorized_key` row, or a `SignCert` failure. Those indicate a real
bug or corrupt state, not a down host, so they still **abort** the whole rotation
(CA not swapped, the staged `ca.next` left on disk) and print the list of peers
already rotated for manual recovery.

**Exit contract.** A rekey/revoke that finishes for the reachable fleet but
leaves stragglers **exits 0** (returns success), so a single down host does not
break automation. Stragglers are surfaced only through a prominent **stderr
warning** and the summary line — script around stderr or the per-peer DB serials,
not the exit code. A logic/data-error abort exits non-zero as before.

#### The straggler hazard (read carefully)

A peer that is unreachable *during* a rekey keeps trusting only the **old** CA
(its `cert-authority` line / `ca.pub` is not updated) and keeps its old cert,
while the manager's own cert is rotated to the **new** CA and the old CA is
archived. After the swap, the manager presents a *new*-CA cert that the straggler
does **not** trust → **the manager can no longer SSH into the straggler with cert
auth.** The straggler is not silently lost: rekey prints a multi-line warning to
stderr naming each unreached peer, stating they **still trust the previous CA and
were NOT rotated**, and naming the archived old CA directory to recover with.

#### Recovery via the archived old CA

The pre-rotation CA is archived to `<data-dir>/ca.old.<timestamp>` (the swap
renames the live `ca` dir there before moving `ca.next` into place; the name is in
the warning). To rotate a straggler once it is reachable again:

1. Mint a temporary manager cert from the **archived** CA key
   (`ca.old.<timestamp>/ca`) — the straggler still trusts that CA, so this cert
   can reach it.
2. SSH in with that cert and push the **new** CA trust (rewrite the
   `cert-authority` line / `ca.pub`) plus the peer's new cert.
3. Re-run `rekey` (or `update` for that one peer) so the manager re-signs and
   re-pushes; its DB `cert_serial` then catches up.

Re-running `rekey` from scratch is also valid but rolls a *fresh* CA across the
whole fleet again; targeted recovery via the archived CA is cheaper.

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
