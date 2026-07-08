# Maintenance & operations

This covers how certhold changes a peer after onboarding — the push mechanism
shared by every operation, the pull channel for client-style peers, then the two
heaviest operations, **revocation** and **rekey**. Command flags are in
[usage.md](usage.md); the trust model is in
[architecture.md](architecture.md).

## The push model

Certhold runs no daemon on the peer — nothing resident, only files (plus
`certhold-cli`, a small bash CLI run on demand). For push-managed (`inbound`)
peers, every
state change — a reissued cert, an updated principals list, a rotated CA — is
delivered by SSHing into the peer and writing files. (Client-style peers are
never dialed; they get [the pull channel](#the-pull-channel-client-style-peers)
instead.) The shape is the same for all commands:

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
trust-on-first-use at push time.

That file is populated **automatically at enroll time**. Right after a peer
redeems its install token, `serve` makes an outbound capture dial to the peer
(keyed by the address the manager dials — the `enroll --address` value, else the
peer's name), records the presented host key, and confirms the manager can reach
the peer for pushes. So the **first** `group allow`/`update`/`rekey` push works
with no manual `ssh-keyscan`. Verification at push time stays strict: pushes
never learn a new key.

Two cases still need a hand:

- **The manager cannot dial the peer back (non-bidirectional).** Enrollment
  *requires* peer→manager (the curl), so a peer behind NAT/a firewall, or one
  whose `--address` is unreachable from the manager, enrolls fine but cannot be
  pushed to. Such a peer is flagged **`push-unreachable`** and routed onto the
  [self-fetch (pull) channel](#the-pull-channel-client-style-peers): push
  commands skip dialing it and print the same pending-refresh notice as a
  client-style peer, and it picks up changes when `certhold-cli refresh` runs on
  it. `certhold list` shows its delivery as `push-unreachable,self-fetch`. The
  flag is set only by the enroll-time probe, and pushes intentionally skip the
  peer, so nothing re-probes it on its own — it stays on self-fetch even after
  reachability returns. **To restore manager-push delivery, re-enroll the peer**
  (which re-runs the probe and re-captures its host key). Automatic
  re-probe/recovery is planned but not yet built.
- **The peer's host key *changed* (reinstall), but the peer is still
  reachable.** A changed key is a `knownhosts: key mismatch` (distinct from the
  first-contact `key is unknown`), and the manager refuses it strictly rather
  than silently re-trusting it. Clear the stale entry by hand for now:

  ```
  ssh-keygen -R <peer-address> -f <data-dir>/self/<home>/.ssh/known_hosts
  ```

  then the next push re-captures the new key. (A `relearn` command to automate
  this is planned.)

If the manager's own peer key is passphrase-protected, the unattended enroll
probe reads the passphrase from `CERTHOLD_PEER_PASSPHRASE` (the same env the
`serve` systemd unit carries); without it the probe cannot dial and the peer is
recorded `push-unreachable`. As above, pushes then skip it, so recovery is to
re-enroll it once the passphrase is available (the probe re-runs and captures
the host key).

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

Every command that dials a peer also re-splices the peer's keyed `config` block
(its `Host` aliases) from current fleet state, and every command that (re)signs
a cert persists the cert bytes in the database — that stored cert is what the
pull channel serves.

> **TUI.** Every flow in this document has an equivalent in `certhold tui` (see
> [`tui`](usage.md#tui)), which runs the identical `ops` paths — `update` is `u`
> (or `i` for allowed-inbound), `revoke` is `x`, `rekey` is `K`, group CRUD is
> `n`/`R`/`D`/`m`, enroll is `e` — so the push model, passphrase handling, and
> straggler reporting described here apply unchanged. The TUI additionally
> batches `update`/`revoke`/membership over a multi-selected set of peers.

## The pull channel (client-style peers)

A [client-style peer](architecture.md#client-style-peers-and-the-pull-channel)
(`enroll --no-inbound`/`--client`) is never dialed. Every mutating command
treats it the same way: the DB-side change still lands in full (group rows
edited, cert re-signed and stored, fleet revision bumped), the SSH push is
skipped, and the command prints

```
client peer <name>: changes pending until 'certhold-cli refresh' runs on it
```

Delivery happens when someone runs `certhold-cli refresh` **on the peer**, which
pulls the stored material from `serve` (which must therefore be running — see
[usage.md](usage.md#serve)). Until then the peer keeps acting on its old cert
and config. There is no notification mechanism: staleness is visible on the
manager (the notice, and the fleet revision) and on the peer
(`certhold-cli status` reports `stale (run: certhold-cli refresh)`).

The same eventual consistency applies to `Host` alias blocks fleet-wide: a
reachability change (new peer, changed address, allow-list edit) reaches each
peer's `~/.ssh/config` at that peer's **next push or pull** — commands do not
fan out config to peers they would not otherwise dial.

### No retry queue

Multi-peer operations iterate peers in a plain loop. **There is no automatic
retry queue and no background reconciler.** A peer that is offline during a push
is skipped and reported as a *straggler* (`revoke`/`rekey` continue past an
unreachable peer), and the way to catch it up is to **re-run the command
manually**. Re-runs are idempotent — the database tracks per-peer cert serials —
but nothing retries on its own. This is an accepted soft-consistency tradeoff:
until an offline peer receives an update it keeps acting on its old state. The
pull channel has the same property from the other side: a client-style peer
keeps acting on its old state until someone runs `certhold-cli refresh` on it.

## Revocation

There is no native KRL (`RevokedKeys` is a `sshd_config` directive certhold never
uses): trust lives entirely in the `cert-authority` line in each peer's
`authorized_keys`, with nowhere to push a revocation list. Certhold therefore
offers two ways to take a peer out of the fleet.

**Default — `certhold revoke <name>` (clean decommission).** The manager SSHes
into the (reachable) peer and strips certhold from it: this instance's keyed
config block, its identity files (private key + cert), and its `cert-authority`
trust lines in `authorized_keys` — the active CA's line and any stale line left
by an archived pre-rekey CA — leaving other instances' lines untouched. Once
the peer is clean, its row is **hard-deleted** from the manager. Nothing else in
the fleet is touched, and the CA is not rotated. This is the everyday "retire a
machine" path. It requires the peer to be reachable and to accept inbound SSH:

- A **no-inbound/client peer** (e.g. a laptop, `enroll --client`) is never dialed
  by the manager, so `revoke` errors up front and deletes nothing — use
  `certhold remove <name>` (DB-only) or `revoke --rekey` instead.
- If the peer is **unreachable**, the clear fails and the row is **kept** (so the
  manager's view stays accurate); use `remove` or `--rekey`.

**`certhold revoke --rekey <name>` (compromised or unreachable peer).** This never
contacts the revoked host. It flags the row revoked, rotates the entire CA and
reissues a fresh cert to **every other** peer, then deletes the revoked row. The
revoked peer never receives a new cert, and its old cert was signed by the
now-retired CA, so it stops being accepted as the new CA propagates across the
fleet. Its standing pull token is refused once the row is gone
(`GET /pull/<token>` and `…/rev` answer `404`), so a client-style peer cannot
pull its way back in either. If the rotation fails before doing anything (e.g.
a wrong CA passphrase), the row is kept and stays flagged revoked: the peer
remains visible in `list`, its old cert is **still valid** until a rekey
succeeds, and re-running the same command retries.

`--rekey` reuses the [rekey](#rekey) engine, so it is **resilient to unreachable
peers** (see below): an offline remaining peer becomes a reported straggler
instead of aborting the revoke. For each peer the rekey rewrites only **this
instance's** `cert-authority` line in `authorized_keys` (matched by the old CA
pubkey) and pushes the namespaced cert — other instances' lines are preserved.

### Multi-instance peers

A peer can be managed by several certhold instances at once; each owns a separate,
key-namespaced `cert-authority` line and `config` block (see
[peer-file-layout.md](peer-file-layout.md#config--the-keyed-client-block)).
Revoke / rekey from one instance touches only that instance's lines and certs, so
the other instances keep managing the peer uninterrupted.

## Rekey

`certhold rekey` is the big-hammer rotation: a brand-new CA, a fresh cert for
**every** non-revoked peer, with certhold's own files rotated last. Reach for it
when the CA key may be compromised, or as periodic hygiene. (`revoke --rekey`
reuses this same engine with the revoked peer excluded.)

### What it does

1. Load the current (old) CA.
2. Generate a new CA into a staging location (`<data-dir>/ca.next`). If that
   already exists, rekey refuses to start — it is the guard against a
   half-finished previous run.
3. For each non-revoked peer except certhold: sign a new cert with the new CA and
   push it — rewrite this instance's `authorized_keys` `cert-authority` line with
   the new CA pubkey, push the new namespaced cert, and re-splice the keyed
   `config` block (no `sshd` reload). A peer that cannot be reached is skipped
   and recorded as a straggler (see below) rather than aborting the rotation.
   A client-style peer is re-signed and its cert stored, but never dialed — the
   pending-refresh notice is printed instead (see
   [below](#client-style-peers-under-rekey-and-revoke)).
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

### Client-style peers under rekey (and revoke)

Client-style peers are **not stragglers** — they are handled by design, not by
failure. The rekey loop re-signs each one from its stored public key under the
new CA, persists the new cert in the database, prints
`client peer <name>: changes pending until 'certhold-cli refresh' runs on it`,
and counts it as rotated; it is never dialed.

The operational consequence is the mirror of the straggler hazard, but
**self-healing**: until `certhold-cli refresh` runs on it, a client-style peer
keeps presenting its old-CA cert, which the rotated fleet no longer accepts —
**it is locked out of every peer** (it accepts no inbound SSH anyway, so nothing
is lost in the other direction). One `certhold-cli refresh` on the peer pulls
the new-CA cert from `serve` and restores its access; no archived-CA recovery
dance is needed, because a client-style peer trusts no CA inbound — only its own
cert changes. After a `revoke --rekey`, run `certhold-cli refresh` on each
remaining client-style peer for the same reason. The revoked peer itself gets
`404` from the pull endpoints once its row is deleted and stays cut off. (The
default `revoke` rotates nothing, so it triggers no client-peer refresh.)

### Passphrase across rotation

By default the new CA key inherits the old key's at-rest protection: if the old
key was encrypted, the same passphrase is reused (you type it once); if it was
plaintext, the new key is plaintext too. `--rotate-passphrase` prompts for a
fresh CA passphrase for the new key instead. It affects the **CA key only** —
the manager peer key's passphrase is never changed by rekey. See
[security.md](security.md#when-the-manager-prompts). In the TUI this is the
`K` rekey modal's *rotate at-rest CA passphrase* toggle.

## Planned, not built

These appear in the design but are **not implemented**; treat them as future
direction:

- **Automatic retry / reconciler** for offline peers. Catch-up is a manual re-run.
- **Resume-from-`ca.next`** after a failed rekey. Recovery is manual.
- Reducing the standing `manager` blast radius (short-TTL per-operation certs,
  force-command) and moving the CA key off the bastion (TPM / hardware token /
  offline root). See [security.md](security.md).
