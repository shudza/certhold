# Security model

This describes certhold's trust root, the blast radius of a compromise, and the
protections in place — and is honest about what is **shipped** versus **planned**.

## Trust root and blast radius

Certhold's entire trust root is two artifacts on the manager, under `<data-dir>`:

- **The CA private key** (`ca/ca`). Anyone who can read and decrypt it can mint a
  cert with any principals for any key — including the `manager` principal.
- **The manager peer key and its cert** (`self/`). This grants certhold inbound
  root-equivalent access to every peer directly, with no signing step.

Two design facts set the blast radius:

1. **`manager` is effectively root on every peer, forever.** Every peer accepts
   the `manager` principal for root login, and there is **no `command=` /
   `ForceCommand` restriction** — certhold gets an unrestricted shell when it
   pushes.
2. **The manager cert never expires.** It is issued (like every peer cert) with
   no `ValidBefore`, so it is valid indefinitely.

> Honest summary: an attacker who obtains `<data-dir>` and can decrypt the keys
> holds, immediately and indefinitely, root on every enrolled peer — by using
> the manager key/cert directly, or by minting a fresh `manager` cert with the CA
> key. Recovery means a full CA [rekey](maintenance-and-operations.md#rekey)
> **and** re-enrolling every peer.

### Planned hardening (not implemented)

These narrow the blast radius but **do not exist in the code today**; they are
recorded as future direction:

- **Reduce the `manager` blast radius** — short-TTL, per-operation manager certs
  (CA key "hot" only during a push), and/or a `command=` force-command limiting
  `manager` to the fixed set of file-swap/reload operations.
- **Get the CA key off the bastion** — a TPM-backed or hardware-token CA key (key
  never exists as an exfiltratable file), or an offline root CA signing a
  short-lived online intermediate. This is the highest-leverage item: at-rest
  passphrase protection (below) defends the bytes on disk but not against code
  execution on a running manager, where the unlocked key can be read from memory.

## At-rest passphrase protection (default)

The one blast-radius mitigation that **is shipped**: by default `init` writes
both the CA key and the manager peer key **encrypted at rest**, prompting once
for a passphrase. Commands that sign or push transparently unlock them. This is a
cheap, large win against stolen backups, disk-image theft, snapshot exfiltration,
and cold-boot — but **not** against code execution on the manager itself (that is
the planned hardware-key work above).

Exactly two private keys are encrypted (both ed25519); the public halves and
certs are never encrypted:

| Key | On-disk path | Env-var passphrase |
|---|---|---|
| CA private key | `<data-dir>/ca/ca` | `CERTHOLD_CA_PASSPHRASE` |
| Manager peer key (user mode) | `<data-dir>/self/<home>/.ssh/id_ed25519` | `CERTHOLD_PEER_PASSPHRASE` |
| Manager peer key (root mode) | `<data-dir>/self/etc/ssh/peer_ed25519` | `CERTHOLD_PEER_PASSPHRASE` |

`<home>` mirrors the peer layout — `root` for the `root` user, otherwise
`home/<user>`. `init` prompts once and uses the same passphrase for both keys;
`--separate-passphrases` sets a distinct one per key. The passphrase is read
no-echo, with the env var checked first so automation never blocks; no flag ever
takes a passphrase value, and unlocked passphrase bytes are wiped at command exit.

The long-running **`serve` process never touches either key** — under
sign-at-mint, signing happens in the `enroll` CLI and `serve` only hands out the
stored bundle (see [usage.md](usage.md#onboarding-a-peer)).

### When the manager prompts

A command that **signs** unlocks the CA key; a command that **pushes** unlocks the
manager peer key; a command that does neither prompts for nothing. A multi-peer
push prompts **at most once per key**, never once per peer.

| Command | CA key | Manager peer key |
|---|---|---|
| `init` | set (create) | set (create) |
| `enroll` | unlock (sign cert) | — |
| `update` | unlock (re-sign) | unlock (push) |
| `group allow` / `disallow` | — | unlock (push) |
| `revoke` (root mode) | unlock (build KRL) | unlock (push KRL) |
| `revoke` (user mode) | unlock old + set new (it is a CA rekey) | unlock (push) |
| `rekey` | unlock old + set new | unlock (push) |
| `serve`, `list` | never | never |

`init`'s cells say *set* because the keys are being created (passphrase
established), not decrypted. A user-mode `revoke` is a partial CA rekey, so its
key usage matches `rekey`, not the root-mode `revoke` row. `rekey` reuses the old
CA passphrase for the new key by default; `--rotate-passphrase` prompts for a
fresh one (CA key only) — see
[rekey](maintenance-and-operations.md#passphrase-across-rotation).

### Per-peer passphrases (install-side)

Separately, the **peer's own** outbound key can be encrypted at install time —
a purely peer-local secret the **manager never sees, stores, or prompts for**.
When the install one-liner runs, the script offers to encrypt that peer's key
(`~/.ssh/id_ed25519` in user mode, `/etc/ssh/peer_ed25519` in root mode):

- Type a passphrase at the prompt → the key is encrypted before being left on
  disk (read no-echo from `/dev/tty`).
- Press Enter → key left unencrypted (the default).
- Pre-set `CERTHOLD_KEY_PASSPHRASE=…` → used non-interactively.
- Pre-set `CERTHOLD_NO_PASSPHRASE=1` → skip the prompt entirely.

The encryption step is best-effort and never aborts the install. This passphrase
protects the peer's *outbound* credentials against compromise of the peer itself;
it has **no effect** on certhold's inbound access, which uses the `manager` cert
validated against the CA, not the peer's outbound key.

### Opt-out: `certhold init --no-passphrase`

`--no-passphrase` writes **both** certhold-side keys unencrypted. The choice is
**implicit going forward** — it is not persisted; later commands simply discover
the keys parse as plaintext and never prompt. (Conversely, adding a passphrase
later means re-encrypting the key file, e.g.
`rekey --rotate-passphrase` for the CA key, not flipping a stored flag.)

Because the result is the entire trust root in plaintext, `init` prints a banner
and requires the operator to type `yes`:

```
================================================================
  WARNING: --no-passphrase
================================================================
  The CA private key and certhold's own peer key will be written
  to disk UNENCRYPTED in <data-dir>. Anyone with read access to
  these files obtains, immediately:

    1. The CA key — can mint a manager-principal cert for any
       attacker-chosen pubkey, giving root on every enrolled
       peer.
    2. The manager peer key and its cert — gives root on every
       enrolled peer directly, no signing required.

  These two keys are the entire trust root of certhold. Theft of
  either is unrecoverable except by a full CA rekey AND re-enrolling
  every peer from scratch.

  The default (passphrase-protected) is strongly recommended.
  Only proceed if <data-dir> is on storage you already protect
  by other means (e.g. LUKS with a passphrase you trust, ephemeral
  CI/test environment, etc.).
================================================================
Type 'yes' to confirm --no-passphrase:
```

The match is exact (lowercase `yes`); anything else aborts with no key written.
There is **no environment-variable bypass** for this gate — a non-interactive
caller that genuinely wants unencrypted keys must pipe `yes` on stdin. Use it
only when `<data-dir>` is already protected by other means (full-disk encryption,
or an ephemeral CI/test environment).
