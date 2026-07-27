# Data model (SQLite)

Certhold keeps all fleet state in a single SQLite database (`state.db` in the
[data directory](architecture.md#data-directory)), using a pure-Go driver (no
cgo). The connection enforces foreign keys, uses WAL journaling, and serializes
access through a single connection. Migrations run automatically on open and are
additive (`ALTER TABLE … ADD COLUMN` with existence checks), so an older database
upgrades in place without data loss.

Two things are deliberately **not** in the database: the manager's `base_url`
(a plain file at `<data-dir>/base_url`) and any key passphrase (keys are
encrypted on disk — see [security.md](security.md)). The database holds no key,
passphrase, or hash columns.

## Tables

### `peers`

One row per enrolled peer, including the manager (which self-enrolls at `init`).

```sql
CREATE TABLE peers (
  name               TEXT PRIMARY KEY,
  cert_serial        INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key     BLOB NOT NULL,
  revoked            INTEGER NOT NULL DEFAULT 0,
  created_at         TIMESTAMP NOT NULL,
  target_user        TEXT NOT NULL DEFAULT '',
  address            TEXT NOT NULL DEFAULT '',
  inbound            INTEGER NOT NULL DEFAULT 1,
  pull_token         TEXT NOT NULL DEFAULT '',
  cert               BLOB,
  push_reachable     INTEGER NOT NULL DEFAULT 1
);
```

| Column | Meaning |
|---|---|
| `name` | Peer name (primary key). |
| `cert_serial` | Serial of the peer's most recent certificate; updated on re-sign (`update`/`rekey`). Revocation keys on this serial. |
| `pubkey_fingerprint` | SHA-256 fingerprint of the peer's public key. |
| `authorized_key` | The peer's public key in `authorized_keys` wire form, persisted so certs can be re-signed without contacting the peer. |
| `revoked` | Revocation flag, set before any push during `revoke`. |
| `created_at` | Enrollment timestamp (UTC). |
| `target_user` | The OS user the files were installed under (the `--user` value; `root` for a `--user root` peer). Recorded at redeem time, and the user certhold dials when pushing. |
| `address` | Network address (host or IP) certhold dials to SSH to this peer. Set by `enroll --address`, else backfilled from the install-time source IP; empty means dial by `name`. Decouples a peer's identity (`name`) from how it is reached. |
| `inbound` | `1` if the peer accepts inbound SSH: it carries a `cert-authority` line, can hold `peer_allowed_groups` rows, appears in other peers' `Host` alias blocks, and is dialed by pushes. `0` for a client-style peer (`enroll --no-inbound`/`--client`), which is skipped by every push path. |
| `pull_token` | Standing token the peer presents to `GET /pull/<token>` for refresh bundles. Minted at every enroll (push-managed peers get one too). `''` on pre-feature rows — an empty token never matches a lookup. |
| `cert` | The peer's latest signed certificate (public material), persisted at every (re)sign — enroll, `update`, the `rekey`/`revoke` loop — together with `cert_serial`, so `serve` can assemble refresh bundles without the CA key. `NULL` on pre-feature rows (a pull then answers `409`). |
| `push_reachable` | `1` if the manager can dial this peer back for pushes. Set by the enroll-time reachability probe (`0` when the manager cannot reach the peer — a non-bidirectional peer behind NAT/firewall). A `0` peer is skipped by every push path and routed onto the pull channel, exactly like a client-style peer. `1` on pre-feature rows (preserves the prior assumption that every peer is dialable; corrected on the next successful probe). |

> **Removed columns (migration history).** Earlier schemas carried `mode`,
> `layout_version`, and `last_krl_version`, plus a `krl_version` table. The
> collapse onto the single user-mode trust model dropped all of them; the
> migration rebuilds `peers`/`tokens` to physically remove the columns and drops
> `krl_version`. See [schema migration](#schema-migration).

### `groups`, `peer_groups`, `peer_allowed_groups`

```sql
CREATE TABLE groups (
  name TEXT PRIMARY KEY
);

CREATE TABLE peer_groups (          -- membership: groups this peer IS in
  peer_name  TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);

CREATE TABLE peer_allowed_groups (  -- inbound: groups this peer ACCEPTS from
  peer_name  TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);
```

`groups` is the set of known group names. Operators populate it explicitly with
`certhold group create`; `certhold init` lazily creates the reserved `manager`
group during manager bootstrap. The two join tables encode a real, independent
distinction:

- **`peer_groups`** — the groups a peer belongs to. Drives the principals on
  **its own certificate**.
- **`peer_allowed_groups`** — the groups a peer accepts inbound connections from.
  Drives **who may log into it** (the `principals="…"` value on its
  `authorized_keys` `cert-authority` line).

`enroll` initializes both to the requested `--groups`, so a fresh peer starts
symmetric (and same-group peers can reach each other immediately). The peer's
own `peer_groups` / `peer_allowed_groups` rows are still created automatically,
but each named group must already exist in `groups` — `enroll`, `update`, and
`group allow` error if it does not. The sets diverge afterward: `update` changes
membership, while `group allow`/`disallow` edits only the allowed set.

The exception is a client-style peer (`enroll --no-inbound`): it gets its
`peer_groups` rows but **no** `peer_allowed_groups` rows at all — it accepts no
inbound connections, and `group allow … --on <client-peer>` is rejected with an
error.

`certhold group delete` removes the group row and every `peer_groups` /
`peer_allowed_groups` row referencing it (atomically). `certhold group rename`
updates all three tables atomically.

### `tokens`

One row per enrollment token; the byte-server hands out the stored install bundle
when a token is redeemed (see [usage.md](usage.md#onboarding-a-peer)).

```sql
CREATE TABLE tokens (
  token                 TEXT PRIMARY KEY,
  peer_name             TEXT NOT NULL,
  groups                TEXT NOT NULL,
  tarball               BLOB,
  consumed              INTEGER NOT NULL DEFAULT 0,
  created_at            TIMESTAMP NOT NULL,
  target_user           TEXT NOT NULL DEFAULT '',
  staged_authorized_key BLOB,
  staged_fingerprint    TEXT NOT NULL DEFAULT '',
  staged_serial         INTEGER NOT NULL DEFAULT 0,
  staged_cert           BLOB,
  staged_pull_token     TEXT NOT NULL DEFAULT '',
  staged_inbound        INTEGER NOT NULL DEFAULT 1,
  staged_address        TEXT NOT NULL DEFAULT '',
  staged_allowed        TEXT
);
```

| Column | Meaning |
|---|---|
| `token` | The opaque token string (primary key). |
| `peer_name` | The peer this token enrolls. |
| `groups` | CSV of groups to assign on redeem. |
| `tarball` | The pre-built, **sign-at-mint** install bundle (the cert is signed when the token is created). Cleared to `NULL` when the token is consumed, so the signed bundle does not linger. |
| `consumed` | Single-use flag. |
| `created_at` | Mint timestamp (UTC). |
| `target_user` | Copied onto the peer row on redeem. If `enroll --user` pinned it, the install request must match; otherwise it is set from the install-time `?user=` value (the user that ran the one-liner). |
| `staged_*` | Present only on a **re-enroll** token (an enroll of an existing peer): the fresh public key, fingerprint, cert+serial, new pull token, inbound flag and optional address staged at mint. `staged_allowed` is `NULL` unless the allowed-inbound set was chosen explicitly (the TUI form); the commit otherwise preserves the peer's current allowed set. `NULL` `staged_authorized_key` marks an ordinary new-peer token. Cleared when the token is consumed. |

Consuming a token is atomic: in one transaction it checks the row is still
unconsumed, marks it consumed, and nulls the tarball. For a **re-enroll token**
the same transaction also commits the staged material to the peer row (key,
cert, pull token, inbound flag, groups, allowed-set transitions, optional
address) and bumps `fleet_rev` — either the token stays redeemable and the peer
row is untouched, or the whole new configuration lands. Until redemption the
peer row is never modified by a re-enroll mint, and minting again for the same
peer deletes any prior unconsumed token for it (superseded one-liners answer
`404`, and deleting the row destroys their staged bundle and its private key).

### `ca`

```sql
CREATE TABLE ca (
  version    INTEGER PRIMARY KEY,
  active     INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL
);
```

- **`ca`** is a monotonic version log; exactly one row is `active`. `init` seeds
  version 1; each [rekey](maintenance-and-operations.md#rekey) inserts the next
  version and flips active. It tracks **only** version metadata — the private key
  itself lives on disk under `<data-dir>/ca/`, never in the database.

### `meta`

A small key/value table; it is not a general configuration store. It holds:

| Key | Meaning |
|---|---|
| `schema_version` | Migration bookkeeping (currently `9`). |
| `instance_key` | The per-instance key (16 lowercase hex chars) namespacing all peer files. |
| `fleet_rev` | The **fleet revision**: a monotonic counter bumped exactly once per successful mutating command (`enroll`, `update`, `rekey`, `revoke`, `group create`/`delete`/`rename`/`allow`/`disallow`); absent reads as `0`. Refresh-bundle manifests and `GET /pull/<token>/rev` report it, so `certhold-cli status` can tell whether a peer is stale without downloading a bundle. |

## Schema migration

Migrations run automatically on open. They first bring any database (fresh or
old) up to a shape with all historical columns present (additive
`ALTER TABLE … ADD COLUMN` with existence checks), then **rebuild** `peers` and
`tokens` to physically drop the vestigial `mode` / `layout_version` /
`last_krl_version` columns and `DROP` the dead `krl_version` table left behind by
the removal of root mode and KRL revocation. The rebuild preserves foreign keys
(`peer_groups` / `peer_allowed_groups`) and is idempotent — once the dead columns
are gone it no-ops. These legacy steps only run for databases below schema
version 6; after them, the additive client-peer migration adds
`peers.inbound` / `pull_token` / `cert` (schema version 7), a further additive
step adds `peers.push_reachable` (schema version 8), and another adds the
`tokens.staged_*` re-enroll columns (schema version 9). The result is the
schema shown above. Pre-existing rows default to `inbound=1`, an empty
`pull_token`, a `NULL` cert, and `push_reachable=1` — exactly the push-managed,
assumed-dialable behavior they had; only a re-enroll mints them a pull token, and
the next successful enroll-time probe corrects `push_reachable`.
