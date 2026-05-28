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
  address            TEXT NOT NULL DEFAULT ''
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

`groups` is the set of known group names, populated lazily as groups are
referenced. The two join tables encode a real, independent distinction:

- **`peer_groups`** — the groups a peer belongs to. Drives the principals on
  **its own certificate**.
- **`peer_allowed_groups`** — the groups a peer accepts inbound connections from.
  Drives **who may log into it** (the `principals="…"` value on its
  `authorized_keys` `cert-authority` line).

`enroll` initializes both to the requested `--groups`, so a fresh peer starts
symmetric (and same-group peers can reach each other immediately). They diverge
afterward: `update` changes membership, while `group allow`/`disallow` edits only
the allowed set.

### `tokens`

One row per enrollment token; the byte-server hands out the stored install bundle
when a token is redeemed (see [usage.md](usage.md#onboarding-a-peer)).

```sql
CREATE TABLE tokens (
  token       TEXT PRIMARY KEY,
  peer_name   TEXT NOT NULL,
  groups      TEXT NOT NULL,
  tarball     BLOB,
  consumed    INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMP NOT NULL,
  target_user TEXT NOT NULL DEFAULT ''
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

Consuming a token is atomic: in one transaction it checks the row is still
unconsumed, marks it consumed, and nulls the tarball.

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

A small `meta` table holds the schema version (and the per-instance key) for
bookkeeping; it is not a general configuration store.

## Schema migration

Migrations run automatically on open. They first bring any database (fresh or
old) up to a shape with all historical columns present (additive
`ALTER TABLE … ADD COLUMN` with existence checks), then **rebuild** `peers` and
`tokens` to physically drop the vestigial `mode` / `layout_version` /
`last_krl_version` columns and `DROP` the dead `krl_version` table left behind by
the removal of root mode and KRL revocation. The rebuild preserves foreign keys
(`peer_groups` / `peer_allowed_groups`) and is idempotent — once the dead columns
are gone it no-ops. The result is the clean single-user-mode schema shown above.
