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
  last_krl_version   INTEGER NOT NULL DEFAULT 0,
  mode               TEXT NOT NULL DEFAULT 'root',
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
| `last_krl_version` | Last KRL version successfully pushed to this (root-mode) peer; a value behind the global max means the peer is stale. |
| `mode` | `user` or `root` — the peer's on-disk layout and revocation path. See [architecture.md](architecture.md#operating-modes). |
| `target_user` | For user-mode peers, the OS user the files were installed under (empty in root mode); recorded at redeem time. |
| `address` | Network address (host or IP) certhold dials to SSH to this peer. Set by `enroll --address`, else backfilled from the install-time source IP; empty means dial by `name`. Decouples a peer's identity (`name`) from how it is reached. |

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
  Drives **who may log into it** (its `auth_principals` / `authorized_keys` line).

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
  mode        TEXT NOT NULL DEFAULT 'root',
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
| `mode`, `target_user` | Copied onto the peer row on redeem; `target_user` may be set from the install request in user mode. |

Consuming a token is atomic: in one transaction it checks the row is still
unconsumed, marks it consumed, and nulls the tarball.

### `ca` and `krl_version`

```sql
CREATE TABLE ca (
  version    INTEGER PRIMARY KEY,
  active     INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE krl_version (
  version      INTEGER PRIMARY KEY,
  generated_at TIMESTAMP NOT NULL
);
```

- **`ca`** is a monotonic version log; exactly one row is `active`. `init` seeds
  version 1; each [rekey](maintenance-and-operations.md#rekey) inserts the next
  version and flips active. It tracks **only** version metadata — the private key
  itself lives on disk under `<data-dir>/ca/`, never in the database.
- **`krl_version`** is a monotonic counter; each KRL generation records a new
  version. It pairs with `peers.last_krl_version` to track which peers have the
  latest KRL. See [revocation](maintenance-and-operations.md#revocation).

A small `meta` table holds the schema version for migration bookkeeping; it is
not a general configuration store.
