# Usage

This is the operator reference: how to install certhold, bootstrap the manager,
onboard peers, and the full command surface. For the trust model behind it see
[architecture.md](architecture.md); for day-to-day fleet operations (push,
revoke, rekey) see
[maintenance-and-operations.md](maintenance-and-operations.md).

## Installation

```bash
git clone https://github.com/shudza/certhold && cd certhold
make build                          # → ./bin/certhold
sudo cp ./bin/certhold /usr/local/bin/
```

Building needs Go. A peer needs only OpenSSH 6.5+ and `curl` (see
[architecture.md](architecture.md#requirements--compatibility)).

## Bootstrapping the manager

One-time setup on the manager box:

```bash
certhold init                 # generate the CA, self-enroll, pick the interface peers reach you on
certhold serve --addr :8443   # run the enroll endpoint over HTTPS (self-signed). Leave it running.
```

`init` generates the CA, self-enrolls certhold as its own peer (with the
`manager` principal), prompts once for an at-rest passphrase protecting the CA
and manager keys, picks the network interface peers will use, and persists a
base URL like `https://192.168.1.10:8443`. `serve` then runs the enrollment
endpoint and prints the self-signed cert's SHA-256 fingerprint.

A systemd unit for `serve` is recommended so it survives reboots and crashes.
`sudo certhold install` is the one-command way to get one: it writes
`/etc/systemd/system/certhold.service` (running `serve` as the invoking
`SUDO_USER`) and enables and starts it — see [`install`](#install). The `serve`
process never holds the CA key, so it can run as an unprivileged, network-facing
service. Beyond onboarding, `serve` is also what [client-style
peers](#client-style-peers-enroll---client) pull their refreshed certs from, so
it should stay up for the life of the fleet.

### Activating the manager as a peer

`init` writes certhold's own peer files under `<data-dir>/self/<home>/.ssh/`, but
does not install them into the manager host's live SSH config. The manager uses
those files directly for its outbound pushes, so the fleet works without this
step — but to make the manager itself reachable as a peer (or to use the issued
cert for ordinary `ssh` from it), copy the contents of
`<data-dir>/self/<home>/.ssh/` into the real `~/.ssh/` of the matching user
(`<data-dir>/self/root/.ssh/` → `/root/.ssh/` when `init --user root`).

## Onboarding a peer

Onboarding is two commands. Run `enroll` on the manager to mint a token; it
prints a single one-liner. The referenced groups must exist beforehand — `init`
bootstraps `manager` automatically, but everything else is operator-created with
`certhold group create`:

```
$ certhold group create infra
$ certhold group create databases
$ certhold enroll app1 --groups infra,databases
curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
```

Paste that one-liner on the new peer, as the user who should own the SSH files.
That is the entire peer-side onboarding — the peer contacts no other peer, and
existing peers need no update (they already trust anything the CA signed).

Running it prints a per-file summary and a final `ssh` hint:

```
$ curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash

Changed files:
  + ~/.ssh/id_ed25519_<instance>            (installed, 0600 - private key)
  + ~/.ssh/id_ed25519_<instance>-cert.pub   (installed, 0644 - certificate)
  ~ ~/.ssh/known_hosts                       (appended manager host key)
  ~ ~/.ssh/authorized_keys                   (appended cert-authority line)
  ~ ~/.ssh/config                            (replaced certhold block)
  + ~/.local/bin/certhold-cli               (installed, 0755 - client CLI)
  + ~/.ssh/certhold_<instance>.conf   (installed, 0600 - client conf)

Success. Try:  ssh app1@app1.lan
This address is what this peer reports for itself; if a different
address is reachable from the manager, pass --address to certhold enroll next time.
```

`+` marks files certhold installs whole; `~` marks files it edits in place
(`known_hosts` and `authorized_keys` lines are only printed if this install
actually appended them, so a re-run on an already-trusted peer shows fewer
lines). If `~/.local/bin` is not on the user's `PATH`, the script prints
`hint: ~/.local/bin is not on your PATH; add it to run certhold-cli by name` —
it never edits shell rc files. The host in the `Success` line comes from the
peer's own `hostname -f`; if that isn't the address reachable from the manager,
pass `enroll --address <host-or-ip>` next time.

What happens under the hood:

- `enroll` (on the manager) validates inputs, loads and unlocks the CA, generates
  the peer's keypair, signs its certificate (principals = the peer name plus its
  `--groups`), builds the install tarball, and stores it against the token row.
  This **sign-at-mint** step is the only thing that touches the CA key. It also
  mints the peer's standing [pull token](#client-style-peers-enroll---client)
  and stores the signed cert on the peer row, so the peer can later pull
  refreshed material from `serve`.
- The peer's `curl … | bash` fetches a small install script, then the tarball,
  unpacks it into the invoking user's `~/.ssh/`, appends the `cert-authority`
  line, splices the keyed `~/.ssh/config` block, and installs `certhold-cli`
  plus its conf file. Nothing system-wide changes and there is no `sshd` reload.

The `-k` accepts the self-signed TLS cert; the enrollment token is the real
authentication.

### The install user (and managing root)

- The install targets the **invoking user's** `~/.ssh` — the script reads `$HOME`
  and `id -un`. Running it as `alice` targets `/home/alice/.ssh`; running it **as
  root** targets `/root/.ssh`.
- By default that user is **reported by the peer** at install time and recorded
  on the peer row (`target_user`). Pass `enroll --user <name>` to **pin** it: the
  install request must then match, or the server rejects it (the token is
  preserved, so it can be retried).
- **To manage root, enroll with `--user root` and run the one-liner as root.**
  There is no separate mode; root is just a target user whose home is `/root`.

### Name vs. address

A peer's `name` is its **identity** (the cert key-id, a principal, the database
primary key); its `address` is **how certhold reaches it over SSH**. They are
decoupled: every push path (`update`, `group`, `rekey`, `revoke`'s fan-out) dials
the recorded address, falling back to the name when none is set. If a peer's name
isn't a resolvable/reachable hostname, pass `enroll --address <host-or-ip>` to
record the dial target up front. Otherwise the address is backfilled from the
source IP seen when the peer fetches its tarball at install (`X-Forwarded-For` is
not trusted, so behind a proxy or NAT use `enroll --address` explicitly).
`update`/`group --host` still override the address for a single invocation.

Peers get the same decoupling for free: each peer's keyed `~/.ssh/config` block
carries a `Host <name>` alias (recorded address + login user) for every peer it
may reach, so from a peer

```
[laptop]$ ssh app1
```

works by name even when `app1` is not a resolvable hostname. The aliases are
written at install and refreshed at each later push or `certhold-cli refresh` —
see [peer-file-layout.md](peer-file-layout.md#config--the-keyed-client-block).

### Client-style peers (`enroll --client`)

Pass `--no-inbound` (or its alias `--client`) to enroll a **client-style peer**
— a peer that accepts no inbound SSH, fit for laptops and workstations. It is
still an ordinary peer (same cert, same groups, full outbound reach); what
changes:

- its bundle ships **no `cert-authority` line**, so neither other peers nor the
  manager can SSH into it, and `group allow … --on` it is rejected;
- the manager **never dials it** — mutating commands persist the change and
  print `client peer <name>: changes pending until 'certhold-cli refresh' runs
  on it`;
- it picks changes up itself by running `certhold-cli refresh` (installed at
  onboarding), which pulls a public-material bundle from `serve` using a
  standing per-peer **pull token**.

```
$ certhold enroll laptop --groups infra --client
curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
client-style peer; manager cannot push to it; updates arrive via `certhold-cli refresh`.
```

Onboarding is the same one-liner; the changed-files output simply lacks the
`authorized_keys` line. See
[architecture.md](architecture.md#client-style-peers-and-the-pull-channel) for
the push-vs-pull model and
[`certhold-cli`](#certhold-cli-on-the-peer) for the peer-side commands.

### Serve endpoints

`certhold serve` exposes an enroll route with two behaviors, keyed on a `.sh`
suffix:

- **`GET /enroll/<token>.sh`** — returns the install script. The token is
  inspected, **not consumed**.
- **`GET /enroll/<token>`** — streams the pre-built tarball and **consumes** the
  token (the stored bundle is cleared in the same step, so it cannot be
  re-downloaded). The request carries a `?user=` parameter (the invoking user),
  added by the install script.

Status codes:

| Condition | Status |
|---|---|
| missing token | `400` |
| token not found | `404` |
| missing / invalid / mismatched `?user=` | `400` (token preserved) |
| token already consumed (re-fetch) | `410` |
| otherwise | `200` |

It also exposes the **pull channel** used by `certhold-cli`, keyed on the
standing per-peer pull token (minted at every enroll, **not consumed** by use):

- **`GET /pull/<token>`** — streams the peer's refresh bundle
  (`application/gzip`, `Cache-Control: no-store`): its latest stored cert, the
  keyed `config` block, the current `certhold-cli`, and a manifest — public
  material only (see
  [peer-file-layout.md](peer-file-layout.md#the-refresh-bundle-pull-channel)).
- **`GET /pull/<token>/rev`** — returns the current fleet revision as
  `text/plain` (a decimal plus newline), for cheap staleness checks.

Status codes (both pull routes):

| Condition | Status |
|---|---|
| token not found (or empty) | `404` |
| peer revoked | `410` |
| peer has no stored cert (pre-feature enrollment; bundle route only) | `409` — re-enroll it or run `certhold update` on the manager |
| otherwise | `200` |

Like enrollment, `serve` never signs on the pull path — bundles are assembled
from the cert stored at the last (re)sign.

## Command reference

The binary is `certhold` with the subcommands below. Two persistent flags apply
to all of them:

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir` | `~/.certhold` | Holds `ca/`, the manager's own `self/` files, and `base_url`. |
| `--db` | `<data-dir>/state.db` | SQLite state database. Independent of `--data-dir` — set both if you relocate state. |

Passphrases are read no-echo from `/dev/tty`, or from an environment variable
checked first so automation never blocks. No flag ever takes a passphrase value.

| Variable | Used by | Effect |
|---|---|---|
| `CERTHOLD_CA_PASSPHRASE` | init, enroll, update, revoke, rekey | CA-key passphrase, non-interactive. |
| `CERTHOLD_PEER_PASSPHRASE` | update, group, revoke, rekey | Manager peer-key passphrase, non-interactive. |
| `CERTHOLD_BASE_URL` | enroll | Fallback enroll base URL when not pinned by `--base-url` or persisted at `init`. |

Which keys each command unlocks is summarized in
[security.md](security.md#when-the-manager-prompts).

### `init`

```
certhold init [--hostname <name>] [--user <name>]
              [--listen-ip <ip>] [--port <port>] [--no-prompt]
              [--no-passphrase] [--separate-passphrases]
```

Generates the CA, self-enrolls the manager, picks the enroll interface, persists
`base_url`. Refuses to overwrite an existing `state.db`. No SSH push.

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | OS hostname | Manager peer name (cert key-id and a principal). |
| `--user` | current OS user | Unix user owning the manager's `~/.ssh` files; `--user root` puts them under `/root/.ssh`. |
| `--listen-ip` | — | IPv4 peers reach the manager on; skips the interactive interface picker. |
| `--port` | `8443` | Port baked into the persisted base URL. |
| `--no-prompt` | `false` | Fail instead of prompting for the interface (auto-selects a sole candidate). |
| `--no-passphrase` | `false` | Write both keys **unencrypted** after a typed `yes` confirmation. Not recommended — see [security.md](security.md#opt-out-certhold-init---no-passphrase). |
| `--separate-passphrases` | `false` | Prompt for two distinct passphrases (CA and manager key) instead of one shared. |

If exactly one usable (non-loopback, non-virtual) IPv4 interface exists it is
chosen automatically; otherwise `init` prompts unless `--listen-ip` / `--no-prompt`
is given.

### `enroll`

```
certhold enroll <name> --groups <a,b,c> [--base-url URL]
                [--user <name>] [--address <host>]
                [--no-inbound | --client]
```

Mints a one-time token, signs the peer cert (sign-at-mint), builds and stores the
install tarball, records the peer (with a standing pull token and the signed
cert), and prints the onboarding one-liner. Errors if a peer of that name
already exists. Every group named in `--groups` must already exist — create them
up front with [`group create`](#group-create); there is no implicit creation. No
SSH push — the peer pulls its tarball from `serve`.

| Flag | Default | Meaning |
|---|---|---|
| `--groups` | — (**required**) | Comma-separated groups for the new peer (≥1, deduped). |
| `--base-url` | persisted / fallback | Enroll base URL for the one-liner. Precedence: flag > `$CERTHOLD_BASE_URL` > the `base_url` persisted by `init` > `https://certhold.home.lan`. |
| `--user` | — | Pin the install user; a hard constraint at install time. Use `--user root` (and run the one-liner as root) to manage `/root/.ssh`. |
| `--address` | — | Network address (host or IP) certhold dials to reach this peer. Defaults to the source IP seen at install, then the peer name. See [Name vs. address](#name-vs-address). |
| `--no-inbound` | `false` | Enroll a [client-style peer](#client-style-peers-enroll---client): no inbound trust line, other peers cannot SSH into it, updates arrive via `certhold-cli refresh`. |
| `--client` | `false` | Alias for `--no-inbound`. |

(`--hostname` is accepted but unused under the current layout — host trust is
TOFU `known_hosts`, so there is no host-label entry to set.)

Unlocks the CA key (to sign); no manager-key prompt, since `enroll` does not push.

### `list`

```
certhold list [--peers | --groups]
```

Reads local state and prints a table. No push, no passphrase. Default (or
`--peers`): `NAME GROUPS ALLOWED INBOUND REVOKED`. `--groups`: groups with peer
counts. `GROUPS` is the peer's own membership; `ALLOWED` is who may connect into
it (see [data-model.md](data-model.md)); `INBOUND` is `Y` for push-managed peers
and `N` for [client-style peers](#client-style-peers-enroll---client).

### `tui`

```
certhold tui [--read-only]
```

Interactive fleet dashboard in the terminal's alternate screen, over the same
state `list` reads. By default it can also **mutate** the fleet in place —
enroll, edit groups, revoke, rekey, group CRUD — running the very same
[`ops`](#command-reference) paths the individual commands do, so a TUI action is
byte-for-byte equivalent to its CLI counterpart (same signing, same SSH push,
same fleet-rev bump). Pass `--read-only` for the v1 dashboard: no mutating keys,
no CA key load, no SSH dial, zero writes — safe to leave open.

Four views, switched with `tab` (cycles) or the number keys `1`–`4`:

- **`1` Peers** (default): `NAME ADDRESS USER GROUPS ALLOWED INBOUND REVOKED
  SERIAL EXPIRES`. `ADDRESS` is the dial target (recorded address, falling back
  to the peer name — see [Name vs. address](#name-vs-address)). `EXPIRES` is read
  from the peer's stored signed cert: `-` for peers enrolled before certs were
  persisted, `∞` for a no-expiry cert. Revoked peers are dimmed red; expired
  certs highlighted. On terminals too narrow for every column, low-priority
  columns (`INBOUND`, `SERIAL`, then `ALLOWED`, …) are dropped so `REVOKED` and
  `EXPIRES` stay readable. `enter` opens a detail pane with the full record
  (status, cert validity window, fingerprint, created, …); the pane stays pinned
  to that peer across reloads. Pull token values are never displayed — the detail
  pane only says whether one exists.
- **`2` Groups**: groups with peer counts; the pane under the table shows the
  selected group's members and which peers allow it inbound.
- **`3` Status**: a health snapshot — the `serve` endpoint's liveness and its
  reported fleet-rev / CA version (fetched from `/healthz`; flags `STALE` when
  the server's rev lags the local db), then fleet totals (peers / inbound /
  client, revoked count, expired and ≤30-day-expiring certs), and the manager's
  own fleet rev and active CA version. `r` refetches `/healthz` and reloads.
- **`4` Net**: live reachability of inbound peers. Columns `PEER HOST STATUS
  LATENCY LAST OK`; `STATUS` is `● up` / `○ down` / `–` (not probed, e.g. a
  client peer). Probes run every 5 s (capped at 8 concurrent); `LAST OK` shows
  the last success as `hh:mm:ss`, prefixed with `mm-dd` when it is not today.
  `p` pauses/resumes the sweep, `P` probes once now.

The header shows the db path, fleet revision and active CA version, plus the
view tabs with live peer/group counts. The selected row is marked with `>`, a
multi-selected row with `▣`, and the active tab is bracketed, so the dashboard
stays usable when styling is stripped (`NO_COLOR`). When a table overflows the
window, a `sel/total` scroll cue with `▲`/`▼` shows the position.

**Navigation, filtering, detail (all views):**

| Key | Action |
|---|---|
| `tab` / `1` `2` `3` `4` | Cycle views / jump to Peers, Groups, Status, Net. |
| `j` / `k`, `↓` / `↑` | Move the selection (Peers, Groups, Net). |
| `enter` | Open the selected peer's detail pane (Peers view). |
| `/` | Fuzzy-filter the current table (Peers/Groups only; subsequence match; the match count updates live; `enter` applies, `esc` clears). |
| `esc` | Close the detail pane, else clear the current view's filter, else clear all marks. |
| `r` | Reload from the database (Status also refetches `/healthz`). |
| `q`, `ctrl+c` | Quit. |

**Net view only:**

| Key | Action |
|---|---|
| `p` | Pause / resume the periodic probe sweep. |
| `P` | Probe every inbound peer once now. |

**Mutating actions** (omitted under `--read-only`). Each opens a modal; `esc`
cancels at any step, and a passphrase-protected CA / manager key is prompted
through a masked modal (see *Passphrase session* below). The action runs in a
progress modal that streams its `ops` events and reports done/failed; `esc`
dismisses it. A transcript longer than the modal follows its tail as events
arrive; `j`/`k` (arrows, `pgup`/`pgdn`) scroll back through it — scrolling up
stops the tail-follow, scrolling back to the bottom resumes it — and the
running/failed/done status and `esc` hint stay pinned below the transcript.

| Key | View | Action |
|---|---|---|
| `e` | Peers, Groups | Enroll a new peer (form: name, groups, allowed-inbound, user, address, client toggle). The result screen shows the `curl … \| bash` one-liner; the pull token is never rendered. A duplicate name is rejected live as it is typed. |
| `u` | Peers | Edit the selected peer's group membership (multi-pick, pre-checked with its current groups). |
| `i` | Peers | Edit which groups may **connect into** the selected peer (allowed-inbound multi-pick). |
| `x` | Peers | Revoke the selected peer (confirm → revoke + CA rekey to exclude it). |
| `K` | Peers, Groups | Rekey the whole fleet (type `rekey` to confirm; optional toggle to rotate the at-rest CA passphrase). |
| `n` | Groups | Create a new group (name entry). |
| `R` | Groups | Rename the selected group (cascading re-sign + push to affected peers). |
| `D` | Groups | Delete the selected group (confirm; body spells out the affected members and allow-by rewrites). |
| `m` | Groups | Edit the selected group's membership (peer multi-pick). |

**Multi-select + batch (Peers view):** `space` marks/unmarks the selected peer
(marks are keyed by peer name and survive a filter change; the footer shows the
mark count, `esc` clears them). With one or more peers marked, `u` / `x` / `m`
(the last from the Groups view) fan out over the whole marked set as a single
batch: one confirm/pick modal, one aggregated progress modal with a `✓`/`✗` line
per peer and an `N ok, M failed` summary. Peers whose op succeeded are unmarked;
failed ones stay marked for a retry. A wrong passphrase aborts the whole batch
and re-prompts once, re-running it in place.

**Passphrase session:** the CA key and the manager peer key are each unlocked at
most once per session — the first action that needs one prompts, and subsequent
actions reuse the cached value (mirroring the CLI's session unlocker). `ctrl+l`
forgets both cached passphrases, so the next action prompts again. The entered
bytes are never echoed (a `•` mask stands in) and never stored in the model
beyond the modal's transient input.

| Key | Action |
|---|---|
| `space` | Mark / unmark the selected peer (Peers view). |
| `ctrl+l` | Forget the cached CA and manager-peer passphrases. |

Modal keys: confirm modals take `y`/`enter` or `n`/`esc`; multi-pick modals use
`j`/`k` to move, `space` to toggle, `enter` to apply, `esc` to cancel; the
enroll form moves between fields with `tab`/`shift+tab` (or `↑`/`↓`), `enter`
advances (and submits from the last field).

Exits with a clear error (before entering the alternate screen) if the state
database is missing or not initialized.

### `update`

```
certhold update <name> --groups <a,b,d> [--host HOST]
```

Reissues the peer's cert with a new group set, then SSHes in (as the peer's
`target_user`) and pushes the new cert plus a refreshed `Host`-alias config
block. No `sshd` reload. Runs a post-push health check. Errors if the peer is
unknown or revoked. Every group named in `--groups` must already exist — create
them up front with [`group create`](#group-create); there is no implicit
creation. A client-style peer is re-signed but **not** dialed: `update` prints
`client peer <name>: changes pending until 'certhold-cli refresh' runs on it`
and the new cert lands at the peer's next refresh.

| Flag | Default | Meaning |
|---|---|---|
| `--groups` | — (**required**) | New comma-separated group set. |
| `--host` | the peer name | SSH host to push to. |

Unlocks the CA key (to sign) and the manager peer key (to push).

### `group allow` / `group disallow`

```
certhold group allow    <group> --on <peer> [--host HOST]
certhold group disallow <group> --on <peer> [--host HOST]
```

Changes which groups may **connect into** a peer (its inbound allow-list),
without reissuing the peer's cert. `allow` adds, `disallow` removes; both rewrite
the `principals="…"` value on the peer's `authorized_keys` `cert-authority` line,
push it, and run a health check (no `sshd` reload). Idempotent — a no-op exits
without pushing. `manager` is always implicit and cannot be removed. The group
named on `allow` must already exist — create it up front with
[`group create`](#group-create); there is no implicit creation.

A client-style peer has no inbound allow-list: `allow` is rejected with
`peer <name> is a client-style peer (enrolled --no-inbound); it accepts no
inbound connections`, and `disallow` no-ops gracefully (never dialing the peer).

| Flag | Default | Meaning |
|---|---|---|
| `--on` | — (**required**) | Peer to update. |
| `--host` | value of `--on` | SSH host to connect to. |

Unlocks the manager peer key only (no CA signing).

### `group create`

```
certhold group create <name>
```

Creates a new empty group. Refuses to create the reserved `manager` group.
Errors if the group already exists (no silent dedup, so typos surface).
Local-only — no push, no CA, no manager-key prompt.

| Flag | Default | Meaning |
|---|---|---|
| (none) | — | Takes only the positional `<name>`. |

Unlocks nothing — no CA, no manager peer key.

### `group show`

```
certhold group show <name>
```

Prints the group's members (peers whose cert names it) and the peers that allow
it inbound. Read-only.

| Flag | Default | Meaning |
|---|---|---|
| (none) | — | Takes only the positional `<name>`. |

Unlocks nothing — read-only.

### `group delete`

```
certhold group delete <name>
```

Removes a group from every peer's membership and inbound allow-list across the
fleet, then deletes the group row. Reissues certs for members and rewrites
`authorized_keys` for allow-list peers, pushing both. Refuses `manager`. Skips
revoked peers. Client-style members are re-signed but not dialed (the
pending-refresh notice is printed instead). If any peer cannot be reached, the
group row is preserved and the command exits non-zero so the operator can re-run
after the straggler is recovered; per-peer pushes that already succeeded remain
committed.

| Flag | Default | Meaning |
|---|---|---|
| (none) | — | Takes only the positional `<name>`. |

Unlocks the manager peer key (to push) and the CA key (to reissue member
certs) — the CA prompt is skipped if the group has no members.

### `group rename`

```
certhold group rename <old> <new>
```

Atomically renames a group across the DB and the fleet. Reissues every member's
cert and rewrites every allow-list peer's `authorized_keys` so they carry the
new name. Refuses to/from `manager`. A same-name rename is a no-op. Client-style
members are re-signed but not dialed (the pending-refresh notice is printed
instead). If any push fails, the DB rename stays committed and the command exits
non-zero; reconcile stragglers with a subsequent `update` (for member-only
stragglers) or a no-op `group allow` (for allow-list stragglers).

| Flag | Default | Meaning |
|---|---|---|
| (none) | — | Takes only the positional `<old>` and `<new>`. |

Unlocks the manager peer key (to push) and the CA key (to reissue member
certs) — the CA prompt is skipped if the group has no members.

### `revoke`

```
certhold revoke <name> [--hostname <manager-name>]
```

Marks the peer revoked, then cuts its cert off across the fleet by forcing a
**partial CA rekey**: the CA is rotated and every other peer is reissued, while
the revoked peer is excluded so its old-CA cert stops being accepted as the new
CA propagates. The revoked peer's standing pull token is refused from that point
on (`410`), so a revoked client-style peer cannot pull either. Full mechanics
are in [revocation](maintenance-and-operations.md#revocation).

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | OS hostname | Manager's own peer name (must match the self row); the rekey rotates it last. |

Unlocks the CA key and the manager peer key.

### `remove`

```
certhold remove <name>
```

Forgets a peer: deletes it and its references (group membership, allowed-inbound,
enrollment tokens) from manager state. Makes **no** peer contact — no SSH dial,
no CA rekey, no passphrase unlock — so it works even when the peer is offline,
dead, or already wiped. The peer's host is left untouched: its installed cert and
config stay in place until the operator clears them, and its old-CA cert keeps
working until the next `rekey`.

Use `remove` to forget a peer you control or have already torn down. Use
[`revoke`](#revoke) instead when you need to cut a peer off the fleet: revoke
cleans the host's trust by rotating the CA so the peer's old cert stops being
accepted, whereas remove only edits the database.

### `rekey`

```
certhold rekey [--hostname <name>] [--rotate-passphrase]
```

Rotates the CA: generates a new CA, reissues every non-revoked peer's cert,
pushes the new trust material to each, rotates certhold itself last, then
archives the old CA. Unreachable peers are skipped and reported as stragglers
rather than aborting the rotation. Client-style peers are re-signed under the
new CA but never dialed — they stay on their old-CA cert (locked out of the
fleet) until they run `certhold-cli refresh`. See
[rekey](maintenance-and-operations.md#rekey) for the algorithm, straggler
recovery, and
[client-style peers under rekey](maintenance-and-operations.md#client-style-peers-under-rekey-and-revoke).

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | OS hostname | Certhold's own peer name (must match the self row). |
| `--rotate-passphrase` | `false` | Prompt for a fresh CA passphrase for the new key instead of reusing the current one. Affects the CA key only. |

Unlocks the old CA key and the manager peer key; sets the new CA key's
passphrase (reused from the old, or fresh with `--rotate-passphrase`).

### `serve`

```
certhold serve [--addr :8443] [--tls-cert FILE --tls-key FILE]
```

Runs the HTTPS endpoint that peers `curl` during onboarding and that
`certhold-cli` pulls refresh bundles from afterwards (see
[Serve endpoints](#serve-endpoints)). Long-running, graceful shutdown on
SIGINT/SIGTERM; keep it up so client-style peers can refresh — `certhold
install` makes it a systemd service. TLS is always on: with no explicit cert it
generates a self-signed one and prints its SHA-256 fingerprint. Reads the state
db; never touches the CA key or prompts for a passphrase.

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `:8443` | Listen address. |
| `--tls-cert` / `--tls-key` | — | Use your own TLS cert/key. Must be supplied together. |

### `install`

```
certhold install [--addr :8443] [--tls-cert FILE --tls-key FILE] [--print]
```

Installs `certhold serve` as a systemd system service so it survives reboots and
crashes. Writes `/etc/systemd/system/certhold.service` — a unit whose
`ExecStart` runs `serve` with the resolved binary path, `--db`/`--data-dir`, and
the flags below, with `User=` set to the invoking `SUDO_USER` (so the endpoint
runs unprivileged, never as root) — then runs `systemctl daemon-reload` and
`systemctl enable --now certhold.service` to start it now and on boot. Reports
whether the unit file changed. Must run as root (try `sudo certhold install`),
except with `--print`, which renders the unit to stdout and exits with no root
and no side effects.

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `:8443` | Listen address baked into the unit's `serve` command. |
| `--tls-cert` / `--tls-key` | — | Use your own TLS cert/key (resolved to absolute paths in the unit). Must be supplied together. |
| `--print` | `false` | Print the rendered unit to stdout and exit; no root required, no side effects. |

### `certhold-cli` (on the peer)

```
certhold-cli refresh [--instance <key>]
certhold-cli status  [--instance <key>]
certhold-cli --help
```

The one command that runs on a peer — a small pure-bash script installed at
enroll time into `~/.local/bin/certhold-cli`, run on demand (nothing resident).
It discovers managing instances from `~/.ssh/certhold_*.conf` files and operates
on all of them, or just one with `--instance <key>`. It needs no manager-side
key or passphrase: the conf's pull token is the credential.

- **`refresh`** — for each instance, pulls the refresh bundle from
  `<BASE_URL>/pull/<PULL_TOKEN>`, atomically installs the new cert, splices the
  keyed `config` block (foreign blocks and user content untouched), and records
  the bundle's fleet revision in the conf's `LAST_REV`:

  ```
  [laptop]$ certhold-cli refresh
  refreshed laptop (<key>): rev 7, cert ~/.ssh/id_ed25519_<key>-cert.pub
  ```

  As its **last** action it replaces itself from the bundle's `certhold-cli`
  when the script changed (printing
  `certhold-cli: self-updated from bundle at <path>`). A failing instance is
  isolated — others still refresh; the exit code is non-zero if any failed.
- **`status`** — per instance, prints the conf path, the installed cert with its
  serial and principals (via `ssh-keygen -L`), the local revision (`LAST_REV`),
  the manager's current revision (from `<BASE_URL>/pull/<PULL_TOKEN>/rev`), and
  a verdict: `up-to-date`, `stale (run: certhold-cli refresh)`, or
  `manager unreachable`. An unreachable manager does **not** make `status` exit
  non-zero.

Although every peer gets the CLI and a pull token, it is the **only** update
channel for [client-style peers](#client-style-peers-enroll---client) — run
`refresh` on them after any manager-side change that affects them (and always
after a `rekey`/`revoke`, which otherwise leaves them on the retired CA).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Push fails with `ssh: handshake failed` | The peer's host key changed (or was never seeded); update the manager's `known_hosts` — see [maintenance-and-operations.md](maintenance-and-operations.md#host-key-trust-on-the-push). |
| `update` / `group` health check fails | Inspect the peer's `~<user>/.ssh/authorized_keys` and `id_ed25519_<key>-cert.pub`, and check `sshd`'s logs for auth errors. For a `--user root` peer also confirm the account isn't password-locked and `PermitRootLogin` allows pubkey/cert. |
| `init` errors `state db already exists` | A `state.db` is already present; move it aside or use a different `--data-dir` / `--db`. |
| A client-style peer can no longer ssh anywhere after `rekey`/`revoke` | Expected: it still holds the retired CA's cert. Run `certhold-cli refresh` on it (requires `serve` up). |
| `certhold-cli refresh` fails with HTTP `410` | The peer is revoked; its pull token is permanently refused. |
| `certhold-cli refresh` fails with HTTP `409` | The peer row has no stored cert (pre-feature enrollment) — re-enroll it or run `certhold update` on the manager. |
| `certhold-cli` verdict is `manager unreachable` | `serve` is down or the `BASE_URL` in `~/.ssh/certhold_<key>.conf` is wrong. Certs do not expire, so existing access keeps working meanwhile. |
