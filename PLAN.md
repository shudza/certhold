# Certhold — Design Plan

## Goal

A homelab SSH access manager. Two-command onboarding for new devices, group-based access control, no per-device agent. OpenSSH and curl are the only dependencies on peers.

## Core model

**One trust root, one actor type.** Certhold runs an SSH Certificate Authority. Every device on the network — including certhold itself — is a "peer." Each peer holds a CA-signed certificate listing the groups it belongs to. Peers grant access to other peers based on group principal matching, enforced by `sshd` natively.

**No expiries, no agents.** Certificates are issued without expiration. Peers run no software beyond OpenSSH. State changes are pushed by certhold over SSH using its own peer cert.

**Certhold is a peer.** It self-enrolls at init, gets a cert with a privileged `manager` principal that every peer accepts as root. All manager → peer operations use this cert. No bespoke authentication anywhere in the system.

## Architecture

Two components:

**Certhold** — a single Go binary running on one machine in the home network. Exposes:
- A CLI for all administrative operations
- One HTTP endpoint, `GET /enroll/<token>`, for peer onboarding
- Holds the CA private key and a sqlite database of peers, groups, and tokens

**Peers** — any Linux device with OpenSSH. After onboarding, they have a fixed set of files in `/etc/ssh/` and need no further configuration unless their group membership changes.

## Modes

**User-mode (default in T15+)** — peers install five files under `~<user>/.ssh/`. A single `cert-authority,principals="..."` line in `authorized_keys` handles inbound access. No sshd config changes; no reloads. No host certs; outbound uses TOFU via per-peer `known_hosts`. Revocation rotates the CA (skipping the revoked peer) since there is no native KRL. The `target_user` is peer-reported at install time (`id -un`) by default; the admin may pin it with `enroll --user <u>`, in which case the install request must match. Opt out per peer with `--mode root` on `enroll` / `init`.

**Root-mode (opt-in via `--mode root`)** — the "Peer file layout (root mode)" below applies. Sentinel-block edits to `/etc/ssh/sshd_config`. Native KRL for revocation. Sshd reload on every change.

## Peer file layout (user mode)

Files under `~<target_user>/.ssh/` (paths in the install tarball are relative; the install script untars into the resolved home):

```
id_ed25519                              # peer's outbound private key (0600)
id_ed25519-cert.pub                     # CA-signed user cert (0644)
authorized_keys                         # cert-authority,principals="manager,..." ssh-ed25519 ... (0644)
known_hosts                             # TOFU bootstrap; empty by default (0644)
config                                  # Host *: CertificateFile/IdentityFile/UserKnownHostsFile (0644)
```

Revoke in user-mode triggers a partial CA rekey — the revoked peer's old cert ends up signed by a retired CA after the rotation completes.

## Peer file layout (root mode)

```
/etc/ssh/peer_ed25519                    # peer's private key
/etc/ssh/peer_ed25519-cert.pub           # CA-signed cert, no expiry
/etc/ssh/ca.pub                          # CA's signing pubkey (trusted root)
/etc/ssh/krl                             # Key Revocation List, initially empty
/etc/ssh/sshd_config                     # sshd directives spliced in between
                                         #   "# BEGIN certhold" / "# END certhold"
/etc/ssh/auth_principals/root            # one group name per line
/etc/ssh/ca_known_hosts                  # @cert-authority entry for outbound SSH
/etc/ssh/ssh_config                      # client-side cert config spliced in between
                                         #   "# BEGIN certhold" / "# END certhold"
/root/.ssh/authorized_keys               # contains certhold principal indirectly via auth_principals
```

The sentinel-bracketed block appended to `/etc/ssh/sshd_config`:
```
# BEGIN certhold
HostKey /etc/ssh/peer_ed25519
HostCertificate /etc/ssh/peer_ed25519-cert.pub
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/krl
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
# END certhold
```

Every peer's `auth_principals/root` implicitly includes `manager` (added at onboarding, before the user-specified groups). This is what gives certhold standing access.

## Onboarding flow

**Admin runs on manager:**
```
$ certhold enroll new-vm --groups infra,databases
curl -fsSL https://certhold.home.lan/enroll/<token>.sh | bash
```

**Admin pastes on new peer:**
```
$ curl -fsSL https://certhold.home.lan/enroll/<token>.sh | bash
```

The script fetched from `/enroll/<token>.sh` is a short bash payload:
1. Curls `https://certhold.home.lan/enroll/<token>` and pipes the response (a gzipped tarball) into `tar -xzC /`
2. Reloads sshd

**Manager handles `/enroll/<token>.sh`:** returns the install bash script that curls the tarball endpoint. Token is NOT consumed here; only inspected non-destructively (404 if missing, 410 if already consumed).

**Sign-at-mint, not at fetch.** The CA-signing step happens inside the `certhold enroll` CLI command (which mints the token), not inside the HTTP handler. The CLI prompts for the CA passphrase, generates the peer keypair, signs the cert, builds the full tarball, stores the bytes against the token row, and wipes the CA key from memory. The HTTP `/enroll/<token>` handler then becomes a dumb byte-server. This keeps the long-lived `serve` process from ever needing CA-key access. See "Key passphrase protection" below.

**`certhold enroll <name>` (CLI) does:**
1. Validates name/groups; inserts token row
2. Prompts for CA passphrase (unless `init` was run with `--no-passphrase`)
3. Generates an ed25519 keypair in-memory
4. Signs the cert with principals `<name>` plus the requested groups (NOT `manager` — only certhold's self-cert holds that principal)
5. Builds the tarball with all files listed in the relevant mode's file layout. `auth_principals/root` (root mode) or the `cert-authority,principals="..."` line (user mode) always starts with `manager`, then the peer's groups.
6. Stores `tarball` BLOB on the token row; wipes CA key and temp key material
7. Records peer's pubkey fingerprint in the `peers` table for future operations

**Manager handles `/enroll/<token>`:**
1. Validates token, marks consumed
2. Streams the stored tarball bytes
3. Clears the tarball blob on successful read (best-effort; row stays for audit)

The peer ends up enrolled with no communication to any other peer. Existing peers don't know about the new one and don't need to — they already trust anything the CA signed.

## CLI surface

```
certhold init [--no-passphrase]        # generate CA, self-enroll certhold as a peer
certhold enroll <name> --groups a,b    # mint a token, sign cert, build tarball, print onboarding one-liner
certhold list [--peers|--groups]       # show state
certhold update <name> --groups a,b,d  # reissue cert with new principals, push to peer, reload sshd
certhold group allow <group> --on <peer>      # add group to peer's auth_principals/root, push
certhold group disallow <group> --on <peer>   # remove from auth_principals/root, push
certhold revoke <name>                 # add cert serial to KRL, regenerate KRL, push to all peers
certhold rekey                         # rotate CA: new keypair, new certs for every peer, push atomically
```

Every operation except `init` and `enroll` involves certhold SSHing into one or more peers using its own cert. Certhold has no other authentication mechanism to peers.

## Push operations

When certhold modifies a peer (cert reissue, principals update, KRL push), the flow is:

1. SSH into the peer using certhold's cert
2. Write new files to a staging path (e.g. `/etc/ssh/.staging/`)
3. Atomically move them into place
4. `systemctl reload sshd`
5. Verify sshd is healthy (test connection)

For multi-peer operations (KRL push, rekey), iterate over all peers. Offline peers are queued for retry. State of "last successfully pushed KRL version" per peer is tracked in the sqlite db so retries are idempotent.

## Revocation

The KRL is a single binary file generated with `ssh-keygen -k`. Every peer ships with `RevokedKeys /etc/ssh/krl` already configured from day one. Initial KRL is empty.

On `revoke <name>`:
1. Mark peer as revoked in db
2. Regenerate KRL from all currently-revoked peers' cert serials
3. Push the new KRL file to every non-revoked peer
4. The revoked peer itself is not pushed to (and would be ignored by other peers anyway once the KRL propagates)

Offline peers will receive the updated KRL on the next push attempt. Until then, they would still accept the revoked cert if presented — accepted as a soft consistency tradeoff for v1.

## Rekey

`rekey` is the big-hammer rotation operation. Used when the CA key may have been compromised, or periodically as hygiene.

1. Generate new CA keypair
2. For each peer (including certhold itself, last):
   - Issue a new cert signed by the new CA, same principals as before
   - SSH in using the current (old-CA) cert
   - Write new `ca.pub` and new `peer-cert.pub` to staging
   - Atomic move both into place
   - Reload sshd
3. Once all peers are updated, retire the old CA key
4. Manager rekeys itself last so it doesn't lock itself out mid-operation

If rekey fails partway, the operation is resumable: peers already updated have the new CA in place, and certhold can be reissued certs against the new CA to continue. For v1, manual recovery on failure is acceptable.

## Data model (sqlite)

```sql
CREATE TABLE peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  revoked INTEGER DEFAULT 0,
  created_at TIMESTAMP,
  last_krl_version INTEGER DEFAULT 0
);

CREATE TABLE groups (
  name TEXT PRIMARY KEY
);

CREATE TABLE peer_groups (
  peer_name TEXT REFERENCES peers(name),
  group_name TEXT REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);

CREATE TABLE peer_allowed_groups (
  -- which groups can SSH INTO this peer (separate from membership)
  peer_name TEXT REFERENCES peers(name),
  group_name TEXT REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);

CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT,
  groups TEXT,
  tarball BLOB,                        -- pre-built install bundle, signed at enroll-CLI time
  consumed INTEGER DEFAULT 0,
  created_at TIMESTAMP
);

CREATE TABLE ca (
  version INTEGER PRIMARY KEY,
  active INTEGER DEFAULT 0,
  created_at TIMESTAMP
  -- private key stored separately on disk, not in db
);

CREATE TABLE krl_version (
  version INTEGER PRIMARY KEY,
  generated_at TIMESTAMP
);
```

Two relations on group: `peer_groups` (which groups this peer is *in*, controlling what its cert says) and `peer_allowed_groups` (which groups this peer *accepts* incoming connections from, controlling its `auth_principals/root`). These are usually symmetric but not necessarily — a peer might be in `infra` but not accept incoming `infra` connections.

## Blast radius mitigations

1. Reduce the blast radius of certhold principal.
Right now manager = root on every peer, forever. A few cheap changes:

Drop the universal principal, push per-operation certs. Instead of certhold holding one long-lived cert with certhold principal, it signs itself a short-TTL cert (say 5 minutes) right before each push operation, scoped to just the peers it needs to touch. The CA key is only "hot" during operations. Between operations, no cert in existence grants manager-level access.
Force-command on certhold principal. auth_principals/root could map manager to a restricted command set via authorized_keys command= or sshd Match Principal blocks — essentially "certhold can only run these specific atomic-file-swap and reload-sshd operations, not arbitrary shell." Limits what a compromised manager can do per-host even if it has the cert. Fiddly to get right but matches your "push model" cleanly since the operations are a fixed set.

2. Get the CA key off certhold.
This is the big one. The CA private key is the crown jewel; if it lives as a file on the bastion next to the Go binary, popping the binary pops the CA.

TPM-backed CA key. Most modern hardware has a TPM 2.0. You can generate the CA key inside the TPM and sign through it — the key never exists as a file. An attacker with root on certhold can still request signatures while they're on the box, but can't exfiltrate the key to use later or elsewhere. ssh-tpm-agent or direct PKCS#11 via tpm2-pkcs11 both work with ssh-keygen. This is probably the single highest-leverage mitigation.
YubiKey / hardware token. Same idea, removable. CA key on a YubiKey, plugged in only when you're actively administering. Great for homelab — matches the "I'm at my desk doing admin" workflow. Touch-to-sign means even with root on certhold, an attacker can't sign new certs without physical presence.
Offline CA, online intermediate. Two-tier: a root CA that lives on an air-gapped machine or a USB stick in a drawer, which signs an intermediate CA on the bastion with a short lifetime (e.g. 90 days). Bastion compromise burns the intermediate; you sign a new one from the offline root. More ceremony than a homelab probably wants, but it's the textbook answer.

3. **Passphrase-protect the keys on certhold.** Default in v1; see "Key passphrase protection" below. Cheap, large win against file-theft / backup-theft / disk-at-rest attacks. Does not protect against persistent RCE on certhold itself — that's what mitigation 2 (hardware-backed key) covers.


## Key passphrase protection

**Default behavior**: both keys on certhold (the CA private key, and certhold's own outbound peer key — the one paired with its `manager`-principal cert) are encrypted with passphrases at rest. Every CLI command that needs a key prompts for its passphrase, holds it unlocked only for the duration of the command, and wipes it on exit. The long-lived `serve` process never touches either key.

### Threat model addressed

Either key, in plaintext form, is full game-over:

- **CA key** → an attacker can mint a `manager`-principal cert for any pubkey they own → root on every peer.
- **Manager peer key** → an attacker can directly present certhold's existing manager cert → root on every peer immediately, no signing required.

Both sit on the same disk in `<data-dir>`. Passphrase-protecting them defeats: stolen backups, snapshot exfiltration, disk-image theft, cold-boot, lost-laptop-with-certhold-data.

It does **not** defeat persistent RCE on the certhold host — an attacker who can execute code at the moment a command is running can dump the unlocked key from process memory. That residual gap is what mitigation 2 above (TPM/YubiKey-backed CA, short-TTL per-op manager certs) closes.

### Keys covered

| Key | Location | Encrypted with |
|---|---|---|
| CA private key | `<data-dir>/ca/ca` | CA passphrase (set at `init`) |
| Manager peer key | `<data-dir>/self/id_ed25519` (user mode) or `<data-dir>/self/peer_ed25519` (root mode) | Manager passphrase (set at `init`) |

`init` prompts for one passphrase by default and uses it for both. Pass `--separate-passphrases` (or answer the second prompt with a different value when offered) to split them.

### When the manager prompts

| CLI command | CA key | Manager peer key |
|---|---|---|
| `init` | set (mint) | set (mint + sign self-cert) |
| `enroll <name>` | unlock (sign peer cert) | — |
| `update <name>` | unlock (re-sign cert) | unlock (push to peer) |
| `group allow` / `group disallow` | — | unlock (push to peer) |
| `revoke <name>` | unlock (sign new KRL) | unlock (push KRL to all non-revoked peers) |
| `rekey` | set new + unlock old chain as needed | unlock old, set new |
| `serve` | **never** | **never** |
| `list` | — | — |

Multi-peer push (`revoke`, `rekey`) prompts at most once per key, regardless of peer count: certhold uses a single outbound key for all peers, so unlocking it once covers the whole push. N peers never means N prompts. This is feasible because the design has no background or non-interactive push surface — every push is admin-initiated from the CLI, and offline-peer retries happen on the next manual run of the same command (state tracked in the db).

### Per-peer passphrases (install-side, optional)

When the install one-liner runs on a new peer, the install script gives the operator the option to passphrase-protect *that peer's* outbound key (`~/.ssh/id_ed25519` in user mode, `/etc/ssh/peer_ed25519` in root mode). Prompt reads from `/dev/tty` since the script is piped through `bash`. Operator can:

- Type a passphrase → script runs `ssh-keygen -p` to encrypt the key before placing it.
- Hit enter → key stays unencrypted (current behavior).
- Pre-set `CERTHOLD_KEY_PASSPHRASE=…` in the environment when invoking the curl one-liner for non-interactive installs.
- Pre-set `CERTHOLD_NO_PASSPHRASE=1` to skip the prompt entirely.

The manager never sees this passphrase. It's a purely peer-local secret protecting that peer's outbound credentials against compromise of the peer itself.

Note that peer-side passphrases don't affect certhold's inbound access to the peer: certhold authenticates by presenting its `manager`-principal cert, which sshd validates against the trusted CA pubkey on the peer — no peer-side passphrase enters that path.

### Opt-out: `certhold init --no-passphrase`

Disables passphrase protection for **both** certhold-side keys. The choice is implicit going forward — the keys are written unencrypted, and subsequent commands detect this and skip the prompt. No flag needs to be passed again.

When `--no-passphrase` is set, `init` prints a banner before doing any work and requires the operator to type `yes` to proceed:

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

### Implementation notes

- Use `golang.org/x/crypto/ssh.MarshalPrivateKeyWithPassphrase` to write encrypted keys, `ssh.ParsePrivateKeyWithPassphrase` to read them. Detect encrypted-vs-not on read by trying unencrypted parse first and catching `*ssh.PassphraseMissingError`.
- Read passphrases from `/dev/tty` (via `golang.org/x/term`) so they aren't echoed and aren't visible to processes parsing argv. Never accept passphrases as a flag value. Accept `CERTHOLD_CA_PASSPHRASE` / `CERTHOLD_PEER_PASSPHRASE` env vars for automation.
- Wipe passphrase byte slices and unlocked-key material before command exit (`runtime.GC` is not enough; explicit zeroing of byte buffers where the key sits).
- For rekey, the operator may want to keep the same passphrase across the rotation; the command should default to reusing the entered passphrase for the new keys and accept `--rotate-passphrase` to prompt for a fresh one.


## User level vs root level scoping

When running in user mode:
The key trick is that cert-authority in ~/.ssh/authorized_keys is the user-space equivalent of TrustedUserCAKeys + AuthorizedPrincipalsFile combined.
A line like this in the target user's authorized_keys:
cert-authority,principals="manager,infra,databases" ssh-ed25519 AAAA...CA_PUBKEY...
tells sshd: accept any user cert signed by this CA, but only if the cert presents one of these principals. That single line replaces three things from your root design: the TrustedUserCAKeys directive, the AuthorizedPrincipalsFile directive, and the per-principal file. Group membership for inbound access is now just the comma-separated list inside principals="...", which certhold rewrites whenever you run group allow/disallow.
Adjusted peer layout, all under the target user's home:
~/.ssh/authorized_keys           # cert-authority line(s), principals inline
~/.ssh/id_ed25519                # peer's private key (outbound)
~/.ssh/id_ed25519-cert.pub       # CA-signed user cert (outbound)
~/.ssh/known_hosts               # pre-populated host keys for outbound
~/.ssh/config                    # CertificateFile + IdentityFile
No sshd reload needed for any change — authorized_keys is read per-connection. That's a nice simplification over the root version.
What you actually lose without root:
Host certificates are off the table. You can't sign sshd's host keys. The original design used host certs so peers could verify each other without TOFU via @cert-authority in ca_known_hosts.
Native KRL revocation is gone. RevokedKeys is an sshd_config directive only. Treat revocation as a rekey-style operation: rotate the CA, reissue to everyone except the revoked peer. Heavy but correct.


## Minimum openssh version

The features the design uses and when each landed:

Certificate authorities, TrustedUserCAKeys, HostCertificate, AuthorizedPrincipalsFile, @cert-authority, AuthorizedPrincipalsFile %u token — OpenSSH 5.4 (2010)
Binary KRLs, RevokedKeys pointing at a KRL file, ssh-keygen -k — OpenSSH 6.0 (2012)
ed25519 keys and certificates — OpenSSH 6.5 (2014)

**Effective floor: OpenSSH 6.5 (2014).** The install script appends certhold's directives directly to `/etc/ssh/sshd_config` and `/etc/ssh/ssh_config` between `# BEGIN certhold` / `# END certhold` sentinel markers, so neither `Include` (sshd 8.2 / ssh 7.3) nor `sshd_config.d/` are required.

Trade-off: every cert reissue, group edit, KRL push, and CA rekey still uses atomic file writes into `/etc/ssh/` over SSH (those touch their own files, not the main configs). Only the *initial install* mutates `/etc/ssh/sshd_config` and `/etc/ssh/ssh_config` in place via the sentinel-bracketed block; re-running the install script is idempotent because `sed` deletes any prior block before the new one is appended.

Distro coverage at 6.5+: RHEL/CentOS/Rocky/Alma 7+ (7.0 ships OpenSSH 6.6.1), Debian 8+ (Jessie ships 6.7), Ubuntu 14.04+ (ships 6.6), Fedora 21+, recent Arch/openSUSE — essentially anything still booting today.

## Out of scope for v1

Explicitly deferred:

- **DNS / hostname resolution.** Peers reach each other by IP for v1. A DNS server on certhold is a clear v2 addition.
- **Cert expiries.** Certs are issued without `-V`. The architecture supports adding TTLs later without changes — just start issuing with `-V +24h` and add a cert-refresh push to certhold's CLI.
- **Multiple users per device.** Every peer is a single identity. No user/host distinction.
- **Audit logging.** sshd logs locally on each peer. No central collection.
- **Web UI.** CLI only.
- **High availability.** Single manager, sqlite, no replication. If certhold dies, existing peers continue working (their certs are still valid); only new enrollments and changes are blocked until it's restored.

## Build order

1. **`init` and `enroll`** — get a peer online end-to-end. CA generation, token issuance, HTTP endpoint, tarball assembly, peer-side install script. Self-enrollment of certhold.
2. **`list`** — read the db, print state. Sanity check that the data model works.
3. **Push infrastructure** — the SSH client code in certhold that connects to a peer using certhold's cert, writes files atomically, reloads sshd. This is the foundation for everything below.
4. **`update`, `group allow`, `group disallow`** — use the push infrastructure to modify a single peer.
5. **`revoke` and KRL push** — multi-peer push, retry queue for offline peers.
6. **`rekey`** — the most complex operation. Build last when everything else is solid.

After step 1 you have a usable demo. After step 4 it's usable for daily homelab work. Steps 5–6 are robustness additions.

## Tech choices

- **Language**: Go. Single static binary, good ssh library (`golang.org/x/crypto/ssh`), easy to cross-compile if you ever want certhold on different architectures.
- **CA operations**: shell out to `ssh-keygen` for cert signing. It's the reference implementation, well-tested, and avoids reimplementing OpenSSH's cert format in Go.
- **Database**: sqlite via `mattn/go-sqlite3` or `modernc.org/sqlite` (pure Go, no cgo).
- **HTTP**: stdlib `net/http`. One endpoint, no framework needed.
- **TLS for the enroll endpoint**: self-signed cert is fine for v1 since the onboarding command can pin the fingerprint. Or skip TLS entirely and rely on the home network being trusted — the enroll token is the actual auth. **Implemented (T17)**: `serve` defaults to HTTPS with an auto-generated in-memory ed25519 self-signed cert; the SHA-256 fingerprint is printed at startup and the install one-liner uses `curl -k` to accept it.