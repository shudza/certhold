# Peer file layout

The exact files certhold installs on a peer, with permissions and contents.
Certhold has a single trust model: everything lands under the **target user's**
`~/.ssh/`. The tarball is built and signed by `enroll` and delivered once during
[onboarding](usage.md#onboarding-a-peer). Tarball entries are reproducible
(ownership comes from the extracting user, not baked in).

> **Managing root.** There is no separate "root mode". To manage `root`, enroll
> with `--user root` and run the install one-liner **as root**: the script reads
> `$HOME` (`/root`) and `id -un` (`root`), so the files land in `/root/.ssh/` and
> stock `sshd` honors the `cert-authority` line for root logins. No
> `sshd_config` change, no host certificate, no reload.

## Where the files go

Everything lands under `<home>/.ssh/`, where `<home>` is the target user's home
(`/root/.ssh/` for `--user root`, `/home/<user>/.ssh/` otherwise). Certhold makes
**no changes to `sshd_config` and triggers no `sshd` reload**, so an unprivileged
operator who can write their own home can install it — and managing root is the
same flow run as root.

Identity files are **namespaced by the instance key** (16 lowercase hex chars,
stored in `meta.instance_key`, generated at first `init`/`enroll` and **never
changed by rekey**) so multiple certhold instances can manage the same peer
without colliding. The inbound `cert-authority` line and the outbound client
block are **per-instance** and isolated. Tarball entries (relative to
`<home>/.ssh/`):

| File | Mode | Contents |
|---|---|---|
| `id_ed25519_<key>` | `0600` | This instance's outbound private key (newly generated per enroll). |
| `id_ed25519_<key>-cert.pub` | `0644` | CA-signed user certificate for that key. |
| `known_hosts` | `0644` | Outbound host trust; **empty** by default (TOFU). |
| `config` | `0644` | This instance's keyed SSH client block (below). |
| `ca_authorized_keys` | `0644` | The `cert-authority` line for this instance's CA; the install script **appends** it to `authorized_keys` idempotently and then removes this staging file. |

A whole `authorized_keys` file is **never shipped** — the install script appends
this instance's line only if its CA pubkey isn't already trusted (grep-guarded),
so other instances' lines (and any pre-existing keys) survive.

## `authorized_keys` — the inbound trust line

`authorized_keys` carries a single `cert-authority` line per certhold instance —
`manager` first (always, deduped), then the peer's allowed groups, followed by
the CA public key:

```
cert-authority,principals="manager,infra,databases" ssh-ed25519 AAAA… certhold-ca
```

`manager` is what gives certhold standing inbound access; the group list is what
`group allow`/`disallow` and `update` rewrite in place on a live peer. Because
`sshd` reads `authorized_keys` per connection, these edits need **no reload** —
and for a `--user root` peer this same line in `/root/.ssh/authorized_keys` is
what grants root logins.

## `config` — the keyed client block

The keyed sentinel block is **not** a tarball file you drop in whole — the
install script splices it into `<home>/.ssh/config`:

```
# BEGIN certhold <key> v2
# <6-line comment header: managed-by note, what the block does, why the key
#  namespaces it, and how to refresh via the enroll one-liner>
Host *
    CertificateFile ~/.ssh/id_ed25519_<key>-cert.pub
    IdentityFile ~/.ssh/id_ed25519_<key>
    UserKnownHostsFile ~/.ssh/known_hosts
# END certhold <key> v2
```

The comment header is part of the spliced block (see `V2SshClientBlock` in
`internal/peerfiles/layout.go`), so a human inspecting `~/.ssh/config` sees who
owns the range and how to refresh it. The key precedes the version so the
install splice uses a **per-instance, version-agnostic** `sed`:

```
sed -i -E "/^# BEGIN certhold <key>( v[0-9]+)?$/,/^# END certhold <key>( v[0-9]+)?$/d" <home>/.ssh/config
```

which removes only *this* instance's block before re-appending — other instances'
blocks are untouched.

> **Known limitation (`Host *` first-match).** Each instance contributes its own
> `Host *` block. SSH applies the **first** match per option, so when an outbound
> connection could use more than one instance's identity, `CertificateFile` /
> `UserKnownHostsFile` resolve to the first block in `config`. `IdentityFile`
> lines are additive (SSH tries each), so authentication still works; this only
> affects which cert/known_hosts file is *preferred*. Acceptable for leaf peers.

## The install script

Under `set -e`, the install script:

1. resolves the invoking user (`id -un`) and home (`$HOME`) — running it as root
   targets `/root/.ssh`, as any other user targets that user's `~/.ssh`;
2. creates and `chmod 700`s `<home>/.ssh`, fetches and unpacks the tarball into a
   staging dir (`curl -kfsSL …?user=<user> | tar -xz`);
3. installs the namespaced key (`0600`) and cert (`0644`), then runs the optional
   [peer-key passphrase step](security.md#per-peer-passphrases-install-side);
4. appends `ca_authorized_keys` to `authorized_keys` **only if** this instance's
   CA pubkey isn't already trusted (grep-guarded), so other instances survive;
5. splices the keyed `config` block (per-instance `sed` delete + append) and
   removes the staging dir.

It does **not** edit `sshd_config`, ships **no** `TrustedUserCAKeys` /
`AuthorizedPrincipalsFile` / `RevokedKeys` / `HostCertificate` directives, and
**never reloads `sshd`**.

## The manager's own files

At `init`, certhold writes its own files under `<data-dir>/self/<home>/.ssh/`
(`<data-dir>/self/root/.ssh/` for `--user root`, otherwise
`<data-dir>/self/home/<user>/.ssh/`): the namespaced identity pair, a local
`authorized_keys` mirror, the `known_hosts`, and the keyed `config` block. The
manager uses these directly for its outbound pushes; to make the manager itself
reachable as a peer, copy them into the real `~/.ssh/` (see
[usage.md](usage.md#activating-the-manager-as-a-peer)). `EnsureInstanceKey`
backfills the per-instance key on an upgraded DB.
