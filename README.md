# certhold

> Certificate-based SSH access manager for private networks. One binary issues and pushes SSH certificates to every device; OpenSSH enforces access. No per-device daemon.

certhold manages who can SSH into what across a network, using SSH certificates instead of scattered `authorized_keys` files and hand-copied keys.

You run a single binary on one machine — the **manager**. It stands up an SSH certificate authority and onboards every other device with one pasted command. Each device (a **peer**) receives a certificate that names the **groups** it belongs to. Access is group-based: you declare which groups a machine accepts connections from, and any device in one of those groups can connect — no key distribution, no per-host edits.

Grant, change, and revoke access centrally from the manager; changes reach peers by SSH push, or — for **client-style peers** the manager never dials, like laptops — by an on-demand pull (`certhold-cli refresh`). Peers run no daemon and nothing resident: a peer is OpenSSH plus a handful of files, and client-style peers additionally get a small on-demand bash CLI. No scheduled rotation to babysit.

- **Two-command onboarding** — `certhold enroll <name>`, then paste one `curl … | bash` on the new device.
- **Group-based access** — membership and inbound access are just principals on a cert, edited centrally.
- **Client-style peers** — `enroll <name> --client` for devices that should accept no inbound SSH (laptops, workstations): the manager never dials them; they fetch renewed certs themselves with `certhold-cli refresh`.
- **Name-based ssh** — each peer's `~/.ssh/config` gains a `Host` alias per peer it may reach, so `ssh app1` works by name.
- **Central revocation & CA rotation** — cut off a device, or roll the whole trust root, from one command.
- **Interactive TUI** — `certhold tui` is a full-fleet dashboard that also drives the mutating flows in place (enroll, regroup, revoke, rekey, group CRUD, multi-select batch), plus live status and reachability views; `--read-only` for a safe, write-free dashboard.
- **Runs anywhere OpenSSH does** — effective floor is OpenSSH 6.5 (2014); see [docs/architecture.md](docs/architecture.md#requirements--compatibility).

## Architecture

Two things exist in the system: **certhold** (a Go binary on one machine) and **peers** (any Linux box with OpenSSH and curl).

```
                                ┌─────────────────────────────────┐
                                │           certhold              │
                                │  ┌──────────┐  ┌────────────┐   │
                                │  │   CLI    │  │ HTTP /enroll│  │
                                │  └────┬─────┘  └─────┬──────┘   │
                                │       │              │          │
                                │  ┌────┴───────────┐  │          │
                                │  │  CA private    │  │          │
                                │  │     key        │  │          │
                                │  └────────────────┘  │          │
                                │  ┌────────────────┐  │          │
                                │  │  SQLite state  │  │          │
                                │  └────────────────┘  │          │
                                └────────┬────────────┬┴──────────┘
                                         │            │
                          ssh (own cert) │            │ https (enroll + pull tokens)
                                         │            │
                ┌────────────────────────┴────────────┴──────────────┐
                │                                                    │
                ▼                                                    ▼
        ┌──────────────┐                                     ┌──────────────┐
        │   peer A     │  ─── sshd (CA-signed) ──────────►   │   peer B     │
        │  /etc/ssh/   │     principal match on groups       │  /etc/ssh/   │
        │  peer cert   │  ◄──────────────────────────────    │  peer cert   │
        └──────────────┘                                     └──────────────┘
```

Trust flows one way: every peer trusts certs signed by the CA. Certhold itself is a peer (it self-enrols at `init`) holding a cert with a privileged `manager` principal that push-managed peers accept; all push operations use this cert. Peers enrolled `--client` install no inbound trust at all — nobody, the manager included, can SSH into them — and instead pull refreshed material from `serve` with `certhold-cli`.

## Installation

```bash
git clone https://github.com/shudza/certhold && cd certhold
make build                                   # → ./bin/certhold
sudo cp ./bin/certhold /usr/local/bin/
```

Building certhold needs Go. A peer needs only OpenSSH 6.5+ and `curl` — see [docs/architecture.md](docs/architecture.md#requirements--compatibility) for the full version and distro matrix.

## Getting started

Set up the manager, enroll two peers, and connect between them.

**1. Bootstrap the manager** (one time):

```bash
certhold init                 # generate the CA, self-enroll, pick the interface peers reach you on
                              #   → prompts for an at-rest passphrase and prints the base url, e.g.
                              #     base url: https://192.168.1.10:8443
certhold serve --addr :8443   # run the enroll endpoint over HTTPS (self-signed). Leave it running.
```

To keep `serve` running across reboots and crashes, install it as a systemd
service: `sudo certhold install` writes and enables `certhold.service` (running
`serve` unprivileged as your user). See [docs/usage.md](docs/usage.md#install).
Keeping it up matters beyond onboarding: client-style peers fetch their cert
refreshes from `serve` whenever they run `certhold-cli refresh`.

**2. Enroll two peers** from the manager, both in the `infra` group. Groups are
created explicitly — `init` bootstraps `manager`, every other group is
operator-created:

```bash
certhold group create infra
certhold enroll app1 --groups infra
# → curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
certhold enroll app2 --groups infra
# → curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
```

**3. Onboard each peer** by pasting its own one-liner on that machine, as the user that should own the SSH files:

```bash
# on app1 (192.168.1.11)
curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
# on app2 (192.168.1.12)
curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
```

Each install drops a CA-signed cert plus SSH config into that user's `~/.ssh/`. Nothing else to configure.

**4. Connect between peers.** Both are members of `infra` and, by default, accept incoming connections from `infra`, so they can reach each other immediately:

```bash
# from app1, ssh into app2 as the user that onboarded it:
[app1]$ ssh deploy@192.168.1.12
# app1 presents its CA-signed cert; app2's sshd accepts it because the cert
# carries the "infra" principal, which app2 allows. No password, no copied keys.
# (accept the host key on first connect — peers bootstrap host trust via TOFU.)
```

Each peer's `~/.ssh/config` also gains a `Host <name>` alias (recorded address + login user) for every peer it may reach, so `ssh app2` works by name — aliases land at install time and are refreshed by later pushes or `certhold-cli refresh` as the fleet grows.

**5. Optional — enroll a client-style peer**, e.g. a laptop that should accept no inbound SSH:

```bash
certhold enroll laptop --groups infra --client
# → curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
#   client-style peer; manager cannot push to it; updates arrive via `certhold-cli refresh`.
```

Onboard it with the one-liner as usual; the install additionally drops `certhold-cli` into `~/.local/bin/`. The laptop can `ssh` into `infra` peers like any other member, but nothing — the manager included — can SSH into it. Since the manager cannot push to it, the laptop pulls fleet changes itself (keep `serve` running for this):

```bash
[laptop]$ certhold-cli status     # shows identity, cert serial, and staleness vs the manager
[laptop]$ certhold-cli refresh    # pulls the latest cert + config from serve
```

That is the whole loop: onboard each device with one command, and same-group peers trust each other through the CA.

## Usage

Day-to-day operations, all run on the manager:

```bash
certhold list                              # peers, their group membership, and who may connect in
certhold group create web                  # create a group (required before any enroll/update/allow that references it)
certhold group show web                    # who's in "web" and who allows it inbound
certhold update app1 --groups infra,web    # change a peer's group membership (reissues its cert)
certhold group allow web --on app2         # let "web" members SSH into app2
certhold group disallow web --on app2      # …and take it back
certhold group rename web frontend         # rename a group; cascades to every member's cert and every allow-list peer
certhold group delete web                  # delete a group; cascades to every member's cert and every allow-list peer
certhold revoke app1                       # cut app1 off the network
certhold rekey                             # rotate the CA (e.g. after a suspected key leak)
```

Membership (what a peer *is*) and allowed-groups (who it *accepts*) are independent: `update` changes the former, `group allow`/`disallow` the latter. Full reference in [docs/usage.md](docs/usage.md).

## Philosophy

certhold is built for **intranets** — home networks, homelabs, and small private fleets where you own all the machines and just want them to trust each other without managing keys by hand. It treats SSH access as a *certificate* problem, not a key-distribution problem: one CA, group-based principals, central control, and OpenSSH doing all the enforcement.

The design leans into that setting:

- **No per-device daemon.** A peer is stock OpenSSH plus a handful of files — nothing resident, nothing to keep running. Client-style peers get one extra file, `certhold-cli`, a small bash script run on demand; still no daemon, no service, no schedule.
- **No key sprawl.** You never copy public keys between hosts. Belonging to a group is enough to connect; the CA vouches for it.
- **Central, simple control.** Enroll, regroup, revoke, and rotate from one machine. State is a single SQLite db plus a CA key.

It is deliberately *not* an enterprise zero-trust platform. There is one manager (no HA), no central audit pipeline, and certs don't expire by default — revocation is the kill switch. Those trade-offs keep it small enough to run and reason about on a home network. For the trust-root blast radius and hardening options, see [docs/security.md](docs/security.md).

## Status

v1. Tested across all components with race-enabled unit tests. SSH push has an end-to-end test gated by `CERTHOLD_E2E=1`. Production-readiness beyond a trusted private network needs the CA hardening discussed in [docs/security.md](docs/security.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
