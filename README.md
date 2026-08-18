# certhold

> SSH access for your private network, without the key juggling. Runs on top of OpenSSH.

You know the spiderweb. Which key sits in which `authorized_keys`. Which of the five `root`s in your known_hosts is which box. What breaks when a rebuilt VM changes its host key.

certhold ends it. One binary runs an SSH certificate authority. One pasted command onboards each device. After that, `ssh remote1` just works — no passwords, no copied keys, and one place to turn access off.

- **It's just OpenSSH.** No tunnels, no new protocol, nothing in the data path. `sshd` enforces every connection.
- **No agents.** A peer is stock OpenSSH plus a few files in `~/.ssh`. Nothing resident, nothing to babysit. OpenSSH 6.5+ (2014) qualifies.
- **No cert juggling.** Enroll mints and installs the cert. Revoke kills it fleet-wide. Rekey rotates everything. You never look at a certificate.
- **A real TUI.** `certhold tui` — the whole fleet on one screen, every operation without leaving it.

![certhold tui — fleet dashboard, peer detail, groups, status and live reachability](docs/assets/tui.gif)

## Getting started

On the machine that will be the manager:

```bash
certhold init                 # creates the CA, prints your base url
certhold serve --addr :8443   # onboarding endpoint; leave it running
                              # (sudo certhold install makes it a systemd service)
```

Enroll a device — this mints its certificate and prints a one-liner:

```bash
certhold group create infra
certhold enroll remote1 --groups infra
# → curl -kfsSL https://192.168.1.10:8443/enroll/<token>.sh | bash
```

Paste that one-liner on `remote1`. That's the entire device-side setup. Do the same for `remote2`, then from either machine:

```bash
[remote1]$ ssh remote2
```

Done. Both are in `infra`, so they trust each other — the CA vouches, `sshd` verifies, and the `ssh remote2` alias was written at install.

Your laptop gets the same treatment, with one twist — it should reach servers, but nothing should reach it:

```bash
certhold enroll laptop --groups infra --client
```

A client-style peer accepts no inbound SSH at all (not even from the manager) and picks up fleet changes itself with `certhold-cli refresh`, a small script installed alongside the cert.

## Day two

Everything runs from the manager — `certhold tui` interactively, or the CLI:

```bash
certhold list                              # the whole fleet at a glance
certhold update remote1 --groups infra,media   # change what a peer is
certhold group allow media --on remote2        # change who a peer lets in
certhold revoke laptop                     # lost device? gone fleet-wide, one command
certhold rekey                             # suspected CA leak? rotate the trust root
```

Access is group-based: a cert names the groups a device belongs to, each device declares which groups it lets in, and both sides are edited centrally. Full reference in [docs/usage.md](docs/usage.md).

## What it is (and isn't)

Built for networks where you own all the machines — a homelab, a home network, a small fleet. That focus keeps it small: one manager, no HA, no audit pipeline, no OAuth, no cloud. Certs don't expire by default; revocation is the kill switch. If you need enterprise zero-trust, this isn't it. If you need `ssh remote1` to work and one place to cut access, it is.

Trust model and hardening: [docs/security.md](docs/security.md). Design: [docs/architecture.md](docs/architecture.md).

## Installation

```bash
git clone https://github.com/shudza/certhold && cd certhold
make build                                   # → ./bin/certhold
sudo cp ./bin/certhold /usr/local/bin/
```

Building needs Go; that's the only machine that needs anything beyond OpenSSH and `curl`.

## Status

v1. Race-enabled unit tests across all components, plus a docker-compose end-to-end suite doing live SSH. Production use beyond a trusted private network needs the CA hardening in [docs/security.md](docs/security.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
