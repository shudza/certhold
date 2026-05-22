# certhold

> Homelab SSH access manager. One binary on a bastion, OpenSSH on every other box, no per-device agent.

Certhold runs an SSH Certificate Authority. Every machine — including certhold itself — is a "peer" holding a CA-signed cert that names the groups it belongs to. `sshd` enforces access natively via principal matching. State changes (enroll, group edits, revoke, CA rotation) are pushed by certhold over SSH using its own peer cert. No expiries, no agents, no bespoke auth.

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
                          ssh (own cert) │            │ https (one-time tokens)
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

Trust flows one way: every peer trusts certs signed by the CA. Certhold itself is a peer (it self-enrols at `init`) holding a cert with a privileged `manager` principal that every peer accepts as root. All push operations use this cert.

### Data model

```
peers ───┬── peer_groups          (membership: groups in the peer's cert)
         └── peer_allowed_groups  (incoming: groups its sshd accepts)
tokens                            (single-use enrollment tokens)
ca                                (CA version history)
krl_version                       (monotonic KRL counter)
```

Membership and allowed-groups are deliberately separate. A peer in `infra` doesn't automatically accept incoming `infra` connections — the admin opts in via `group allow`.

## Getting started

```bash
# build
git clone https://github.com/shudza/certhold && cd certhold
make build && sudo cp ./bin/certhold /usr/local/bin/

# on the manager box
certhold init                            # generate CA, self-enroll
certhold serve --addr :8443 &            # run the HTTP enroll endpoint

# add a peer
certhold enroll vm1 --groups infra,databases
# → prints: curl -fsSL https://certhold.home.lan/enroll/<token>.sh | bash
# paste that one-liner on vm1 as root. done.
```

Common operations after onboarding:

```bash
certhold list                            # show peers and their groups
certhold update vm1 --groups infra       # change membership
certhold group allow databases --on vm1  # open incoming access
certhold revoke vm1                      # add to KRL, push to remaining peers
certhold rekey                           # rotate the CA
```

Full reference: see [USAGE.md](USAGE.md). Design rationale and blast-radius discussion: [PLAN.md](PLAN.md).

## Status

v1. Tested across all components with race-enabled unit tests. SSH push has an end-to-end test gated by `CERTHOLD_E2E=1`. Production-readiness for non-homelab use needs the CA hardening discussed in PLAN.md.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
