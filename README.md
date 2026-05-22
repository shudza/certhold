# certhold

Certhold is a homelab SSH access manager. A single Go binary runs an SSH certificate authority on one manager machine, signs peer certs, and pushes configuration to peers over SSH. Peers run nothing beyond OpenSSH; access between peers is enforced by `sshd` via CA-signed certs and group principal matching. See [PLAN.md](PLAN.md) for the full design.

## Build

```
make build
```

This produces `./bin/certhold`.

## Test

```
make test
make vet
```
