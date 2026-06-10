.PHONY: build test vet e2e e2e-systemd static clean

build:
	go build -o ./bin/certhold ./cmd/certhold

test:
	go test ./...

# Real end-to-end suite: spins up docker compose (manager + 2 sshd peers) and
# asserts on live SSH trust. Requires a Docker daemon + `docker compose`; the
# tests are gated behind the `e2e` build tag so plain `make test` never runs them.
e2e:
	go test -tags e2e -count=1 -timeout 20m ./test/e2e/...

# Host-level install e2e: requires systemd + passwordless sudo and MUTATES the
# host (installs/removes certhold.service). Gated behind the e2e_systemd tag.
e2e-systemd:
	go test -tags e2e_systemd -count=1 -timeout 5m ./test/e2e/...

vet:
	go vet ./...

static:
	mkdir -p ./dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ./dist/certhold-linux-amd64 ./cmd/certhold
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o ./dist/certhold-linux-arm64 ./cmd/certhold
	cd ./dist && sha256sum certhold-linux-amd64 certhold-linux-arm64 > SHA256SUMS

clean:
	rm -rf ./bin ./dist
