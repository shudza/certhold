.PHONY: build test vet static clean

build:
	go build -o ./bin/certhold ./cmd/certhold

test:
	go test ./...

vet:
	go vet ./...

static:
	mkdir -p ./dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ./dist/certhold-linux-amd64 ./cmd/certhold
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o ./dist/certhold-linux-arm64 ./cmd/certhold
	cd ./dist && sha256sum certhold-linux-amd64 certhold-linux-arm64 > SHA256SUMS

clean:
	rm -rf ./bin ./dist
