.PHONY: build test vet

build:
	go build -o ./bin/certhold ./cmd/certhold

test:
	go test ./...

vet:
	go vet ./...
