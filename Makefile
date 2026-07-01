BINARY := coen
PKG := github.com/baspeters/coen
VERSION ?= dev
LDFLAGS := -X $(PKG)/internal/cli.Version=$(VERSION)

.PHONY: build build-linux test vet tidy
build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/coen
build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/coen
test:
	go test ./...
vet:
	go vet ./...
tidy:
	go mod tidy
