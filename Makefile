VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/tincan

# Extra SANs for the selfca server certificate (comma-separated DNS names / IPs).
# Defaults to the primary LAN IP on macOS so phones on the same network can connect.
SELFCA_SANS ?= $(shell ipconfig getifaddr en0 2>/dev/null)

.PHONY: build test run-selfca clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/tincan

test:
	go vet ./...
	go test -race ./...

run-selfca:
	TINCAN_TLS_MODE=selfca \
	TINCAN_HTTPS_ADDR=:8443 \
	TINCAN_HTTP_ADDR=:8080 \
	TINCAN_SELFCA_DIR=./.data/selfca \
	TINCAN_SELFCA_SANS='$(SELFCA_SANS)' \
	go run -ldflags '-X main.version=$(VERSION)' ./cmd/tincan

clean:
	rm -rf bin
