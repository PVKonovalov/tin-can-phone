VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/tincan

# Extra SANs for the selfca server certificate (comma-separated DNS names / IPs).
# Defaults to the primary LAN IP on macOS so phones on the same network can connect.
SELFCA_SANS ?= $(shell ipconfig getifaddr en0 2>/dev/null)
# Name constraints of the dev CA: loopback plus the private IPv4 ranges.
SELFCA_PERMITTED ?= localhost,127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
# Media: announce the LAN IP (and loopback for same-machine browsers).
ADVERTISE_IPS ?= $(subst $() ,$(comma),$(strip $(shell ipconfig getifaddr en0 2>/dev/null) 127.0.0.1))
MEDIA_PORT ?= 50000
comma := ,

.PHONY: build test e2e run-selfca clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/tincan

test:
	go vet ./...
	go test -race ./...

# Browser end-to-end tests (Playwright, Node). Not part of `make test`.
# E2E_MIC=synthetic replaces the fake capture device with a WebAudio tone,
# for environments where Chrome cannot open capture devices at all.
e2e:
	cd e2e && npm ci --no-audit --no-fund && npx playwright install chromium
	cd e2e && TINCAN_E2E_MIC=$(E2E_MIC) npx playwright test

run-selfca:
	TINCAN_TLS_MODE=selfca \
	TINCAN_HTTPS_ADDR=:8443 \
	TINCAN_HTTP_ADDR=:8080 \
	TINCAN_SELFCA_DIR=./.data/selfca \
	TINCAN_SELFCA_SANS='$(SELFCA_SANS)' \
	TINCAN_SELFCA_PERMITTED='$(SELFCA_PERMITTED)' \
	TINCAN_PUBLIC_HTTP_PORT=8080 \
	TINCAN_MEDIA_PORT=$(MEDIA_PORT) \
	TINCAN_ADVERTISE_IPS='$(ADVERTISE_IPS)' \
	go run -ldflags '-X main.version=$(VERSION)' ./cmd/tincan

clean:
	rm -rf bin
