# tin-can-phone

Self-hosted multi-user audio calls in the browser, shipped as a single Go binary.
Hard rule: **no external infrastructure at runtime**: no public STUN/TURN, CDNs,
third-party fonts or analytics. Everything the client needs comes from your server.
It works on the Internet (public IP + domain, Let's Encrypt) and in isolated
LAN/VPN networks (the server runs its own CA).

> Status: step 2 of the [roadmap](docs/ROADMAP.md). TLS modes, rooms and WebSocket
> signaling are done; audio (the SFU) is not implemented yet.

## Build

Requires Go 1.26+.

```sh
make build   # -> bin/tincan
make test    # go vet + go test -race
```

## Run locally (`selfca` mode)

```sh
make run-selfca                              # HTTPS :8443, HTTP :8080
make run-selfca SELFCA_SANS=192.168.1.10,tincan.lan
```

On first start the server creates a local CA and a server certificate in
`.data/selfca/`. The CA is name-constrained to `localhost`, loopback and the
private IPv4 ranges (`SELFCA_PERMITTED` in the Makefile), so it cannot vouch for
public sites. On macOS the Makefile also adds the LAN IP of `en0` to the server
certificate. If you change `SELFCA_PERMITTED` (or still have a CA from an older
build), the server refuses to start: delete `.data/selfca` and reinstall the CA.

```sh
curl --cacert .data/selfca/ca.crt https://localhost:8443/healthz
curl --cacert .data/selfca/ca.crt -X POST https://localhost:8443/api/rooms
open http://localhost:8080/install          # CA install instructions per OS
```

To use it from a phone on the same network, open `http://<lan-ip>:8080/install`,
install and trust the CA (check the SHA-256 fingerprint against the server log),
then open `https://<lan-ip>:8443/`.

## Configuration

All settings are environment variables with the `TINCAN_` prefix:

| Variable | Default | Notes |
|---|---|---|
| `TLS_MODE` | (required) | `acme`, `files` or `selfca` |
| `HTTPS_ADDR`, `HTTP_ADDR` | `:443`, `:80` | |
| `PUBLIC_URL` | | optional, `https://host[:port]` |
| `TLS_CERT`, `TLS_KEY` | | `files` mode; send `SIGHUP` to reload |
| `ACME_DOMAINS`, `ACME_EMAIL`, `ACME_CACHE_DIR` | cache: `.data/acme` | `acme` mode; port 80 must be reachable |
| `SELFCA_DIR`, `SELFCA_SANS` | dir: `.data/selfca` | `selfca` mode |
| `SELFCA_PERMITTED` | (required for `selfca`) | CA name constraints: DNS suffixes + CIDRs |
| `PUBLIC_HTTP_PORT` | `80` | external HTTP port for the `selfca` install link |
| `MAX_PEERS`, `MAX_ROOMS`, `ROOM_TTL` | `8`, `1000`, `30m` | room limits |
| `ALLOWED_ORIGINS` | origin of `PUBLIC_URL` | WebSocket Origin allow-list |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/ROADMAP.md](docs/ROADMAP.md) for what comes next.

## License

MIT, see [LICENSE](LICENSE).
