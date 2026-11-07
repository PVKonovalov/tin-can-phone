# tin-can-phone

Self-hosted multi-user audio calls in the browser, shipped as a single Go binary.
Hard rule: **no external infrastructure at runtime**: no public STUN/TURN, CDNs,
third-party fonts or analytics. Everything the client needs comes from your server.
It works on the Internet (public IP + domain, Let's Encrypt) and in isolated
LAN/VPN networks (the server runs its own CA).

> Status: step 1 of the [roadmap](docs/ROADMAP.md). The server skeleton, TLS modes
> and the placeholder page are done; calls are not implemented yet.

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
`.data/selfca/`. `localhost` and `127.0.0.1` are always included; on macOS the
Makefile also adds the LAN IP of `en0` by default.

```sh
curl --cacert .data/selfca/ca.crt https://localhost:8443/healthz
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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/ROADMAP.md](docs/ROADMAP.md) for what comes next.

## License

MIT, see [LICENSE](LICENSE).
