# Agent prompt — Step 1: Skeleton, configuration, TLS modes

## Context

Read `docs/ARCHITECTURE.md` and `docs/ROADMAP.md` first. The repository is empty
apart from LICENSE/README. This step builds the server skeleton only — **no rooms,
no WebSocket, no WebRTC** (steps 2–3).

Hard requirement for the whole project: **no external infrastructure at runtime**
(no CDNs, external fonts, public STUN, analytics). ACME is allowed only for
issuing certificates in `acme` mode.

## Task

1. `go mod init github.com/PVKonovalov/tin-can-phone`, current stable Go.
   Dependencies: standard library + `golang.org/x/crypto/acme/autocert` only.
   Logging with `log/slog`.
2. `internal/config`: parse `TINCAN_*` variables from the ARCHITECTURE table that
   are relevant now (`PUBLIC_URL`, `HTTPS_ADDR`, `HTTP_ADDR`, `TLS_MODE`,
   `TLS_CERT`, `TLS_KEY`, `ACME_DOMAINS`, `ACME_EMAIL`, `ACME_CACHE_DIR`,
   `SELFCA_DIR`, `SELFCA_SANS`). Validate per mode, return all errors at once,
   print effective config (without secrets) at startup.
3. `internal/tlsmode` — returns a `*tls.Config` and the port-80 handler:
   - `files`: load cert/key; reload on SIGHUP.
   - `acme`: `autocert.Manager` with `HostWhitelist(ACME_DOMAINS)`, `DirCache`;
     port 80 = `manager.HTTPHandler(redirect-to-https)`.
   - `selfca`:
     - On first start create in `SELFCA_DIR`: CA (ECDSA P-256, 10 years,
       `IsCA`, `MaxPathLen 0`, name "tin-can-phone local CA <hostname>") and a
       server cert signed by it (ECDSA P-256, **validity 397 days**, EKU
       serverAuth, SANs from `SELFCA_SANS` — DNS names and IPs, `localhost` and
       `127.0.0.1` always included). Files 0600, directory 0700.
     - On later starts reuse them; re-issue the server cert (same CA) if it
       expires in < 30 days or the SAN list changed.
     - Port 80 serves only: `/install` (HTML page with instructions for
       Android, iOS, Windows, macOS, Linux, and the CA SHA-256 fingerprint),
       `/ca.crt` (`application/x-x509-ca-cert`), `/ca.mobileconfig`
       (`application/x-apple-aspen-config`, payload type
       `com.apple.security.root`, unsigned). Everything else → 308 to HTTPS.
     - The HTTPS page shows a link to `/install` (via the HTTP URL) for users who
       had to click through a warning.
   - TLS 1.2 minimum.
4. HTTPS server (`cmd/tincan`):
   - `web/` embedded via `go:embed`: placeholder `index.html` + `style.css`
     (no external resources), served at `/`.
   - `GET /healthz` → `200 {"status":"ok","version":...}` (version via `-ldflags`).
   - Security headers: HSTS (not in `selfca` mode), `Content-Security-Policy`
     with `default-src 'self'`, `X-Content-Type-Options`, `Referrer-Policy`,
     `Permissions-Policy: microphone=(self)`.
   - Sensible timeouts (`ReadHeaderTimeout` etc.).
   - Graceful shutdown on SIGINT/SIGTERM for both listeners.
5. `Makefile`: `build`, `test`, `run-selfca` (local run on unprivileged ports
   `:8443`/`:8080`, `SELFCA_DIR=./.data/selfca`). Add `.data/` to `.gitignore`.
   Add `.idea/workspace.xml` to `.gitignore`.
6. Short `README.md`: what it is, build, run locally in `selfca` mode, link to docs.

## Tests (required)

- config: valid and invalid combinations for each mode; all errors reported.
- selfca: chain verifies with `x509.Verify` for every SAN; restart reuses the CA;
  re-issue on near expiry and on SAN change keeps the same CA; file permissions.
- port-80 handlers: `/ca.crt`, `/ca.mobileconfig` (content types, parseable),
  `/install`, redirect of other paths with path+query preserved.
- HTTPS: `/healthz`, `/` and security headers via `httptest.NewTLSServer`
  or a real listener on `127.0.0.1:0`.
- `go vet ./...` clean, `go test -race ./...` green.

## Done when

- `make test` is green.
- `make run-selfca` starts; `curl --cacert .data/selfca/ca.crt https://localhost:8443/healthz`
  returns ok; `http://localhost:8080/install` shows the install page.
- From a phone on the same LAN (with `SELFCA_SANS` containing the Mac's LAN IP),
  after installing the CA, `https://<lan-ip>:8443/` opens without warnings.

## Out of scope

Rooms, WebSocket, WebRTC, PWA, Docker/systemd (later steps).

## On completion

Update the step 1 status in `docs/ROADMAP.md` and `docs/ROADMAP.ru.md`, move this
file to `docs/executed/`, and list anything deferred or decided differently.
