# Agent prompt — Step 2: Rooms and WebSocket signaling

## Context

Read `docs/ARCHITECTURE.md`, `docs/ROADMAP.md` and `docs/executed/AGENT_PROMPT_1_SKELETON.md`.
Step 1 (skeleton, TLS modes) is done. This step adds rooms and the signaling
channel, plus two small `selfca`/URL fixes (sections 0 and 0b). **No WebRTC yet** — the SFU arrives in step 3 and must plug into what you
build here without reworking it.

Same hard rule: no external infrastructure at runtime.

## 0. Fix from step 1: external ports

Redirects and the install link are built from the *listen* ports. Behind port
forwarding (e.g. external 443 → internal 8443) they point to the wrong port.

- If `PUBLIC_URL` is set, the HTTP→HTTPS redirect uses its host and port
  (path and query preserved). Without `PUBLIC_URL` keep the current behaviour.
- New optional `TINCAN_PUBLIC_HTTP_PORT` (default `80`) — external plain-HTTP
  port used to build the `selfca` install link.
- Tests for both cases.

## 0b. `selfca`: name-constrained CA

A CA root installed and trusted on users' devices must not be able to vouch for
arbitrary sites if `ca.key` leaks. Restrict it with X.509 name constraints to a
zone and address ranges (not to exact names, so renaming servers inside the zone
does not need a new CA).

- New variable `TINCAN_SELFCA_PERMITTED` — comma-separated DNS suffixes and
  CIDRs, e.g. `tincan.lan,localhost,10.0.0.0/8,127.0.0.0/8`. **Required in
  `selfca` mode.** `make run-selfca` sets a sensible dev value
  (`localhost,127.0.0.0/8,::1/128` plus the private ranges `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`).
- CA certificate:
  - `PermittedDNSDomains` from the DNS entries, `PermittedIPRanges` from the CIDRs,
    `PermittedDNSDomainsCritical = true`;
  - constraints apply per name type, so if no CIDR is given, set
    `ExcludedIPRanges` to `0.0.0.0/0` and `::/0`; at least one DNS suffix is
    required (`localhost` counts);
  - `ExtKeyUsage = [serverAuth]` on the CA as well.
- Validation at startup: every entry of `SELFCA_SANS` must lie inside the
  permitted set, otherwise a config error that names the offending entries.
- Existing CA whose constraints differ from the config (including the
  unconstrained CA from step 1 dev runs): **refuse to start** with a message that
  the CA must be recreated (delete `SELFCA_DIR`) and reinstalled on every device.
  Never replace it silently. Changing only `SELFCA_SANS` within the permitted set
  still just re-issues the server certificate.
- `/install` page shows the permitted zone and ranges next to the fingerprint.
- Document in `ARCHITECTURE.md` (config table and the `selfca` section).

Tests:

- Chain verifies with `x509.Verify` for every SAN inside the constraints.
- A leaf signed by the same CA for `example.com` and for `8.8.8.8` fails
  verification (sign it in the test directly with the CA key).
- No CIDR configured → a leaf with any IP SAN fails.
- SAN outside the permitted set → config error.
- Existing CA with different (or no) constraints → startup refusal; same
  constraints → reused.

Done-when addition: after reinstalling the new CA, the LAN page opens without
warnings on an iPhone and an Android phone (both platforms honour name
constraints; record the result in the completion notes).

## 1. Configuration

Add to `internal/config` (validated, logged at startup):

| Variable | Default | Meaning |
|---|---|---|
| `MAX_PEERS` | 8 | participants per room (2…32) |
| `MAX_ROOMS` | 1000 | rooms in memory at once |
| `ROOM_TTL` | 30m | an empty room (including never joined) is removed after this |
| `ALLOWED_ORIGINS` | origin of `PUBLIC_URL`; if unset — same host as the request | WebSocket Origin allow-list, comma-separated |

## 2. REST

- `POST /api/rooms` → `201 {"roomId": "...", "url": "https://.../room/<id>"}`.
  - Room ID: 128 bits from `crypto/rand`, lowercase base32 without padding.
  - URL from `PUBLIC_URL`; without it, from the request `Host` (https).
  - Rate limit per client IP (token bucket, e.g. 10/min, burst 5) → `429` with
    `Retry-After`. `MAX_ROOMS` reached → `503`.
- `GET /api/rooms/{id}` → `200 {"roomId", "peers": n, "maxPeers"}` or `404`.
- `GET /room/{id}` → serves `index.html` (the UI decides what to show; it will
  call `GET /api/rooms/{id}`). Validate the id format; malformed → `404`.
- JSON errors: `{"error": "<code>", "message": "..."}`.

## 3. Room manager (`internal/room`)

- In-memory, safe for concurrent use; your choice of mutex or one goroutine per
  room, but `go test -race` must be clean and no global lock may be held while
  writing to a socket.
- Tracks per room: created time, time it became empty, peers
  (`peerId`, display name, muted, connected at).
- Janitor removes rooms empty for longer than `ROOM_TTL`.
- Define a small interface for the media side, so step 3 only adds an
  implementation:

  ```go
  // MediaHandler receives media signaling for a peer and peer lifecycle events.
  type MediaHandler interface {
      PeerJoined(roomID, peerID string, send func(Envelope) error)
      PeerLeft(roomID, peerID string)
      Signal(roomID, peerID string, msg Envelope) // offer / answer / ice-candidate
  }
  ```

  In this step use a stub that answers any media message with
  `error {code: "media-unavailable"}`.

## 4. WebSocket `/ws?room={roomId}` (`internal/signal`)

Library: `github.com/coder/websocket` (not gorilla, not `nhooyr.io` — that path
moved to coder). JSON text frames only.

Connection flow:

1. Origin checked against `ALLOWED_ORIGINS` before upgrade (`403` otherwise).
2. After upgrade the client must send `hello` within 5 s, otherwise close.
3. Server assigns `peerId` (random, ≥ 64 bits), replies `welcome`, and sends
   `peer-joined` to everyone else.
4. On disconnect (any reason) — `peer-left` to the rest, `MediaHandler.PeerLeft`.

Envelope: `{"type", "from", "to", "payload"}`. The server always sets `from`
(`"server"` or the sender's `peerId`); a client-supplied `from` is ignored.

| Type | Direction | Payload |
|---|---|---|
| `hello` | C→S | `{displayName}` — trimmed, 1…40 runes, control chars stripped |
| `welcome` | S→C | `{peerId, peers: [{peerId, displayName, muted}], maxPeers}` |
| `peer-joined` | S→C | `{peerId, displayName, muted}` |
| `peer-left` | S→C | `{peerId}` |
| `peer-state` | C→S, S→C | `{muted}` — server rebroadcasts with `from` set |
| `offer`, `answer`, `ice-candidate` | C↔S | passed to `MediaHandler` (`to` = `"sfu"`) |
| `error` | S→C | `{code, message}` |

Application close codes (document them in `ARCHITECTURE.md`):

| Code | Meaning |
|---|---|
| 4400 | malformed or unknown message / no `hello` in time |
| 4404 | room not found |
| 4409 | room full |
| 4429 | message rate exceeded |
| 1001 | server shutting down |

Limits and liveness:

- Max message size 64 KiB; per-connection rate limit (e.g. 50 msg/s, burst 100).
- Ping every 15 s, close if no pong within 10 s; write timeout 5 s.
- Bounded outbound queue per peer (e.g. 64); a slow consumer is closed instead of
  blocking the room.
- Graceful shutdown closes all sockets with 1001 before the HTTP server stops.

Reconnection with the same identity (resume token) is **not** in this step
(step 5) — just don't design anything that blocks it.

## 5. CSP

Check that the step 1 CSP allows `wss://` to the same origin
(`connect-src 'self'`); adjust if needed.

## Tests (required)

- Room manager: create/lookup, `MAX_ROOMS`, TTL expiry with a fake clock,
  concurrent join/leave under `-race`.
- REST: create (URL with and without `PUBLIC_URL`), lookup, malformed id,
  rate limit → 429, `MAX_ROOMS` → 503.
- WebSocket with `httptest` and several real clients:
  - welcome contains existing peers; others get `peer-joined`;
  - `peer-left` on close and on abrupt connection drop;
  - spoofed `from` is replaced;
  - `peer-state` is rebroadcast;
  - unknown room → 4404, full room → 4409, no `hello` → 4400,
    oversized/garbage message → 4400, flood → 4429;
  - bad Origin → 403;
  - a peer that stops reading is closed and does not stall the others;
  - media messages reach the stub and get `media-unavailable`;
  - shutdown closes clients with 1001.
- `go vet ./...` clean, `go test -race ./...` green.

## Done when

- `make test` is green.
- `make run-selfca`, then
  `curl --cacert .data/selfca/ca.crt -X POST https://localhost:8443/api/rooms`
  returns a room URL, and `GET /api/rooms/{id}` sees it.
- `ARCHITECTURE.md` describes the final protocol (messages, close codes, limits)
  exactly as implemented.

## Out of scope

WebRTC/SFU, UI beyond the existing placeholder, reconnection, PWA.

## On completion

Update the step 2 status in `docs/ROADMAP.md` and `docs/ROADMAP.ru.md`, move this
file to `docs/executed/`, and list anything deferred or decided differently.
