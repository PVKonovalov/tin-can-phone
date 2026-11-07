# Agent prompt — Step 3: SFU and the first audio call

## Context

Read `docs/ARCHITECTURE.md`, `docs/ROADMAP.md` and the executed prompts of steps
1–2 in `docs/executed/`. Signaling, rooms and the `room.MediaHandler` interface
exist; media is a stub (`UnavailableMedia`). This step replaces the stub with a
real SFU and adds a minimal UI, so that **two browsers can talk**.

Same hard rule: no external infrastructure at runtime — the client uses **no STUN
or TURN servers at all** (`iceServers: []`). The server is reachable (public IP or
same network) and announces its own addresses; clients behind NAT reach it and the
server learns their address as peer-reflexive candidates.

## 1. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MEDIA_PORT` | 50000 | single UDP port for all media |
| `ADVERTISE_IPS` | auto | IPs announced as ICE host candidates, comma-separated |

- `ADVERTISE_IPS` unset → all non-loopback, non-link-local unicast addresses of the
  host, logged at startup with a warning that explicit config is recommended.
- Validate: valid IPs, no duplicates; port 1…65535 and not equal to the HTTP(S)
  ports.

## 2. SFU (`internal/sfu`, Pion `github.com/pion/webrtc/v4`)

Implements `room.MediaHandler`; wired in `cmd/tincan` instead of the stub.

Pion setup (one `webrtc.API` for the process):

- `MediaEngine` with **Opus only** (48 kHz, 2 ch, `minptime=10;useinbandfec=1`);
  default interceptors (RTCP reports, NACK).
- `SettingEngine`:
  - one UDP socket on `MEDIA_PORT` shared by all connections (`ICEUDPMux`);
  - `SetNAT1To1IPs(ADVERTISE_IPS, host)`;
  - network types UDP4 (+ UDP6 if an IPv6 address is advertised);
  - mDNS disabled; no STUN/TURN in the server config either.
  - ICE-TCP is **not** in this step (step 5).

Model — one `PeerConnection` per participant who pressed *Join Audio*:

- Each publisher's incoming audio is forwarded into a `TrackLocalStaticRTP`
  created by the server: stream ID = publisher `peerId`, track ID =
  `<peerId>-audio`. Clients use the stream ID to know whose audio it is.
- That local track is added to every other participant's connection; when a
  participant leaves, their track is removed from the others and their connection
  closed. RTP forwarding only — no decoding, mixing or transcoding.
- Write the general N-participant logic now (2 participants must not be a special
  case); step 4 adds the multi-party UI and e2e coverage.

Negotiation — **only the server sends offers** (no glare, no perfect negotiation
on the client). Update `ARCHITECTURE.md` accordingly.

1. After getting the microphone, the client sends `media-join` (new message
   type, C→S, empty payload; add it to `internal/protocol` and the docs).
2. The server creates the connection with one `sendrecv` audio transceiver for
   the client's microphone plus `sendonly` tracks of the existing publishers,
   and sends `offer`.
3. The client sets the remote description, attaches its microphone track to the
   audio transceiver from the offer (`sender.replaceTrack`, direction
   `sendrecv`), sends `answer`.
4. Trickle ICE both ways (`ice-candidate`, `null` candidate = end of
   candidates).
5. Any later change (someone joins/leaves) → the server renegotiates with a new
   offer. Per participant, negotiation is serialised: if a change happens while
   an offer is outstanding, set a "pending" flag and send the next offer after
   the answer arrives. Unexpected client `offer` → `error {code: "unexpected-offer"}`.

Lifecycle and safety:

- WebSocket closed or `PeerLeft` → close the connection, remove its track from
  others.
- Connection state `failed`, or `disconnected` for more than 15 s → close it and
  send `error {code: "media-failed"}`; the client may send `media-join` again.
- A second `media-join` while a connection exists → replace the old one cleanly.
- Never block the signaling goroutine on Pion calls that can stall; no goroutine
  leaks (check in tests with a leak detector such as `go.uber.org/goleak`).
- Log ICE/connection state changes per peer at debug level via `slog`.

## 3. Minimal UI (`web/`, vanilla JS, no external resources)

Only what is needed to make a call; styling and PWA come later.

- **Home** (`/`): *Create Call* → `POST /api/rooms` → navigate to `/room/{id}`.
- **Room** (`/room/{id}`):
  - `GET /api/rooms/{id}` → "room not found" message on 404.
  - Display name input (remembered in `localStorage`, wrapped in try/catch).
  - *Join Audio* button — the user gesture: `getUserMedia({audio: {echoCancellation:
    true, noiseSuppression: true, autoGainControl: true}, video: false})`, open
    the WebSocket, `hello`, then `media-join`.
  - `RTCPeerConnection({iceServers: []})`; each remote track → its own hidden
    `<audio autoplay playsinline>` keyed by stream ID; call `play()` and surface a
    "tap to enable audio" button if it is rejected.
  - Participant list from `welcome`/`peer-joined`/`peer-left` (names only for now).
  - Connection status line (signaling + ICE state).
  - *Leave* button: stop tracks, close connection and socket, back to home.
  - Clear messages for: microphone denied, room full (4409), room not found
    (4404), media failed.
- Split into `app.js` (UI) and `rtc.js` (signaling + WebRTC) so step 4–5 changes
  stay local.

## 4. Tests (required)

Go (part of `make test`):

- Config validation for the new variables.
- **Integration without a browser:** start the server in-process; two Pion
  clients in the test connect through the real signaling (WebSocket) and the real
  UDP mux on `127.0.0.1`. Client A sends Opus RTP (synthetic packets are fine);
  client B receives packets on a track whose stream ID equals A's `peerId`, and
  vice versa.
- Renegotiation: B joins after A is already publishing → both receive each
  other; B leaves → A's connection gets a renegotiation removing B's track and
  stays connected.
- Unexpected client offer → `unexpected-offer`; closed socket → server
  connection closed; no goroutine leaks.

Browser e2e (new `make e2e`, not part of `make test`):

- Playwright (Node, in `e2e/` with its own `package.json`; keep it out of the Go
  module). Chromium with `--use-fake-ui-for-media-stream
  --use-fake-device-for-media-stream`.
- Server started by the test in `selfca` mode on free ports,
  `ADVERTISE_IPS=127.0.0.1`; the browser trusts the generated CA (or uses
  `ignoreHTTPSErrors` — say which in the notes).
- Two browser contexts: create a call in one, join from the other, press *Join
  Audio* in both. Pass when, within 15 s, each side's `getStats()` shows an
  `inbound-rtp` audio stream with growing `packetsReceived` and
  `totalAudioEnergy > 0`. Leave in one → the other's participant list updates.

## Done when

- `make test` and `make e2e` are green; `go vet` clean, `-race` green.
- Manual: laptop and phone on the LAN (`ADVERTISE_IPS=<LAN IP>`), call created
  on one and joined from the other — both hear each other. Record device/browser
  versions in the completion notes.
- `ARCHITECTURE.md` describes the final negotiation flow, `media-join`, the new
  error codes and the media config.

## Out of scope

Mute and participant statuses in the UI, Copy Link, 3+ participant e2e (step 4);
reconnection, ICE restart, ICE-TCP (step 5); PWA (step 6); TURN.

## On completion

Update the step 3 status in `docs/ROADMAP.md` and `docs/ROADMAP.ru.md`, move this
file to `docs/executed/`, and list anything deferred or decided differently.
