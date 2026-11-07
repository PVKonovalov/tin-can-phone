# tin-can-phone — Roadmap

Each step ends with a result that can be checked. Agent prompts live in `docs/`
(`AGENT_PROMPT_<step>_<name>.md`); after execution they move to `docs/executed/`.
The prompt for the next step is written after the previous step is done.

| Step | Content | Result (how to check) | Status |
|---|---|---|---|
| 1 | Skeleton: config, TLS modes `acme`/`files`/`selfca`, port-80 handlers, embedded static, `/healthz`, graceful shutdown | Placeholder page opens over HTTPS in `selfca` mode on LAN; tests green | prompt ready |
| 2 | Rooms + WebSocket signaling: server-assigned peer IDs, envelope, TTL, `MAX_PEERS`, Origin check, rate limit, ping/pong | `httptest` tests with several WS clients: join/leave/notify/limits | — |
| 3 | SFU, 1-on-1 audio: Pion, UDPMux on `MEDIA_PORT`, `ADVERTISE_IPS`; minimal UI (Create Call, Join Audio, Leave) | Playwright e2e: two Chromium instances with fake microphone receive each other's audio | — |
| 4 | Multi-party: renegotiation on join/leave, mute, participant statuses, Copy Link | e2e with 4 participants; mute is visible to others | — |
| 5 | Resilience: WS reconnect, ICE restart on network change, ICE-TCP fallback | e2e with UDP blocked still connects; reconnect after WS drop | — |
| 6 | PWA + iOS: manifest, service worker (no caching of `/api`, `/ws`; network-first HTML), Media Session, limitation notes | Installable PWA; manual iOS/Android checklist passed | — |
| 7 | Deployment: docs for Internet and isolated modes, systemd unit, Dockerfile; optional TURN over TLS on 443 | Fresh server deployed by following the docs only | — |
