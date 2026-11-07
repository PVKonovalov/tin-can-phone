// Signaling (WebSocket) and WebRTC for one call. No STUN/TURN: the server
// announces its own addresses and learns ours as peer-reflexive candidates.
//
// Only the server sends offers. Incoming media messages are processed strictly
// in order (one promise chain), so an offer is always applied before the ICE
// candidates that follow it.
//
// Events (CustomEvent.detail):
//   welcome      {peerId, peers: [{peerId, displayName, muted}], maxPeers}
//   peer-joined  {peerId, displayName, muted}
//   peer-left    {peerId}
//   track        {peerId, stream}      remote audio of a participant
//   status       {signaling, ice}      for the status line
//   media-error  {code, message}       e.g. media-failed (call rejoinMedia())
//   closed       {code, reason}        the WebSocket closed

export const CloseCodes = Object.freeze({
  GoingAway: 1001,
  BadMessage: 4400,
  RoomNotFound: 4404,
  RoomFull: 4409,
  RateLimited: 4429,
});

export class Call extends EventTarget {
  constructor(roomId, displayName) {
    super();
    this.roomId = roomId;
    this.displayName = displayName;
    this.peerId = null;
    this.ws = null;
    this.pc = null;
    this.mic = null; // MediaStream from getUserMedia
    this.chain = Promise.resolve();
    this.left = false;
  }

  // start opens the socket, says hello and joins media with the given
  // microphone stream. Resolves on welcome; failures arrive as events.
  start(micStream) {
    this.mic = micStream;
    return new Promise((resolve, reject) => {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${location.host}/ws?room=${encodeURIComponent(this.roomId)}`);
      this.ws = ws;
      let welcomed = false;
      ws.onopen = () => {
        this.send('hello', { displayName: this.displayName });
        this.status();
      };
      ws.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (msg.type === 'welcome') {
          welcomed = true;
          this.peerId = msg.payload.peerId;
          this.emit('welcome', msg.payload);
          this.joinMedia();
          resolve();
          return;
        }
        this.onMessage(msg);
      };
      ws.onclose = (ev) => {
        this.status();
        this.closeMedia();
        this.emit('closed', { code: ev.code, reason: ev.reason });
        if (!welcomed) reject(Object.assign(new Error(ev.reason || 'connection closed'), { code: ev.code }));
      };
    });
  }

  send(type, payload) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, to: 'sfu', payload }));
    }
  }

  emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  status() {
    const ws = this.ws ? ['connecting', 'open', 'closing', 'closed'][this.ws.readyState] : 'idle';
    const ice = this.pc ? this.pc.iceConnectionState : 'idle';
    this.emit('status', { signaling: ws, ice });
  }

  joinMedia() {
    this.closeMedia();
    const pc = new RTCPeerConnection({ iceServers: [] });
    this.pc = pc;
    pc.onicecandidate = (ev) => {
      if (this.pc !== pc) return;
      this.send('ice-candidate', ev.candidate ? ev.candidate.toJSON() : null);
    };
    pc.ontrack = (ev) => {
      const stream = ev.streams[0];
      if (!stream || stream.id === this.peerId) return;
      this.emit('track', { peerId: stream.id, stream });
    };
    pc.oniceconnectionstatechange = () => this.status();
    pc.onconnectionstatechange = () => this.status();
    this.status();
    this.send('media-join', {});
  }

  // rejoinMedia starts a fresh connection after media-failed.
  rejoinMedia() {
    if (!this.left && this.ws && this.ws.readyState === WebSocket.OPEN) this.joinMedia();
  }

  closeMedia() {
    if (this.pc) {
      this.pc.close();
      this.pc = null;
    }
  }

  onMessage(msg) {
    switch (msg.type) {
      case 'peer-joined':
      case 'peer-left':
      case 'peer-state':
        this.emit(msg.type, { ...msg.payload, peerId: msg.payload?.peerId ?? msg.from });
        return;
      case 'offer':
      case 'ice-candidate': {
        const pc = this.pc;
        this.chain = this.chain
          .then(() => (msg.type === 'offer' ? this.onOffer(pc, msg.payload) : this.onCandidate(pc, msg.payload)))
          .catch((err) => console.warn('tincan: media message failed', msg.type, err));
        return;
      }
      case 'error':
        this.emit('media-error', msg.payload || {});
        if (msg.payload?.code === 'media-failed') this.closeMedia();
        this.status();
        return;
    }
  }

  async onOffer(pc, offer) {
    if (!pc || pc !== this.pc) return; // stale: connection was replaced
    await pc.setRemoteDescription(offer);
    // The first transceiver carries our microphone (the server may also use
    // it to send someone else's audio, hence sendrecv).
    const mic = this.mic && this.mic.getAudioTracks()[0];
    const tr = pc.getTransceivers()[0];
    if (tr && mic) {
      if (tr.sender.track !== mic) await tr.sender.replaceTrack(mic);
      if (tr.direction !== 'sendrecv') tr.direction = 'sendrecv';
    }
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    if (pc !== this.pc) return;
    this.send('answer', { type: answer.type, sdp: answer.sdp });
  }

  async onCandidate(pc, cand) {
    if (!pc || pc !== this.pc || !cand) return; // null = end of candidates
    await pc.addIceCandidate(cand);
  }

  leave() {
    this.left = true;
    this.closeMedia();
    if (this.mic) this.mic.getTracks().forEach((t) => t.stop());
    if (this.ws) this.ws.close(1000, 'leave');
  }
}
