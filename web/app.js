// UI: home (create a call) and room (join audio, participants, leave).
import { Call, CloseCodes } from './rtc.js';

const $ = (id) => document.getElementById(id);
const NAME_KEY = 'tincan.displayName';

function show(id) {
  for (const s of ['home', 'room', 'notfound']) $(s).hidden = s !== id;
}

function setError(id, text) {
  const el = $(id);
  el.textContent = text || '';
  el.hidden = !text;
}

function loadName() {
  try { return localStorage.getItem(NAME_KEY) || ''; } catch { return ''; }
}

function saveName(name) {
  try { localStorage.setItem(NAME_KEY, name); } catch { /* private mode etc. */ }
}

async function api(method, path) {
  const res = await fetch(path, { method, headers: { Accept: 'application/json' } });
  let body = null;
  try { body = await res.json(); } catch { /* empty */ }
  return { status: res.status, body };
}

// ---------- home ----------

function initHome() {
  show('home');
  $('create').addEventListener('click', async () => {
    $('create').disabled = true;
    setError('home-error', '');
    try {
      const { status, body } = await api('POST', '/api/rooms');
      if (status === 201) {
        location.assign('/room/' + body.roomId);
        return;
      }
      setError('home-error', body?.message || `Could not create a call (HTTP ${status}).`);
    } catch {
      setError('home-error', 'Could not reach the server.');
    }
    $('create').disabled = false;
  });
}

// ---------- room ----------

async function initRoom(roomId) {
  let info;
  try {
    info = await api('GET', '/api/rooms/' + roomId);
  } catch {
    show('room');
    setError('error', 'Could not reach the server.');
    return;
  }
  if (info.status === 404) {
    show('notfound');
    return;
  }
  show('room');
  const { peers, maxPeers } = info.body || {};
  $('room-info').textContent = peers ? `${peers} of ${maxPeers} in the call` : 'Nobody is in the call yet.';

  const nameInput = $('name');
  nameInput.value = loadName();
  $('join-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    join(roomId, nameInput.value.trim());
  });
}

const participants = new Map(); // peerId → displayName
const audios = new Map(); // peerId → <audio>
let call = null;

function renderParticipants() {
  const ul = $('participants');
  ul.replaceChildren();
  for (const [peerId, name] of participants) {
    const li = document.createElement('li');
    li.textContent = peerId === call?.peerId ? `${name} (you)` : name;
    li.dataset.peerId = peerId;
    ul.append(li);
  }
}

function attachAudio(peerId, stream) {
  let el = audios.get(peerId);
  if (!el) {
    el = document.createElement('audio');
    el.autoplay = true;
    el.setAttribute('playsinline', '');
    el.dataset.peerId = peerId;
    $('audio').append(el);
    audios.set(peerId, el);
  }
  if (el.srcObject !== stream) el.srcObject = stream;
  el.play().catch(() => { $('enable-audio').hidden = false; });
  stream.onremovetrack = () => {
    if (stream.getTracks().length === 0) removeAudio(peerId);
  };
}

function removeAudio(peerId) {
  const el = audios.get(peerId);
  if (el) {
    el.srcObject = null;
    el.remove();
    audios.delete(peerId);
  }
}

async function join(roomId, name) {
  if (!name) {
    setError('error', 'Please enter your name.');
    return;
  }
  saveName(name);
  setError('error', '');
  $('join').disabled = true;

  let mic;
  try {
    mic = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    });
  } catch (err) {
    $('join').disabled = false;
    if (err.name === 'NotAllowedError') {
      setError('error', 'Microphone access was denied. Allow it in the browser’s site settings and try again.');
    } else if (err.name === 'NotFoundError') {
      setError('error', 'No microphone found.');
    } else if (!window.isSecureContext) {
      setError('error', 'The microphone needs a secure (HTTPS) connection.');
    } else {
      setError('error', 'Could not open the microphone: ' + err.message);
    }
    return;
  }

  call = new Call(roomId, name);
  window.tincan = { call }; // handle for debugging and e2e tests

  call.addEventListener('welcome', (ev) => {
    participants.clear();
    for (const p of ev.detail.peers) participants.set(p.peerId, p.displayName);
    participants.set(ev.detail.peerId, name);
    renderParticipants();
    $('join-form').hidden = true;
    $('in-call').hidden = false;
  });
  call.addEventListener('peer-joined', (ev) => {
    participants.set(ev.detail.peerId, ev.detail.displayName);
    renderParticipants();
  });
  call.addEventListener('peer-left', (ev) => {
    participants.delete(ev.detail.peerId);
    removeAudio(ev.detail.peerId);
    renderParticipants();
  });
  call.addEventListener('track', (ev) => attachAudio(ev.detail.peerId, ev.detail.stream));
  call.addEventListener('status', (ev) => {
    $('status').textContent = `Signaling: ${ev.detail.signaling} · Audio: ${ev.detail.ice}`;
  });
  call.addEventListener('media-error', (ev) => {
    if (ev.detail.code === 'media-failed') {
      setError('error', 'The audio connection failed.');
      $('retry').hidden = false;
    } else {
      console.warn('tincan: server error', ev.detail);
    }
  });
  call.addEventListener('closed', (ev) => {
    if (call.left) return;
    const messages = {
      [CloseCodes.RoomNotFound]: 'This call does not exist or has expired.',
      [CloseCodes.RoomFull]: 'This call is full.',
      [CloseCodes.GoingAway]: 'The server is restarting. Please rejoin in a moment.',
      [CloseCodes.RateLimited]: 'Too many messages; disconnected.',
    };
    setError('error', messages[ev.detail.code] || 'Disconnected from the server.');
    for (const id of [...audios.keys()]) removeAudio(id);
    participants.clear();
    renderParticipants();
    $('in-call').hidden = true;
    $('join-form').hidden = false;
    $('join').disabled = false;
  });

  try {
    await call.start(mic);
  } catch {
    mic.getTracks().forEach((t) => t.stop());
    // 'closed' handler has shown the reason.
  }
}

function initCallControls() {
  $('leave').addEventListener('click', () => {
    if (call) call.leave();
    location.assign('/');
  });
  $('retry').addEventListener('click', () => {
    $('retry').hidden = true;
    setError('error', '');
    call?.rejoinMedia();
  });
  $('enable-audio').addEventListener('click', () => {
    $('enable-audio').hidden = true;
    for (const el of audios.values()) el.play().catch(() => { $('enable-audio').hidden = false; });
  });
}

// ---------- routing ----------

const m = location.pathname.match(/^\/room\/([a-z2-7]{26})$/);
initCallControls();
if (m) {
  initRoom(m[1]);
} else {
  initHome();
}
