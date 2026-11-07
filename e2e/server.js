// Global setup: builds tincan, starts it in selfca mode on free ports with
// ADVERTISE_IPS=127.0.0.1, and exports its URL and the server certificate's
// SPKI hash (so Chromium trusts exactly that certificate) via process.env.
import { execFileSync, spawn } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function freeTCPPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function freeUDPPort() {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.once('error', reject);
    sock.bind(0, '127.0.0.1', () => {
      const { port } = sock.address();
      sock.close(() => resolve(port));
    });
  });
}

function healthy(url, ca) {
  return new Promise((resolve) => {
    const req = https.get(url, { ca, timeout: 1000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

export default async function globalSetup() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tincan-e2e-'));
  const bin = path.join(tmp, 'tincan');
  execFileSync('go', ['build', '-o', bin, './cmd/tincan'], { cwd: repo, stdio: 'inherit' });

  const [httpsPort, httpPort, mediaPort] = await Promise.all([freeTCPPort(), freeTCPPort(), freeUDPPort()]);
  const caDir = path.join(tmp, 'selfca');
  const logFile = path.join(tmp, 'server.log');
  const log = fs.openSync(logFile, 'w');
  const server = spawn(bin, [], {
    env: {
      ...process.env,
      TINCAN_TLS_MODE: 'selfca',
      TINCAN_HTTPS_ADDR: `127.0.0.1:${httpsPort}`,
      TINCAN_HTTP_ADDR: `127.0.0.1:${httpPort}`,
      TINCAN_PUBLIC_HTTP_PORT: String(httpPort),
      TINCAN_SELFCA_DIR: caDir,
      TINCAN_SELFCA_PERMITTED: 'localhost,127.0.0.0/8',
      TINCAN_MEDIA_PORT: String(mediaPort),
      TINCAN_ADVERTISE_IPS: '127.0.0.1',
    },
    stdio: ['ignore', log, log],
  });

  const base = `https://127.0.0.1:${httpsPort}`;
  const deadline = Date.now() + 20000;
  for (;;) {
    if (server.exitCode !== null) {
      throw new Error(`tincan exited early:\n${fs.readFileSync(logFile, 'utf8')}`);
    }
    const caFile = path.join(caDir, 'ca.crt');
    if (fs.existsSync(caFile) && (await healthy(`${base}/healthz`, fs.readFileSync(caFile)))) break;
    if (Date.now() > deadline) {
      server.kill('SIGKILL');
      throw new Error(`tincan did not become healthy:\n${fs.readFileSync(logFile, 'utf8')}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  const leaf = new X509Certificate(fs.readFileSync(path.join(caDir, 'server.crt')));
  const spki = createHash('sha256')
    .update(leaf.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64');
  process.env.TINCAN_BASE_URL = base;
  process.env.TINCAN_SPKI = spki;
  process.env.TINCAN_SERVER_LOG = logFile;

  return async () => {
    server.kill('SIGTERM');
    await new Promise((resolve) => {
      if (server.exitCode !== null) return resolve();
      const t = setTimeout(() => { server.kill('SIGKILL'); resolve(); }, 15000);
      server.once('exit', () => { clearTimeout(t); resolve(); });
    });
    if (process.env.TINCAN_KEEP_E2E) {
      console.log(`e2e artifacts kept in ${tmp}`);
    } else {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  };
}
