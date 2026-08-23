// Exercises the cover reference server's protocol surface. The regression this
// guards is a hang, not a wrong answer: an unanswered request looks identical to
// a slow one until the client's own deadline expires, so every request here is
// bounded and a timeout fails.
//
// The extended-CONNECT case is not optional. Serving HTTP/1.1 from this server
// requires a `request` listener, which switches on Node's HTTP/2 compatibility
// layer; that layer attaches to every stream and consumes the extended-CONNECT
// stream the reference WebSocket runs on. Only the capture campaign caught that,
// so it is covered here.
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { connect as http2Connect, constants } from 'node:http2';
import { fileURLToPath } from 'node:url';

const REQUEST_TIMEOUT_MS = 5000;
const STARTUP_TIMEOUT_MS = 15000;
const serverPath = fileURLToPath(new URL('./server.mjs', import.meta.url));

// Binding is asynchronous, so the port is only readable once `listening` has
// fired. Releasing it before the real server binds leaves a small race, which is
// acceptable here and avoids hard-coding a port that a parallel run could hold.
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function withDeadline(promise, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} did not answer within ` +
        `${REQUEST_TIMEOUT_MS} ms`)),
      REQUEST_TIMEOUT_MS
    );
    promise.then(
      value => { clearTimeout(timer); resolve(value); },
      error => { clearTimeout(timer); reject(error); });
  });
}

// Node cannot mint a self-signed certificate on its own, and the capture
// runner already generates one this way.
function generateCertificate(directory) {
  const key = join(directory, 'server.key');
  const certificate = join(directory, 'server.crt');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-nodes', '-keyout', key, '-out', certificate, '-days', '1',
    '-subj', '/CN=localhost'
  ], { stdio: 'ignore' });
  return { key, certificate };
}

async function startServer(directory, port) {
  const { key, certificate } = generateCertificate(directory);
  const child = spawn(process.execPath, [serverPath], {
    env: {
      ...process.env,
      YUME_COVER_TLS_KEY: key,
      YUME_COVER_TLS_CERT: certificate,
      YUME_COVER_HOST: '127.0.0.1',
      YUME_COVER_PORT: String(port)
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`cover server did not start: ${stderr}`)),
      STARTUP_TIMEOUT_MS);
    child.stdout.on('data', chunk => {
      if (String(chunk).includes('listening')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.once('exit', code => {
      clearTimeout(timer);
      reject(new Error(`cover server exited with ${code}: ${stderr}`));
    });
  });
  return child;
}

function fetchOverHttp1(port, path) {
  return withDeadline(new Promise((resolve, reject) => {
    const call = httpsRequest({
      host: '127.0.0.1',
      port,
      path,
      method: 'GET',
      rejectUnauthorized: false,
      // Pinning ALPN is the point of the test: the default would negotiate h2
      // and never touch the HTTP/1.1 path being verified.
      ALPNProtocols: ['http/1.1']
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        contentType: response.headers['content-type'],
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    call.on('error', reject);
    call.end();
  }), 'HTTP/1.1 request');
}

// Client-to-server frames must be masked; the reference rejects unmasked ones.
function maskedFrame(opcode, payload) {
  const mask = randomBytes(4);
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; ++i) masked[i] ^= mask[i & 3];
  return Buffer.concat([
    Buffer.from([0x80 | opcode, 0x80 | masked.length]), mask, masked
  ]);
}

// RFC 8441 extended CONNECT, the transport the reference WebSocket uses. A ping
// round trip is the assertion that matters: the compatibility layer still
// answers the CONNECT with 200 and only breaks the data that follows, so
// checking the status alone would pass while the fixture was broken. Ping is
// used because it does not consume the contract's binary-message budget.
function openWebSocketStream(port, path) {
  return withDeadline(new Promise((resolve, reject) => {
    const session = http2Connect(`https://127.0.0.1:${port}`,
      { rejectUnauthorized: false });
    session.on('error', reject);
    session.on('remoteSettings', settings => {
      if (!settings.enableConnectProtocol) {
        reject(new Error('server did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL'));
        return;
      }
      const stream = session.request({
        [constants.HTTP2_HEADER_METHOD]: 'CONNECT',
        ':protocol': 'websocket',
        [constants.HTTP2_HEADER_PATH]: path,
        [constants.HTTP2_HEADER_SCHEME]: 'https',
        [constants.HTTP2_HEADER_AUTHORITY]: `127.0.0.1:${port}`
      });
      let status;
      const received = [];
      stream.on('response', headers => {
        status = Number(headers[constants.HTTP2_HEADER_STATUS]);
        if (status !== 200) {
          stream.close();
          session.close();
          resolve({ status, pong: null });
          return;
        }
        stream.write(maskedFrame(0x9, Buffer.from('fixture-ping')));
      });
      stream.on('data', chunk => {
        received.push(chunk);
        const frame = Buffer.concat(received);
        if (frame.length < 2 || frame.length < 2 + (frame[1] & 0x7f)) return;
        stream.close();
        session.close();
        resolve({
          status,
          pong: {
            opcode: frame[0] & 0x0f,
            payload: frame.subarray(2, 2 + (frame[1] & 0x7f)).toString('utf8')
          }
        });
      });
      stream.on('error', reject);
    });
  }), 'extended CONNECT');
}

function fetchOverHttp2(port, path) {
  return withDeadline(new Promise((resolve, reject) => {
    const session = http2Connect(`https://127.0.0.1:${port}`,
      { rejectUnauthorized: false });
    session.on('error', reject);
    const stream = session.request({
      [constants.HTTP2_HEADER_PATH]: path,
      [constants.HTTP2_HEADER_METHOD]: 'GET'
    });
    let status;
    let contentType;
    const chunks = [];
    stream.on('response', headers => {
      status = headers[constants.HTTP2_HEADER_STATUS];
      contentType = headers['content-type'];
    });
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end', () => {
      session.close();
      resolve({ status, contentType, body: Buffer.concat(chunks).toString('utf8') });
    });
    stream.on('error', reject);
  }), 'HTTP/2 request');
}

test('serves HTTP/2 and extended CONNECT, and refuses HTTP/1.1 promptly', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'yume-cover-server-'));
  const port = await freePort();
  const child = await startServer(directory, port);
  t.after(() => {
    child.kill('SIGKILL');
    rmSync(directory, { recursive: true, force: true });
  });

  const overHttp2 = await fetchOverHttp2(port, '/');
  assert.equal(Number(overHttp2.status), 200);
  assert.match(overHttp2.contentType, /^text\/html/);

  const missingOverHttp2 = await fetchOverHttp2(port, '/does-not-exist');
  assert.equal(Number(missingOverHttp2.status), 404);

  // The capture fixture depends on this; a `request` listener silently breaks it.
  const websocket = await openWebSocketStream(port, '/__yume_cover_ws');
  assert.equal(websocket.status, 200);
  assert.deepEqual(websocket.pong, { opcode: 0xA, payload: 'fixture-ping' });

  // An HTTP/1.1-only client must be refused at ALPN, promptly. The failure mode
  // that matters is not the rejection but a connection that is accepted and
  // never answered, so this asserts the error rather than tolerating a timeout.
  await assert.rejects(
    fetchOverHttp1(port, '/'),
    error => !/did not answer within/.test(error.message),
    'HTTP/1.1 must fail fast, not hang');
});
