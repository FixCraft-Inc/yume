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
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, connect as netConnect } from 'node:net';
import { METHODS } from 'node:http';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { connect as http2Connect, constants } from 'node:http2';
import { fileURLToPath } from 'node:url';

const REQUEST_TIMEOUT_MS = 5000;
const STARTUP_TIMEOUT_MS = 15000;
const serverPath = fileURLToPath(new URL('./server.mjs', import.meta.url));
const backendPath = fileURLToPath(new URL('./backend.mjs', import.meta.url));

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

async function start_server(directory, port, script = serverPath,
                            timeout_ms = STARTUP_TIMEOUT_MS) {
  const { key, certificate } = script === serverPath
    ? generateCertificate(directory) : {};
  const child = spawn(process.execPath, [script], {
    env: {
      ...process.env,
      YUME_COVER_TLS_KEY: key,
      YUME_COVER_TLS_CERT: certificate,
      YUME_COVER_HOST: '127.0.0.1',
      YUME_COVER_PORT: String(port)
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  // `close` follows exit/error and the closure of both piped streams. Own it
  // before waiting for readiness so a failed start cannot keep the test alive.
  const closed = new Promise(resolve => child.once('close', resolve));
  const stop_server = async () => {
    child.kill('SIGKILL');
    await closed;
  };
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  try {
    await new Promise((resolve, reject) => {
      const finish = error => {
        clearTimeout(timer);
        child.stdout.off('data', on_stdout);
        child.off('exit', on_exit);
        child.off('error', on_error);
        if (error) reject(error);
        else resolve();
      };
      const on_stdout = chunk => {
        if (String(chunk).includes('listening')) finish();
      };
      const on_exit = code => finish(
        new Error(`cover server exited with ${code}: ${stderr}`));
      const on_error = error => finish(error);
      const timer = setTimeout(() => finish(
        new Error(`cover server did not start: ${stderr}`)), timeout_ms);
      child.stdout.on('data', on_stdout);
      child.once('exit', on_exit);
      child.once('error', on_error);
    });
  } catch (error) {
    await stop_server();
    throw error;
  }
  return stop_server;
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

function fetchOverHttp2(port, path, method = 'GET', extraHeaders = {}) {
  return withDeadline(new Promise((resolve, reject) => {
    const session = http2Connect(`https://127.0.0.1:${port}`,
      { rejectUnauthorized: false });
    session.on('error', reject);
    session.once('remoteSettings', () => {
      const requestHeaders = {
        ':method': method,
        ':authority': `localhost:${port}`,
        ...extraHeaders
      };
      // Ordinary CONNECT has only authority; extended CONNECT requires scheme
      // and path and must wait for the peer's enableConnectProtocol setting.
      if (method !== 'CONNECT' || extraHeaders[':protocol']) {
        requestHeaders[':scheme'] = 'https';
        requestHeaders[':path'] = path;
      }
      const stream = session.request(requestHeaders);
      let headers;
      const chunks = [];
      stream.on('response', value => { headers = value; });
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('end', () => {
        session.close();
        resolve({
          status: headers[':status'], contentType: headers['content-type'],
          headers, body: Buffer.concat(chunks).toString('utf8')
        });
      });
      stream.on('error', error => { session.destroy(); reject(error); });
      stream.end();
    });
  }), 'HTTP/2 request');
}

function fetchRawHttp1(port, method, path) {
  return withDeadline(new Promise((resolve, reject) => {
    const socket = netConnect(port, '127.0.0.1');
    const chunks = [];
    socket.on('connect', () => socket.end(
      `${method} ${path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`));
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  }), `HTTP/1.1 ${method}`);
}

const methodNotAllowedBody = 'Method Not Allowed\n';
const methodNotAllowedHeaders = [
  ['content-type', 'text/plain; charset=utf-8'],
  ['cache-control', 'public, max-age=60'],
  ['content-length', '19']
];

function checkMethodNotAllowed(response, method, path) {
  assert.equal(Number(response.status), 405, `${method} ${path}`);
  assert.equal(response.body, methodNotAllowedBody);
  // Date is generated by Node's HTTP layer, rather than writeResponse().
  assert.deepEqual(Object.entries(response.headers).filter(
    ([name]) => name !== ':status' && name !== 'date'), methodNotAllowedHeaders);

  const native = process.env.YUME_NATIVE_COVER_RESPONSE;
  if (native) {
    const expected = `405\n${methodNotAllowedHeaders.map(
      ([name, value]) => `${name}: ${value}\n`).join('')}\n${response.body}`;
    assert.deepEqual(execFileSync(native, ['--method-response', method, path],
      { timeout: REQUEST_TIMEOUT_MS, maxBuffer: 64 * 1024 }),
      Buffer.from(expected), `native cover differs for ${method} ${path}`);
  }
}

test('unsupported HTTP/2 methods match the native static cover', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'yume-cover-methods-'));
  let stop_server;
  t.after(async () => {
    try { await stop_server?.(); }
    finally { rmSync(directory, { recursive: true, force: true }); }
  });
  const port = await freePort();
  stop_server = await start_server(directory, port);

  for (const method of [...METHODS.filter(value =>
    !['GET', 'HEAD', 'CONNECT'].includes(value)), 'FOO', 'get']) {
    checkMethodNotAllowed(await fetchOverHttp2(port, '/', method), method, '/');
  }
  for (const path of ['/missing', '/%', '/../index.html']) {
    checkMethodNotAllowed(await fetchOverHttp2(port, path, 'POST'), 'POST', path);
  }
  checkMethodNotAllowed(await fetchOverHttp2(port, '', 'CONNECT'), 'CONNECT', '');
  checkMethodNotAllowed(await fetchOverHttp2(port, '/wrong', 'CONNECT',
    { ':protocol': 'websocket' }), 'CONNECT', '/wrong');
  await assert.rejects(fetchOverHttp2(port, '/', ''),
    { code: 'ERR_HTTP2_STREAM_ERROR' });
});

test('HTTP/1.1 backend distinguishes method rejection from parser dispatch', async t => {
  const port = await freePort();
  const stop_server = await start_server(null, port, backendPath);
  t.after(stop_server);
  for (const method of METHODS.filter(value =>
    !['GET', 'HEAD', 'CONNECT'].includes(value))) {
    const response = await fetchRawHttp1(port, method, '/');
    const [head, body] = response.split('\r\n\r\n');
    const lines = head.split('\r\n');
    assert.equal(lines.shift(), 'HTTP/1.1 405 Method Not Allowed', method);
    assert.deepEqual(lines.filter(line => !/^(Date|Connection):/i.test(line)), [
      'content-type: text/plain; charset=utf-8', 'content-length: 19'
    ]);
    assert.equal(body, methodNotAllowedBody);
  }
  // llhttp refuses unknown/lowercase/empty methods before the backend callback.
  for (const method of ['FOO', 'get', '']) {
    assert.match(await fetchRawHttp1(port, method, '/'), /^HTTP\/1\.1 400 Bad Request\r\n/);
  }
  // Node emits `connect` instead of `request`; this backend has no listener.
  assert.equal(await fetchRawHttp1(port, 'CONNECT', 'localhost:443'), '');
});

test('serves HTTP/2 and extended CONNECT, and refuses HTTP/1.1 promptly', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'yume-cover-server-'));
  let stop_server;
  t.after(async () => {
    try { await stop_server?.(); }
    finally { rmSync(directory, { recursive: true, force: true }); }
  });
  const port = await freePort();
  stop_server = await start_server(directory, port);

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

test('startup timeout closes the child and its pipes before rejecting', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'yume-cover-startup-'));
  let child_pid;
  t.after(() => {
    // Keep the regression bounded even when the startup cleanup is removed.
    try {
      if (child_pid) {
        try { process.kill(child_pid, 'SIGKILL'); }
        catch (error) { if (error.code !== 'ESRCH') throw error; }
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  const script = join(directory, 'never-ready.mjs');
  writeFileSync(script, `
    process.stderr.write('fixture-pid=' + process.pid + '\\n');
    setTimeout(() => process.exit(0), 10000);
  `);
  await assert.rejects(start_server(null, 0, script, 1000), error => {
    assert.match(error.message, /^cover server did not start:/);
    const match = /fixture-pid=(\d+)/.exec(error.message);
    assert.ok(match, 'fixture must have started before its readiness timeout');
    child_pid = Number(match[1]);
    assert.throws(() => process.kill(child_pid, 0), { code: 'ESRCH' },
      'startup rejection must wait until the child is reaped');
    child_pid = undefined;
    return true;
  });
});
