import { readFileSync } from 'node:fs';
import { createSecureServer, constants } from 'node:http2';

const host = process.env.YUME_COVER_HOST ?? '127.0.0.1';
const port = Number.parseInt(process.env.YUME_COVER_PORT ?? '3000', 10);
const keyPath = process.env.YUME_COVER_TLS_KEY;
const certPath = process.env.YUME_COVER_TLS_CERT;

if (!keyPath || !certPath || !Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('set YUME_COVER_TLS_KEY, YUME_COVER_TLS_CERT, and a valid YUME_COVER_PORT');
}

const html = Buffer.from(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar</title><link rel="stylesheet" href="/assets/site.css"></head>
<body><main><h1>Northstar</h1><p>A small Node.js HTTP/2 reference site.</p></main>
<script src="/assets/site.js" defer></script></body></html>\n`);
const css = Buffer.from('body{font:16px system-ui;margin:4rem;line-height:1.5}main{max-width:52rem}h1{letter-spacing:.02em}\n');
const js = Buffer.from(`document.documentElement.dataset.ready="true";
const ws = new WebSocket('wss://' + location.host + '/__yume_cover_ws');
window.fixtureSocket = ws;
ws.binaryType = 'arraybuffer';
const fixtureMessage = new Uint8Array(16384).fill(0x59);
let echoedMessages = 0;
ws.addEventListener('open', () => {
  for (let i = 0; i < 64; ++i) ws.send(fixtureMessage);
});
ws.addEventListener('message', event => {
  const bytes = new Uint8Array(event.data);
  if (bytes.length !== 16384 || bytes[0] !== 0x59) {
    document.documentElement.dataset.ws = 'bad';
    return ws.close(1002, 'fixture-mismatch');
  }
  echoedMessages += 1;
  if (echoedMessages === 64) {
    document.documentElement.dataset.ws = 'ok';
  }
});
ws.addEventListener('error', () => { document.documentElement.dataset.ws = 'error'; });
`);

function writeResponse(stream, method, status, contentType, body) {
  const headers = {
    ':status': status,
    'content-type': contentType,
    'cache-control': 'public, max-age=60',
    'content-length': String(body.length)
  };
  stream.respond(headers, { endStream: method === 'HEAD' });
  if (method !== 'HEAD') stream.end(body);
}

function encodeWs(opcode, payload, fin = true) {
  const length = payload.length;
  if (length > 0xffff) throw new Error('reference frame too large');
  const head = length < 126
    ? Buffer.from([(fin ? 0x80 : 0) | opcode, length])
    : Buffer.from([(fin ? 0x80 : 0) | opcode, 126, length >>> 8, length & 0xff]);
  return Buffer.concat([head, payload]);
}

function attachReferenceWebSocket(stream) {
  let buffered = Buffer.alloc(0);
  let echoed = 0;
  stream.respond({ ':status': 200 }, { endStream: false });
  stream.on('data', chunk => {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 2) {
      const first = buffered[0];
      const second = buffered[1];
      const masked = (second & 0x80) !== 0;
      let length = second & 0x7f;
      let offset = 2;
      if (!masked) return stream.close(constants.NGHTTP2_PROTOCOL_ERROR);
      if (length === 126) {
        if (buffered.length < 4) return;
        length = buffered.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        return stream.close(constants.NGHTTP2_PROTOCOL_ERROR);
      }
      if (buffered.length < offset + 4 + length) return;
      const mask = buffered.subarray(offset, offset + 4);
      offset += 4;
      const payload = Buffer.from(buffered.subarray(offset, offset + length));
      for (let i = 0; i < payload.length; ++i) payload[i] ^= mask[i & 3];
      buffered = buffered.subarray(offset + length);

      const opcode = first & 0x0f;
      if (opcode === 0x2) {
        if (echoed === 0) {
          stream.write(encodeWs(0x9, Buffer.from('fixture-ping')));
          const split = payload.length >>> 1;
          stream.write(encodeWs(0x2, payload.subarray(0, split), false));
          stream.write(encodeWs(0x0, payload.subarray(split), true));
        } else {
          stream.write(encodeWs(0x2, payload));
        }
        echoed += 1;
      }
      else if (opcode === 0x9) stream.write(encodeWs(0xA, payload));
      else if (opcode === 0x8) {
        stream.end(encodeWs(0x8, payload));
        return;
      }
    }
  });
}

const server = createSecureServer({
  key: readFileSync(keyPath),
  cert: readFileSync(certPath),
  allowHTTP1: true,
  settings: { enableConnectProtocol: true }
});

server.on('stream', (stream, headers) => {
  const method = headers[':method'];
  const path = headers[':path'];
  if (method === 'CONNECT' && headers[':protocol'] === 'websocket') {
    attachReferenceWebSocket(stream);
    return;
  }
  if (method !== 'GET' && method !== 'HEAD') {
    writeResponse(stream, method, 405, 'text/plain; charset=utf-8', Buffer.from('Method Not Allowed\n'));
  } else if (path === '/') {
    writeResponse(stream, method, 200, 'text/html; charset=utf-8', html);
  } else if (path === '/assets/site.css') {
    writeResponse(stream, method, 200, 'text/css; charset=utf-8', css);
  } else if (path === '/assets/site.js') {
    writeResponse(stream, method, 200, 'text/javascript; charset=utf-8', js);
  } else {
    writeResponse(stream, method, 404, 'text/plain; charset=utf-8', Buffer.from('Not Found\n'));
  }
});

server.listen(port, host, () => {
  process.stdout.write(`cover reference listening on https://${host}:${port}\n`);
});
