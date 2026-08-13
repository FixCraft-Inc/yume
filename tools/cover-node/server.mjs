import { readFileSync } from 'node:fs';
import { createSecureServer, constants } from 'node:http2';

import {
  assets,
  attachReferenceWebSocket,
  workloadDocument
} from './workload.mjs';

const host = process.env.YUME_COVER_HOST ?? '127.0.0.1';
const port = Number.parseInt(process.env.YUME_COVER_PORT ?? '3000', 10);
const keyPath = process.env.YUME_COVER_TLS_KEY;
const certPath = process.env.YUME_COVER_TLS_CERT;

if (!keyPath || !certPath || !Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('set YUME_COVER_TLS_KEY, YUME_COVER_TLS_CERT, and a valid YUME_COVER_PORT');
}

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

function acceptReferenceWebSocket(stream) {
  stream.respond({ ':status': 200 }, { endStream: false });
  attachReferenceWebSocket(
    stream, () => stream.close(constants.NGHTTP2_PROTOCOL_ERROR));
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
  if (method === 'CONNECT' && headers[':protocol'] === 'websocket' &&
      path === workloadDocument.websocket_path) {
    acceptReferenceWebSocket(stream);
    return;
  }
  if (method !== 'GET' && method !== 'HEAD') {
    writeResponse(stream, method, 405, 'text/plain; charset=utf-8', Buffer.from('Method Not Allowed\n'));
  } else {
    const asset = assets.get(path);
    writeResponse(
      stream,
      method,
      asset ? 200 : 404,
      asset?.contentType ?? 'text/plain; charset=utf-8',
      asset?.body ?? Buffer.from('Not Found\n'));
  }
});

server.listen(port, host, () => {
  process.stdout.write(`cover reference listening on https://${host}:${port}\n`);
});
