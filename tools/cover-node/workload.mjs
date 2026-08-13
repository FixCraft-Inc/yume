import { readFileSync } from 'node:fs';

const source = new URL('./workload-v1.json', import.meta.url);
export const workloadDocument = Object.freeze(
  JSON.parse(readFileSync(source, 'utf8'))
);

function requireValue(condition, message) {
  if (!condition) throw new Error(`invalid workload-v1.json: ${message}`);
}

const contract = workloadDocument.contract;
requireValue(workloadDocument.schema === 1, 'unsupported schema');
requireValue(workloadDocument.id === 'cover-page-websocket-v1', 'wrong id');
requireValue(workloadDocument.transport_profile === 'chrome151-node24-v1',
  'wrong transport profile');
requireValue(Array.isArray(workloadDocument.assets), 'assets must be an array');
requireValue(contract?.mode === workloadDocument.id, 'mode does not match id');
requireValue(contract?.websocket_bytes_each_direction === 1024 * 1024,
  'wrong transfer size');
requireValue(contract?.client_binary_messages?.count === 64,
  'wrong client message count');
requireValue(contract.client_binary_messages.payload_bytes === 16384,
  'wrong client message size');
requireValue(contract.client_binary_messages.masked === true,
  'client messages must be masked');
requireValue(contract.server_binary_messages?.unfragmented_count === 63,
  'wrong server message count');
requireValue(contract.server_binary_messages.payload_bytes === 16384,
  'wrong server message size');
requireValue(contract.server_binary_messages.masked === false,
  'server messages must be unmasked');
requireValue(JSON.stringify(contract.server_fragmented_binary_message) ===
  JSON.stringify([
    { opcode: 2, payload_bytes: 8192, final: false, masked: false },
    { opcode: 0, payload_bytes: 8192, final: true, masked: false }
  ]), 'wrong server fragmentation');
requireValue(contract.ping_pong?.server_ping_payload_bytes === 12,
  'wrong ping size');
requireValue(contract.ping_pong.client_pong_payload_bytes === 12 &&
  contract.ping_pong.client_pong_masked === true, 'wrong pong contract');
requireValue(contract.close?.payload_bytes === 18, 'wrong close size');
requireValue(contract.close.client_masked === true &&
  contract.close.server_masked === false, 'wrong close masking');
requireValue(contract.client_binary_messages.count *
  contract.client_binary_messages.payload_bytes ===
  contract.websocket_bytes_each_direction, 'client transfer geometry mismatch');
requireValue(contract.server_binary_messages.unfragmented_count + 1 ===
  contract.client_binary_messages.count, 'server transfer geometry mismatch');
requireValue(Buffer.byteLength('fixture-ping') ===
  contract.ping_pong.server_ping_payload_bytes, 'ping payload mismatch');

function renderClientScript() {
  const count = contract.client_binary_messages.count;
  const bytes = contract.client_binary_messages.payload_bytes;
  return `document.documentElement.dataset.ready="true";
const wsScheme = location.protocol === 'https:' ? 'wss://' : 'ws://';
const ws = new WebSocket(wsScheme + location.host + '${workloadDocument.websocket_path}');
window.fixtureSocket = ws;
ws.binaryType = 'arraybuffer';
const fixtureMessage = new Uint8Array(${bytes}).fill(0x59);
let echoedMessages = 0;
ws.addEventListener('open', () => {
  for (let i = 0; i < ${count}; ++i) ws.send(fixtureMessage);
});
ws.addEventListener('message', event => {
  const bytes = new Uint8Array(event.data);
  if (bytes.length !== ${bytes} || bytes[0] !== 0x59) {
    document.documentElement.dataset.ws = 'bad';
    return ws.close(1002, 'fixture-mismatch');
  }
  echoedMessages += 1;
  if (echoedMessages === ${count}) {
    document.documentElement.dataset.ws = 'ok';
  }
});
ws.addEventListener('error', () => { document.documentElement.dataset.ws = 'error'; });
`;
}

export const assets = new Map(workloadDocument.assets.map(asset => {
  requireValue(typeof asset.path === 'string' && asset.path.startsWith('/'),
    'asset path is invalid');
  requireValue(typeof asset.content_type === 'string',
    `asset ${asset.path} has no content type`);
  const generators = Number(asset.body_utf8 !== undefined) +
    Number(asset.generator !== undefined);
  requireValue(generators === 1, `asset ${asset.path} needs one body source`);
  let body;
  if (asset.generator === 'websocket-client-v1') body = renderClientScript();
  else {
    requireValue(asset.generator === undefined && typeof asset.body_utf8 === 'string',
      `asset ${asset.path} has an unknown generator`);
    body = asset.body_utf8;
  }
  return [asset.path, Object.freeze({
    contentType: asset.content_type,
    body: Buffer.from(body)
  })];
}));

requireValue(JSON.stringify([...assets.keys()]) ===
  JSON.stringify(contract.asset_paths), 'asset order differs from contract');

export function encodeWebSocketFrame(opcode, payload, fin = true) {
  const length = payload.length;
  if (length > 0xffff) throw new Error('reference frame too large');
  const head = length < 126
    ? Buffer.from([(fin ? 0x80 : 0) | opcode, length])
    : Buffer.from([(fin ? 0x80 : 0) | opcode, 126, length >>> 8, length & 0xff]);
  return Buffer.concat([head, payload]);
}

// The direct matched-capture target uses this exact frame engine. It records no
// payloads and deliberately rejects unmasked or oversized client frames. The
// installed production HTTP/1 cover backend remains separate.
export function attachReferenceWebSocket(channel, protocolError) {
  let buffered = Buffer.alloc(0);
  let echoed = 0;
  let inputBytes = 0;
  let inputChunks = 0;
  let inputFrames = 0;
  let failed = false;
  let lifetime;
  const fail = () => {
    if (failed) return;
    failed = true;
    clearTimeout(lifetime);
    protocolError();
  };
  lifetime = setTimeout(fail, 120_000);
  lifetime.unref();
  channel.once('close', () => clearTimeout(lifetime));
  channel.on('data', chunk => {
    if (failed) return;
    inputBytes += chunk.length;
    inputChunks += 1;
    if (inputBytes > contract.websocket_bytes_each_direction + 128 * 1024 ||
        inputChunks > 4096) {
      return fail();
    }
    if (buffered.length + chunk.length >
        contract.websocket_bytes_each_direction * 2 + 65536) {
      return fail();
    }
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 2) {
      const first = buffered[0];
      const second = buffered[1];
      const final = (first & 0x80) !== 0;
      if ((first & 0x70) !== 0) return fail();
      const masked = (second & 0x80) !== 0;
      let length = second & 0x7f;
      let offset = 2;
      if (!masked) return fail();
      if (length === 126) {
        if (buffered.length < 4) return;
        length = buffered.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        return fail();
      }
      const opcode = first & 0x0f;
      if (opcode >= 0x8 && (!final || length > 125)) return fail();
      if (buffered.length < offset + 4 + length) return;
      const mask = buffered.subarray(offset, offset + 4);
      offset += 4;
      const payload = Buffer.from(buffered.subarray(offset, offset + length));
      for (let i = 0; i < payload.length; ++i) payload[i] ^= mask[i & 3];
      buffered = buffered.subarray(offset + length);
      inputFrames += 1;
      if (inputFrames > 128) return fail();

      if (opcode === 0x2) {
        if (!final || payload.length !== contract.client_binary_messages.payload_bytes ||
            echoed >= contract.client_binary_messages.count) {
          return fail();
        }
        if (echoed === 0) {
          channel.write(encodeWebSocketFrame(0x9, Buffer.from('fixture-ping')));
          const split = payload.length >>> 1;
          channel.write(encodeWebSocketFrame(0x2, payload.subarray(0, split), false));
          channel.write(encodeWebSocketFrame(0x0, payload.subarray(split), true));
        } else {
          channel.write(encodeWebSocketFrame(0x2, payload));
        }
        echoed += 1;
      } else if (opcode === 0x9) {
        channel.write(encodeWebSocketFrame(0xA, payload));
      } else if (opcode === 0xA) {
        if (payload.length !== contract.ping_pong.client_pong_payload_bytes ||
            !payload.equals(Buffer.from('fixture-ping'))) {
          return fail();
        }
      } else if (opcode === 0x8) {
        if (echoed !== contract.client_binary_messages.count ||
            payload.length !== contract.close.payload_bytes) {
          return fail();
        }
        channel.end(encodeWebSocketFrame(0x8, payload));
        return;
      } else {
        return fail();
      }
    }
  });
}
