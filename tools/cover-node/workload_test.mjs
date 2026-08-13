import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  assets,
  attachReferenceWebSocket,
  workloadDocument
} from './workload.mjs';

class Channel extends EventEmitter {
  constructor() {
    super();
    this.writes = [];
    this.ended = null;
  }

  write(value) {
    this.writes.push(Buffer.from(value));
    return true;
  }

  end(value) {
    this.ended = Buffer.from(value);
    this.emit('close');
  }
}

function maskedFrame(opcode, payload, final = true) {
  assert.ok(payload.length <= 0xffff);
  const mask = Buffer.from([0x11, 0x22, 0x33, 0x44]);
  const header = payload.length < 126
    ? Buffer.from([(final ? 0x80 : 0) | opcode, 0x80 | payload.length])
    : Buffer.from([
      (final ? 0x80 : 0) | opcode,
      0x80 | 126,
      payload.length >>> 8,
      payload.length & 0xff
    ]);
  const body = Buffer.from(payload);
  for (let index = 0; index < body.length; ++index) body[index] ^= mask[index & 3];
  return Buffer.concat([header, mask, body]);
}

assert.equal(workloadDocument.id, 'cover-page-websocket-v1');
assert.deepEqual([...assets.keys()], ['/', '/assets/site.css', '/assets/site.js']);
for (const asset of assets.values()) assert.ok(asset.body.length > 0);

{
  const channel = new Channel();
  let failed = false;
  attachReferenceWebSocket(channel, () => { failed = true; });
  const payload = Buffer.alloc(16384, 0x59);
  for (let index = 0; index < 64; ++index) {
    channel.emit('data', maskedFrame(0x2, payload));
  }
  channel.emit('data', maskedFrame(0xA, Buffer.from('fixture-ping')));
  channel.emit('data', maskedFrame(
    0x8, Buffer.concat([Buffer.from([0x03, 0xe8]), Buffer.from('fixture-complete')])));
  assert.equal(failed, false);
  assert.equal(channel.writes.length, 66);
  assert.equal(channel.writes[0][0], 0x89);
  assert.equal(channel.writes[1][0], 0x02);
  assert.equal(channel.writes[2][0], 0x80);
  assert.equal(channel.ended?.[0], 0x88);
}

{
  const channel = new Channel();
  let failures = 0;
  attachReferenceWebSocket(channel, () => { failures += 1; });
  for (let index = 0; index < 129; ++index) {
    channel.emit('data', maskedFrame(0x9, Buffer.alloc(0)));
  }
  assert.equal(failures, 1);
  channel.emit('close');
}

{
  const channel = new Channel();
  let failures = 0;
  attachReferenceWebSocket(channel, () => { failures += 1; });
  channel.emit('data', Buffer.from([0x82, 0x00]));
  assert.equal(failures, 1);
  channel.emit('close');
}

{
  const channel = new Channel();
  let failures = 0;
  attachReferenceWebSocket(channel, () => { failures += 1; });
  channel.emit('data', maskedFrame(
    0x8, Buffer.concat([Buffer.from([0x03, 0xe8]), Buffer.from('fixture-complete')])));
  assert.equal(failures, 1);
  channel.emit('close');
}

process.stdout.write('cover workload tests passed\n');
