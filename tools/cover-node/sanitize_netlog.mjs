import { readFileSync } from 'node:fs';

const sourcePath = process.argv[2];
const authority = process.argv[3];
if (!sourcePath || !authority) {
  throw new Error('usage: node sanitize_netlog.mjs <netlog.json> <authority>');
}

function loadNetLog(path) {
  const text = readFileSync(path, 'utf8');
  try {
    return { value: JSON.parse(text), recovery: { used: false, skipped_event_lines: 0 } };
  } catch (originalError) {
    // Chrome 151 can occasionally interleave two event writes while closing a
    // long IncludeSensitive NetLog. Constants and events are line-delimited,
    // so recover complete event objects and reject a broadly damaged file.
    // The selected target session still has to pass every semantic check below.
    const marker = '\n"events": [\n';
    const markerOffset = text.indexOf(marker);
    if (markerOffset < 0) throw originalError;
    const constantsText = `${text.slice(0, markerOffset).trimEnd().replace(/,$/, '')}}`;
    const constantsContainer = JSON.parse(constantsText);
    const eventText = text.slice(markerOffset + marker.length);
    const events = [];
    let skippedEventLines = 0;
    for (const sourceLine of eventText.split('\n')) {
      let line = sourceLine.trim();
      if (!line || line === ']' || line === '}') continue;
      if (line.endsWith(',')) line = line.slice(0, -1);
      if (!line.startsWith('{') || !line.endsWith('}')) {
        skippedEventLines += 1;
        continue;
      }
      try {
        events.push(JSON.parse(line));
      } catch {
        skippedEventLines += 1;
      }
    }
    if (skippedEventLines === 0 || skippedEventLines > 64) {
      throw originalError;
    }
    return {
      value: { ...constantsContainer, events },
      recovery: { used: true, skipped_event_lines: skippedEventLines }
    };
  }
}

const loaded = loadNetLog(sourcePath);
const raw = loaded.value;
const eventNames = new Map(
  Object.entries(raw.constants.logEventTypes).map(([name, id]) => [id, name])
);
const named = raw.events.map(event => ({
  ...event,
  event_name: eventNames.get(event.type) ?? `UNKNOWN_${event.type}`
}));
const sessionStart = named.find(event =>
  event.event_name === 'HTTP2_SESSION' && event.phase === 1 &&
  event.params?.host === authority
);
if (!sessionStart) throw new Error(`no HTTP/2 session found for ${authority}`);
const sessionId = sessionStart.source.id;
const session = named.filter(event => event.source.id === sessionId);
const sessionStartTime = Number.parseInt(sessionStart.time, 10);

function normalizeHeaders(headers = []) {
  return headers.map(header => {
    if (header.startsWith('date: ')) return 'date: <runtime-date>';
    return header
      .replaceAll(authority, '<cover-authority>')
      .replaceAll(`https://${authority}`, 'https://<cover-authority>');
  });
}

const headerEvents = session
  .filter(event => event.event_name === 'HTTP2_SESSION_SEND_HEADERS' ||
                   event.event_name === 'HTTP2_SESSION_RECV_HEADERS')
  .map(event => ({
    direction: event.event_name === 'HTTP2_SESSION_SEND_HEADERS' ? 'sent' : 'received',
    stream_id: event.params.stream_id,
    fin: event.params.fin,
    exclusive: event.params.exclusive,
    parent_stream_id: event.params.parent_stream_id,
    weight: event.params.weight,
    headers: normalizeHeaders(event.params.headers)
  }));

const websocketFrames = named
  .filter(event => event.event_name === 'WEBSOCKET_SENT_FRAME_HEADER' ||
                   event.event_name === 'WEBSOCKET_RECV_FRAME_HEADER')
  .map(event => ({
    direction: event.event_name === 'WEBSOCKET_SENT_FRAME_HEADER' ? 'sent' : 'received',
    final: event.params.final,
    masked: event.params.masked,
    opcode: event.params.opcode,
    payload_length: event.params.payload_length
  }));
const websocketSummary = [];
for (const frame of websocketFrames) {
  const match = websocketSummary.find(item =>
    JSON.stringify(item.frame) === JSON.stringify(frame)
  );
  if (match) match.count += 1;
  else websocketSummary.push({ frame, count: 1 });
}

function countDistinct(items) {
  const counted = [];
  for (const item of items) {
    const match = counted.find(entry =>
      JSON.stringify(entry.sample) === JSON.stringify(item)
    );
    if (match) match.count += 1;
    else counted.push({ sample: item, count: 1 });
  }
  return counted;
}

const initialized = session.find(event => event.event_name === 'HTTP2_SESSION_INITIALIZED');
const tlsSourceId = initialized?.params?.source_dependency?.id;
const tls = named.find(event =>
  event.source.id === tlsSourceId && event.event_name === 'SSL_CONNECT' && event.phase === 2
)?.params;

function parseHeader(header) {
  const separator = header.indexOf(': ', header.startsWith(':') ? 1 : 0);
  if (separator < 0) throw new Error(`malformed NetLog header: ${header}`);
  return [header.slice(0, separator), header.slice(separator + 2)];
}

function structuredRequest(event, normalizeCarrierPath = false) {
  if (!event) return undefined;
  const headers = event.headers.map(parseHeader);
  if (normalizeCarrierPath) {
    const path = headers.find(([name]) => name === ':path');
    if (path) path[1] = '<authenticated-carrier-path>';
  }
  return {
    stream_id: event.stream_id,
    parent_stream_id: event.parent_stream_id,
    exclusive: event.exclusive,
    weight: event.weight,
    headers_in_order: headers
  };
}

function headerValue(event, name) {
  return event?.headers.map(parseHeader).find(([key]) => key === name)?.[1];
}

function parseSetting(setting) {
  const match = /^\[id:(\d+) \(([^)]+)\) value:(\d+)\]$/.exec(setting);
  if (!match) throw new Error(`malformed NetLog HTTP/2 setting: ${setting}`);
  return [Number.parseInt(match[1], 10), Number.parseInt(match[3], 10), match[2]];
}

const sentHeaders = headerEvents.filter(event => event.direction === 'sent');
const receivedHeaders = headerEvents.filter(event => event.direction === 'received');
const primingEvent = sentHeaders.find(event =>
  headerValue(event, ':method') === 'GET' && headerValue(event, ':path') === '/'
);
const connectEvent = sentHeaders.find(event =>
  headerValue(event, ':method') === 'CONNECT' &&
  headerValue(event, ':protocol') === 'websocket'
);
if (!primingEvent) throw new Error('no priming GET found in Chrome session');
if (!connectEvent) throw new Error('no RFC 8441 extended CONNECT found in Chrome session');
const connectResponse = receivedHeaders.find(event =>
  event.stream_id === connectEvent.stream_id
);
const assets = sentHeaders
  .filter(event => headerValue(event, ':path')?.startsWith('/assets/'))
  .map(event => ({
    path: headerValue(event, ':path'),
    ...structuredRequest(event)
  }));

const settingsInOrder = (fixtureSettings => {
  if (!Array.isArray(fixtureSettings)) {
    throw new Error('Chrome session has no client HTTP/2 settings');
  }
  return fixtureSettings.map(parseSetting);
})(session.find(event => event.event_name === 'HTTP2_SESSION_SEND_SETTINGS')?.params?.settings);
const nodeSettingsInOrder = session
  .filter(event => event.event_name === 'HTTP2_SESSION_RECV_SETTING')
  .map(event => {
    const match = /^(\d+) \(([^)]+)\)$/.exec(event.params.id);
    if (!match) throw new Error(`malformed Node HTTP/2 setting: ${event.params.id}`);
    return [Number.parseInt(match[1], 10), event.params.value, match[2]];
  });
const connectionWindowUpdate = session.find(event =>
  event.event_name === 'HTTP2_SESSION_SEND_WINDOW_UPDATE' &&
  event.params?.stream_id === 0
)?.params;
if (!connectionWindowUpdate) {
  throw new Error('Chrome session has no connection WINDOW_UPDATE');
}

const frameCount = (direction, opcode, payloadLength, final = undefined) =>
  websocketFrames
    .filter(frame => frame.direction === direction && frame.opcode === opcode &&
      frame.payload_length === payloadLength &&
      (final === undefined || frame.final === final))
    .length;
const h2Pings = session.filter(event =>
  event.event_name === 'HTTP2_SESSION_PING'
).map(event => ({
  milliseconds_after_session_start:
    Number.parseInt(event.time, 10) - sessionStartTime,
  ...event.params
}));

const fixture = {
  schema: 2,
  authority: '<cover-authority>',
  client: {
    name: raw.constants.clientInfo.name,
    version: raw.constants.clientInfo.version,
    os: raw.constants.clientInfo.os_type
  },
  tls_observation: {
    version: tls?.version,
    alpn: tls?.next_proto,
    cipher_suite: `0x${tls?.cipher_suite?.toString(16).padStart(4, '0')}`,
    key_exchange_group: `0x${tls?.key_exchange_group?.toString(16).padStart(4, '0')}`,
    peer_signature_algorithm:
      `0x${tls?.peer_signature_algorithm?.toString(16).padStart(4, '0')}`,
    resumed: tls?.is_resumed,
    encrypted_client_hello: tls?.encrypted_client_hello,
    warning: 'Browser observation only; ClientHello parity is evaluated separately.'
  },
  client_settings_in_order: settingsInOrder,
  client_connection_window_update: {
    stream_id: connectionWindowUpdate.stream_id,
    delta: connectionWindowUpdate.delta,
    resulting_window: 65535 + connectionWindowUpdate.delta
  },
  node_non_default_settings_in_order: nodeSettingsInOrder,
  priming_get: structuredRequest(primingEvent),
  asset_sequence: assets,
  extended_connect: {
    ...structuredRequest(connectEvent, true),
    requires_completed_priming_get: true,
    node_response_headers_in_order:
      connectResponse?.headers.map(parseHeader) ?? []
  },
  websocket_fixture: {
    application_bytes_each_direction: 1024 * 1024,
    client_binary_messages: {
      count: frameCount('sent', 2, 16384, true),
      payload_bytes: 16384,
      masked: true
    },
    server_binary_messages: {
      unfragmented_count: frameCount('received', 2, 16384, true),
      payload_bytes: 16384,
      masked: false
    },
    server_fragmented_binary_message: [
      { opcode: 2, final: false, payload_bytes: 8192, masked: false },
      { opcode: 0, final: true, payload_bytes: 8192, masked: false }
    ],
    ping_pong: {
      server_ping_payload_bytes: 12,
      client_pong_payload_bytes: 12,
      client_pong_masked: true
    },
    close: {
      payload_bytes: 18,
      client_masked: true,
      server_masked: false,
      h2_ping_immediately_before_close: h2Pings.some(ping => !ping.is_ack),
      h2_ping_originator: 'client'
    }
  },
  flow_control_fixture: {
    client_stream_send_stalls: session.filter(event =>
      event.event_name === 'HTTP2_SESSION_STREAM_STALLED_BY_STREAM_SEND_WINDOW'
    ).length,
    window_update_recovery_observed: session.some(event =>
      event.event_name === 'HTTP2_SESSION_RECV_WINDOW_UPDATE'
    )
  },
  idle_and_close: {
    requested_idle_ms: h2Pings.find(ping => !ping.is_ack)
      ?.milliseconds_after_session_start,
    h2_pings: h2Pings,
    graceful_websocket_close_observed:
      frameCount('sent', 8, 18, true) === 1 &&
      frameCount('received', 8, 18, true) === 1
  },
  shaping_policy: {
    synthetic_idle_keepalive: false,
    random_padding: false,
    random_timing_jitter: false,
    bulk_websocket_message_bytes: 16384
  },
  observations: {
    netlog_recovery: loaded.recovery,
    headers: headerEvents,
    websocket_frames: websocketSummary,
    window_updates_received: countDistinct(session.filter(event =>
      event.event_name === 'HTTP2_SESSION_RECV_WINDOW_UPDATE'
    ).map(event => event.params)),
    h2_data_frames: countDistinct(session.filter(event =>
      event.event_name === 'HTTP2_SESSION_SEND_DATA' ||
      event.event_name === 'HTTP2_SESSION_RECV_DATA'
    ).map(event => ({
      direction: event.event_name === 'HTTP2_SESSION_SEND_DATA' ? 'sent' : 'received',
      stream_id: event.params.stream_id,
      fin: event.params.fin,
      size: event.params.size
    })))
  }
};

process.stdout.write(`${JSON.stringify(fixture, null, 2)}\n`);
