import { readFileSync } from 'node:fs';

const sourcePath = process.argv[2];
const authority = process.argv[3];
if (!sourcePath || !authority) {
  throw new Error('usage: node sanitize_netlog.mjs <netlog.json> <authority>');
}

const raw = JSON.parse(readFileSync(sourcePath, 'utf8'));
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

const fixture = {
  schema: 1,
  authority: '<cover-authority>',
  client: {
    name: raw.constants.clientInfo.name,
    version: raw.constants.clientInfo.version,
    os_type: raw.constants.clientInfo.os_type
  },
  tls,
  client_settings: session.find(event =>
    event.event_name === 'HTTP2_SESSION_SEND_SETTINGS'
  )?.params?.settings,
  client_connection_window_update: session.find(event =>
    event.event_name === 'HTTP2_SESSION_SEND_WINDOW_UPDATE' &&
    event.params?.stream_id === 0
  )?.params,
  server_non_default_settings: session
    .filter(event => event.event_name === 'HTTP2_SESSION_RECV_SETTING')
    .map(event => event.params),
  headers: headerEvents,
  websocket_frames: websocketSummary,
  flow_control: {
    stream_stall_count: session.filter(event =>
      event.event_name === 'HTTP2_SESSION_STREAM_STALLED_BY_STREAM_SEND_WINDOW'
    ).length,
    window_updates_received: countDistinct(session.filter(event =>
      event.event_name === 'HTTP2_SESSION_RECV_WINDOW_UPDATE'
    ).map(event => event.params))
  },
  h2_data_frames: countDistinct(session.filter(event =>
    event.event_name === 'HTTP2_SESSION_SEND_DATA' ||
    event.event_name === 'HTTP2_SESSION_RECV_DATA'
  ).map(event => ({
    direction: event.event_name === 'HTTP2_SESSION_SEND_DATA' ? 'sent' : 'received',
    stream_id: event.params.stream_id,
    fin: event.params.fin,
    size: event.params.size
  }))),
  h2_pings: session.filter(event =>
    event.event_name === 'HTTP2_SESSION_PING'
  ).map(event => ({
    milliseconds_after_session_start:
      Number.parseInt(event.time, 10) - sessionStartTime,
    ...event.params
  }))
};

process.stdout.write(`${JSON.stringify(fixture, null, 2)}\n`);
