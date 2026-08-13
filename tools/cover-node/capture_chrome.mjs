const port = Number.parseInt(process.argv[2] ?? '', 10);
const targetUrl = process.argv[3];
const holdMs = Number.parseInt(process.argv[4] ?? '0', 10);
if (!Number.isInteger(port) || port < 1 || port > 65535 || !targetUrl) {
  throw new Error(
    'usage: node capture_chrome.mjs <devtools-port> <https-url> [active-hold-ms]'
  );
}
if (!Number.isInteger(holdMs) || holdMs < 0 || holdMs > 120000) {
  throw new Error('active-hold-ms must be 0..120000');
}

const devtoolsBase = `http://127.0.0.1:${port}`;
const created = await fetch(
  `${devtoolsBase}/json/new?${encodeURIComponent('about:blank')}`,
  { method: 'PUT' }
);
if (!created.ok) throw new Error(`DevTools target creation failed: ${created.status}`);
const target = await created.json();

const socket = new WebSocket(target.webSocketDebuggerUrl);
const pending = new Map();
let nextId = 1;
socket.addEventListener('message', event => {
  const message = JSON.parse(event.data);
  if (!message.id) return;
  const waiter = pending.get(message.id);
  if (!waiter) return;
  pending.delete(message.id);
  if (message.error) waiter.reject(new Error(message.error.message));
  else waiter.resolve(message.result);
});
await new Promise((resolve, reject) => {
  socket.addEventListener('open', resolve, { once: true });
  socket.addEventListener('error', reject, { once: true });
});

function command(method, params = {}) {
  const id = nextId++;
  socket.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

await command('Page.enable');
await command('Runtime.enable');
await command('Page.navigate', { url: targetUrl });
const evaluated = await command('Runtime.evaluate', {
  awaitPromise: true,
  returnByValue: true,
  expression: `new Promise((resolve, reject) => {
    const deadline = Date.now() + 10000;
    const poll = () => {
      const value = document.documentElement?.dataset?.ws;
      if (value === 'ok') return resolve(value);
      if (value === 'bad' || value === 'error') return reject(new Error(value));
      if (Date.now() >= deadline) return reject(new Error('WebSocket fixture timeout'));
      setTimeout(poll, 25);
    };
    poll();
  })`
});
if (evaluated.exceptionDetails || evaluated.result?.value !== 'ok') {
  const diagnostic = await command('Runtime.evaluate', {
    returnByValue: true,
    expression: `({
      readyState: document.readyState,
      dataset: {...document.documentElement.dataset},
      resources: performance.getEntriesByType('resource').map(entry => entry.name)
    })`
  });
  throw new Error(
    'Chrome did not complete the RFC 8441 fixture: ' +
    JSON.stringify({ evaluated, diagnostic })
  );
}
process.stdout.write('Chrome priming GET and WebSocket fixture completed\n');
if (holdMs > 0) await new Promise(resolve => setTimeout(resolve, holdMs));
await command('Runtime.evaluate', {
  expression: `window.fixtureSocket?.close(1000, 'fixture-complete')`
});
socket.close();

const versionResponse = await fetch(`${devtoolsBase}/json/version`);
const version = await versionResponse.json();
const browserSocket = new WebSocket(version.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  browserSocket.addEventListener('open', resolve, { once: true });
  browserSocket.addEventListener('error', reject, { once: true });
});
browserSocket.send(JSON.stringify({ id: 1, method: 'Browser.close' }));
