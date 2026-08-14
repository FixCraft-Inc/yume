import { pathToFileURL } from 'node:url';

const COMMAND_TIMEOUT_MS = 15000;
const HTTP_TIMEOUT_MS = 5000;
const NAVIGATION_TIMEOUT_MS = 15000;
const SOCKET_TIMEOUT_MS = 5000;
const POLL_INTERVAL_MS = 25;

const delay = milliseconds =>
  new Promise(resolve => setTimeout(resolve, milliseconds));

export async function fetchDevtoolsJson(url, {
  method = 'GET',
  timeoutMs = HTTP_TIMEOUT_MS,
  fetchImpl = fetch
} = {}) {
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetchImpl(url, { method, signal });
    if (!response.ok) {
      throw new Error(`DevTools HTTP request failed: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    if (signal.aborted) {
      throw new Error('DevTools HTTP request timed out', { cause: error });
    }
    throw error;
  }
}

function createCdpSession(socket) {
  const lifecycleEvents = [];
  const pending = new Map();
  let nextId = 1;

  const rejectPending = error => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    pending.clear();
  };

  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id !== undefined) {
      const waiter = pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error(message.error.message));
      else waiter.resolve(message.result);
      return;
    }
    if (message.method === 'Page.lifecycleEvent') {
      lifecycleEvents.push(message.params);
      if (lifecycleEvents.length > 256) lifecycleEvents.shift();
    }
  });
  socket.addEventListener('close', () =>
    rejectPending(new Error('Chrome DevTools socket closed')));
  socket.addEventListener('error', () =>
    rejectPending(new Error('Chrome DevTools socket failed')));

  const command = (method, params = {}) => {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`Chrome DevTools command timed out: ${method}`));
      }, COMMAND_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer });
      try {
        socket.send(JSON.stringify({ id, method, params }));
      } catch (error) {
        clearTimeout(timer);
        pending.delete(id);
        reject(error);
      }
    });
  };
  return { command, lifecycleEvents };
}

async function waitForOpen(socket) {
  if (socket.readyState === 1) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Chrome DevTools socket open timed out')),
      SOCKET_TIMEOUT_MS
    );
    socket.addEventListener('open', () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
    socket.addEventListener('error', () => {
      clearTimeout(timer);
      reject(new Error('Chrome DevTools socket open failed'));
    }, { once: true });
  });
}

async function closeSocket(socket) {
  if (socket.readyState === 3) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Chrome DevTools socket close timed out')),
      SOCKET_TIMEOUT_MS
    );
    const complete = callback => {
      clearTimeout(timer);
      callback();
    };
    socket.addEventListener('close', () => complete(resolve), { once: true });
    socket.addEventListener('error', () => complete(() =>
      reject(new Error('Chrome DevTools socket close failed'))), { once: true });
    socket.close();
  });
}

async function waitForLifecycleEvent({
  lifecycleEvents,
  frameId,
  loaderId,
  deadline,
  sleep
}) {
  while (Date.now() < deadline) {
    if (lifecycleEvents.some(event =>
      event.name === 'load' && event.frameId === frameId &&
      event.loaderId === loaderId)) {
      return;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error(
    'Chrome target lifecycle timed out: ' +
    JSON.stringify({ frameId, loaderId, observed: lifecycleEvents })
  );
}

async function waitForTargetDocument({ command, targetUrl, deadline, sleep }) {
  let diagnostic = { state: null, error: null };
  while (Date.now() < deadline) {
    try {
      const evaluatedState = await command('Runtime.evaluate', {
        returnByValue: true,
        expression: `({
          href: location.href,
          readyState: document.readyState,
          fixtureReady: document.documentElement?.dataset?.ready ?? null
        })`
      });
      if (evaluatedState.exceptionDetails) {
        diagnostic = {
          state: null,
          error: evaluatedState.exceptionDetails.text ?? 'evaluation failed'
        };
      } else {
        diagnostic = { state: evaluatedState.result?.value ?? null, error: null };
        if (diagnostic.state?.href === targetUrl &&
            diagnostic.state?.fixtureReady === 'true') {
          return;
        }
      }
    } catch (error) {
      // A matching navigation can replace the execution context between polls.
      diagnostic = { state: null, error: String(error) };
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error(
    'Chrome target document did not become ready: ' +
    JSON.stringify({ targetUrl, diagnostic })
  );
}

export async function navigateToFixture({
  command,
  lifecycleEvents,
  targetUrl,
  timeoutMs = NAVIGATION_TIMEOUT_MS,
  sleep = delay
}) {
  await command('Page.setLifecycleEventsEnabled', { enabled: true });
  lifecycleEvents.length = 0;
  const navigation = await command('Page.navigate', { url: targetUrl });
  if (navigation.errorText) {
    throw new Error(`Chrome target navigation failed: ${navigation.errorText}`);
  }
  if (!navigation.frameId || !navigation.loaderId) {
    throw new Error('Chrome target navigation did not create a new loader');
  }
  const deadline = Date.now() + timeoutMs;
  await waitForLifecycleEvent({
    lifecycleEvents,
    frameId: navigation.frameId,
    loaderId: navigation.loaderId,
    deadline,
    sleep
  });
  await waitForTargetDocument({ command, targetUrl, deadline, sleep });
  return navigation;
}

async function closeBrowser(devtoolsBase) {
  const version = await fetchDevtoolsJson(`${devtoolsBase}/json/version`);
  const browserSocket = new WebSocket(version.webSocketDebuggerUrl);
  await waitForOpen(browserSocket);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Browser.close timed out')),
      SOCKET_TIMEOUT_MS
    );
    const complete = callback => {
      clearTimeout(timer);
      callback();
    };
    browserSocket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (message.id === 1) complete(resolve);
    });
    browserSocket.addEventListener('close', () => complete(resolve), { once: true });
    browserSocket.addEventListener('error', () => complete(() =>
      reject(new Error('Browser.close socket failed'))), { once: true });
    browserSocket.send(JSON.stringify({ id: 1, method: 'Browser.close' }));
  });
}

export async function main(argv = process.argv) {
  const port = Number.parseInt(argv[2] ?? '', 10);
  const targetUrl = argv[3];
  const holdMs = Number.parseInt(argv[4] ?? '0', 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !targetUrl) {
    throw new Error(
      'usage: node capture_chrome.mjs <devtools-port> <https-url> [active-hold-ms]'
    );
  }
  if (!Number.isInteger(holdMs) || holdMs < 0 || holdMs > 120000) {
    throw new Error('active-hold-ms must be 0..120000');
  }

  const devtoolsBase = `http://127.0.0.1:${port}`;
  const target = await fetchDevtoolsJson(
    `${devtoolsBase}/json/new?${encodeURIComponent('about:blank')}`,
    { method: 'PUT' }
  );
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await waitForOpen(socket);
  const { command, lifecycleEvents } = createCdpSession(socket);

  await command('Page.enable');
  await command('Runtime.enable');
  await navigateToFixture({ command, lifecycleEvents, targetUrl });
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
        href: location.href,
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
  if (holdMs > 0) await delay(holdMs);
  await command('Runtime.evaluate', {
    expression: `window.fixtureSocket?.close(1000, 'fixture-complete')`
  });
  await closeSocket(socket);
  await closeBrowser(devtoolsBase);
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
