import assert from 'node:assert/strict';
import test from 'node:test';

import {
  fetchDevtoolsJson,
  navigateToFixture
} from './capture_chrome.mjs';

const targetUrl = 'https://cover.test:39443/';

test('waits for the matching loader before evaluating the fixture', async () => {
  const lifecycleEvents = [{
    name: 'load', frameId: 'old-frame', loaderId: 'old-loader'
  }];
  const calls = [];
  let matchingLoadObserved = false;
  let evaluations = 0;
  const command = async (method, params = {}) => {
    calls.push({ method, params });
    if (method === 'Page.setLifecycleEventsEnabled') return {};
    if (method === 'Page.navigate') {
      setTimeout(() => lifecycleEvents.push({
        name: 'DOMContentLoaded', frameId: 'new-frame', loaderId: 'new-loader'
      }), 1);
      setTimeout(() => {
        matchingLoadObserved = true;
        lifecycleEvents.push({
          name: 'load', frameId: 'new-frame', loaderId: 'new-loader'
        });
      }, 3);
      return { frameId: 'new-frame', loaderId: 'new-loader' };
    }
    assert.equal(method, 'Runtime.evaluate');
    assert.equal(matchingLoadObserved, true);
    evaluations += 1;
    if (evaluations === 1) {
      return { exceptionDetails: { text: 'Execution context was destroyed' } };
    }
    if (evaluations === 2) {
      return { result: { value: {
        href: 'about:blank', readyState: 'complete', fixtureReady: null
      } } };
    }
    return { result: { value: {
      href: targetUrl, readyState: 'complete', fixtureReady: 'true'
    } } };
  };

  await navigateToFixture({
    // The fixture intentionally needs three 25 ms document polls. Leave
    // enough scheduler margin for this success-path test to remain stable
    // while the full CTest suite is compiling/running in parallel.
    command, lifecycleEvents, targetUrl, timeoutMs: 500, sleep: delay
  });
  assert.equal(calls.filter(call => call.method === 'Page.navigate').length, 1);
  assert.equal(evaluations, 3);
});

test('rejects a Page.navigate error without evaluating', async () => {
  const lifecycleEvents = [];
  let evaluations = 0;
  const command = async method => {
    if (method === 'Page.setLifecycleEventsEnabled') return {};
    if (method === 'Page.navigate') return { errorText: 'ERR_CONNECTION_REFUSED' };
    evaluations += 1;
    return {};
  };
  await assert.rejects(
    navigateToFixture({ command, lifecycleEvents, targetUrl, timeoutMs: 20 }),
    /ERR_CONNECTION_REFUSED/
  );
  assert.equal(evaluations, 0);
});

test('times out without a matching frame and loader', async () => {
  const lifecycleEvents = [{
    name: 'load', frameId: 'old-frame', loaderId: 'old-loader'
  }];
  let evaluations = 0;
  const command = async method => {
    if (method === 'Page.setLifecycleEventsEnabled') return {};
    if (method === 'Page.navigate') {
      return { frameId: 'new-frame', loaderId: 'new-loader' };
    }
    evaluations += 1;
    return {};
  };
  await assert.rejects(
    navigateToFixture({ command, lifecycleEvents, targetUrl, timeoutMs: 5 }),
    /lifecycle timed out/
  );
  assert.equal(evaluations, 0);
});

test('bounds a stalled DevTools HTTP request', async () => {
  const hangingFetch = (_url, { signal }) => new Promise((_resolve, reject) => {
    const testDeadline = setTimeout(
      () => reject(new Error('test fetch was not aborted')),
      1000
    );
    signal.addEventListener('abort', () => {
      clearTimeout(testDeadline);
      reject(signal.reason);
    }, { once: true });
  });
  await assert.rejects(
    fetchDevtoolsJson('http://127.0.0.1:39222/json/version', {
      timeoutMs: 5,
      fetchImpl: hangingFetch
    }),
    /HTTP request timed out/
  );
});

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}
