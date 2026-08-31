// SPDX-License-Identifier: MPL-2.0
// Run after npm ci in web/: node --test docs/demo_html_behavior.test.mjs
// These are isolated document tests, not a browser or live-product qualification.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const require = createRequire(new URL('../web/package.json', import.meta.url));
const { JSDOM, VirtualConsole } = require('jsdom');
const sourceURL = new URL('./demo-click-through.html', import.meta.url);
const html = readFileSync(sourceURL, 'utf8');
const defaultOrigin = 'https://127.0.0.1:9443';

function page(url = 'https://localhost/guide.html', seed = {}, blockedStorage = false) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', error => errors.push(error.message));
  const dom = new JSDOM(html, {
    url, runScripts: 'dangerously', virtualConsole,
    beforeParse(window) {
      window.confirm = () => true;
      if (blockedStorage) {
        Object.defineProperty(window, 'localStorage', {
          get() { throw new Error('Storage intentionally disabled for this test'); },
        });
      } else if (!url.startsWith('file:')) {
        for (const [key, value] of Object.entries(seed)) window.localStorage.setItem(key, value);
      }
    },
  });
  return { dom, document: dom.window.document, errors };
}

function assertOrigin(document, expected) {
  for (const link of document.querySelectorAll('[data-demo-path]')) {
    assert.equal(new URL(link.href).origin, expected);
    assert.equal(link.target, '_blank');
    assert.match(link.rel, /noopener/);
  }
}

test('default guide keeps the shipped HTTPS origin and unverified candidate label', () => {
  const { dom, document, errors } = page();
  assertOrigin(document, defaultOrigin);
  assert.match(document.querySelector('#expected-candidate').textContent, /not supplied/);
  assert.deepEqual(errors, []);
  dom.window.close();
});

test('loopback HTTPS and a valid candidate update links without claiming a running-build match', () => {
  const { dom, document, errors } = page('https://localhost/guide.html?demo=https%3A%2F%2Flocalhost%3A7443&candidate=ABCDEF123');
  assertOrigin(document, 'https://localhost:7443');
  assert.equal(document.querySelector('#expected-candidate').textContent, 'abcdef123');
  assert.match(document.querySelector('.identity-grid').textContent, /Read it in System health/);
  assert.deepEqual(errors, []);
  dom.window.close();
});

test('external, credential-bearing, malformed and script origins fail closed', () => {
  for (const supplied of ['https://example.com', 'https://user:password@localhost:7443',
    'javascript:alert(1)', 'file:///tmp/app', 'https://localhost:7443/?token=bad',
    'https://localhost:7443/#bad', 'not a url']) {
    const { dom, document, errors } = page(`https://localhost/guide.html?demo=${encodeURIComponent(supplied)}`);
    assertOrigin(document, defaultOrigin);
    assert.deepEqual(errors, []);
    dom.window.close();
  }
});

test('HTTP visual bridge is accepted only from a loopback HTTP guide', () => {
  for (const [guide, expected] of [
    ['http://127.0.0.1/guide.html', 'http://127.0.0.1:6555'],
    ['https://127.0.0.1/guide.html', defaultOrigin],
    ['http://example.com/guide.html', defaultOrigin],
  ]) {
    const { dom, document } = page(`${guide}?demo=http%3A%2F%2F127.0.0.1%3A6555`);
    assertOrigin(document, expected);
    dom.window.close();
  }
});

test('invalid candidate text is rejected and never parsed as HTML', () => {
  const { dom, document, errors } = page('https://localhost/guide.html?candidate=%3Cimg%20src=x%3E');
  assert.match(document.querySelector('#expected-candidate').textContent, /Invalid candidate/);
  assert.equal(document.querySelector('#expected-candidate img'), null);
  assert.deepEqual(errors, []);
  dom.window.close();
});

test('all fragment destinations are unique and present; source-mode doc links exist', () => {
  const { dom, document, errors } = page(sourceURL.href);
  const ids = Array.from(document.querySelectorAll('[id]'), element => element.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate element IDs');
  for (const link of document.querySelectorAll('a[href^="#"]')) {
    assert.ok(document.getElementById(link.getAttribute('href').slice(1)), link.outerHTML);
  }
  for (const link of document.querySelectorAll('[data-source-href]')) {
    assert.equal(new URL(link.href).protocol, 'file:');
    assert.ok(existsSync(fileURLToPath(link.href)), link.href);
  }
  assert.deepEqual(errors, []);
  dom.window.close();
});

test('reading progress is persisted only for the same origin and expected candidate', () => {
  const key = `trstctl-demo-walkthrough-progress-v2:${defaultOrigin}:abcdef1`;
  const { dom, document } = page('https://localhost/guide.html?candidate=abcdef1');
  document.querySelector('.step-check').click();
  assert.match(document.querySelector('#progress-copy').textContent, /1 of 15 tour stops reviewed/);
  const stored = dom.window.localStorage.getItem(key);
  assert.deepEqual(JSON.parse(stored), ['1']);
  dom.window.close();
  const same = page('https://localhost/guide.html?candidate=abcdef1', { [key]: stored });
  assert.equal(same.document.querySelector('.step-check').checked, true);
  same.dom.window.close();
  for (const url of ['https://localhost/guide.html?candidate=abcdef2',
    'https://localhost/guide.html?candidate=abcdef1&demo=https%3A%2F%2Flocalhost%3A7443']) {
    const other = page(url, { [key]: stored });
    assert.equal(other.document.querySelector('.step-check').checked, false);
    other.dom.window.close();
  }
});

test('disabled storage does not break checkboxes or reset', () => {
  const { dom, document, errors } = page('https://localhost/guide.html', {}, true);
  document.querySelector('.step-check').click();
  assert.match(document.querySelector('#progress-copy').textContent, /1 of 15 tour stops reviewed/);
  document.querySelector('#reset-progress').click();
  assert.match(document.querySelector('#progress-copy').textContent, /0 of 15 tour stops reviewed/);
  assert.deepEqual(errors, []);
  dom.window.close();
});

test('presenter document makes no network request and embeds no third-party asset', () => {
  const { dom, document } = page();
  assert.equal(document.querySelectorAll('script[src], iframe, img[src], link[rel="stylesheet"]').length, 0);
  for (const script of document.querySelectorAll('script')) {
    assert.doesNotMatch(script.textContent, /\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon/);
  }
  dom.window.close();
});
