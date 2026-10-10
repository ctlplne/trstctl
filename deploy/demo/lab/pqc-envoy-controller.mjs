// SPDX-License-Identifier: BUSL-1.1
// Local REST xDS fixture for the PQC host-agent journey. It persists each LDS
// candidate, serves Envoy's native discovery protocol, and reads the active
// listener from Envoy admin before acknowledging a posture change.
import { createServer } from 'node:http';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const statePath = process.env.PQC_ENVOY_STATE || '/state/lds.json';
const adminURL = process.env.PQC_ENVOY_ADMIN || 'http://127.0.0.1:9901';
const seedPath = process.env.PQC_ENVOY_SEED || '/app/initial-lds.json';
const port = Number(process.env.PQC_ENVOY_PORT || '19080');
const listenerName = 'pqc-edge';
let updating = false;

try {
  await readFile(statePath);
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  const seed = JSON.parse(await readFile(seedPath, 'utf8'));
  if (seed.resources?.length !== 1 || seed.resources[0]?.name !== listenerName)
    throw new Error('invalid initial local LDS state');
  await writeFile(statePath, `${JSON.stringify(seed)}\n`, {flag: 'wx', mode: 0o600});
}

const json = (res, status, body) => {
  const data = JSON.stringify(body);
  res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
  res.end(data);
};

async function state() {
  const discovery = JSON.parse(await readFile(statePath, 'utf8'));
  if (discovery.resources?.length !== 1 || discovery.resources[0]?.name !== listenerName ||
      typeof discovery.version_info !== 'string') throw new Error('invalid local LDS state');
  return discovery;
}

function tlsParams(listener) {
  const chains = listener?.filter_chains;
  if (!Array.isArray(chains) || chains.length !== 1) throw new Error('listener filter chains changed');
  const params = chains[0]?.transport_socket?.typed_config?.common_tls_context?.tls_params;
  if (!params) throw new Error('listener TLS parameters missing');
  return params;
}

function posture(params) {
  const versions = {TLSv1_2: 'TLSv1.2', TLSv1_3: 'TLSv1.3'};
  const groups = params.ecdh_curves;
  if (!versions[params.tls_minimum_protocol_version] || !Array.isArray(groups) || !groups.length)
    throw new Error('unsupported active TLS posture');
  return {
    minimum_version: versions[params.tls_minimum_protocol_version],
    cipher_suites: params.cipher_suites || [],
    key_exchange_groups: groups,
  };
}

async function active() {
  const response = await fetch(`${adminURL}/config_dump?resource=dynamic_listeners`, {signal: AbortSignal.timeout(2000)});
  if (!response.ok) throw new Error(`Envoy admin status ${response.status}`);
  const dump = await response.json();
  const selected = dump.configs?.filter((item) => item.name === listenerName);
  if (selected?.length !== 1 || !selected[0].active_state?.listener)
    throw new Error('Envoy has no active bound listener');
  return {
    version: selected[0].active_state.version_info,
    posture: posture(tlsParams(selected[0].active_state.listener)),
  };
}

function exact(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

async function waitActive(expected) {
  // The product verifies independently with a TLS handshake. The controller
  // merely waits for native LDS activation so its GET cannot echo a proposal.
  for (let attempt = 0; attempt < 80; attempt++) {
    const current = await active().catch(() => null);
    if (current && exact(current.posture, expected)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Envoy did not activate the proposed listener posture');
}

async function persist(next) {
  await writeFile(`${statePath}.next`, `${JSON.stringify(next)}\n`, {mode: 0o600});
  await rename(`${statePath}.next`, statePath);
}

function validateDesired(value) {
  if (!value || !['TLSv1.2', 'TLSv1.3'].includes(value.minimum_version) ||
      !Array.isArray(value.cipher_suites) || !Array.isArray(value.key_exchange_groups) ||
      !value.key_exchange_groups.length || value.key_exchange_groups.length > 32 ||
      value.cipher_suites.length > 64 ||
      value.key_exchange_groups.some((group) => !/^[A-Za-z0-9_-]{1,64}$/.test(group)) ||
      value.cipher_suites.some((suite) => !/^[A-Za-z0-9_-]{1,128}$/.test(suite)))
    throw new Error('invalid posture request');
  if (value.minimum_version === 'TLSv1.3' && value.cipher_suites.length)
    throw new Error('Envoy cannot constrain TLS 1.3 cipher suites');
  if (value.minimum_version === 'TLSv1.2' && !value.cipher_suites.length)
    throw new Error('TLS 1.2 requires explicit cipher suites');
  return value;
}

function nativeParams(value) {
  const version = value.minimum_version === 'TLSv1.3' ? 'TLSv1_3' : 'TLSv1_2';
  const params = {tls_minimum_protocol_version: version, ecdh_curves: value.key_exchange_groups};
  if (value.cipher_suites.length) params.cipher_suites = value.cipher_suites;
  return params;
}

async function body(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 8192) throw new Error('posture request exceeds size limit');
  }
  return validateDesired(JSON.parse(raw));
}

createServer(async (req, res) => {
  try {
    if (req.url === '/v3/discovery:listeners' && req.method === 'POST') {
      const discovery = await state();
      json(res, 200, {...discovery, type_url: 'type.googleapis.com/envoy.config.listener.v3.Listener'});
      return;
    }
    if (req.url !== `/v1/tls-posture/${listenerName}`) { json(res, 404, {error: 'unknown listener'}); return; }
    if (req.method === 'GET') { json(res, 200, (await active()).posture); return; }
    if (req.method !== 'PUT') { json(res, 405, {error: 'method refused'}); return; }
    if (updating) { json(res, 409, {error: 'listener update in progress'}); return; }
    updating = true;
    try {
      const desired = await body(req);
      const previous = await state();
      const before = await active();
      if (!exact(posture(tlsParams(previous.resources[0])), before.posture))
        throw new Error('Envoy and durable LDS state diverged');
      if (exact(before.posture, desired)) { json(res, 200, {applied: false}); return; }
      const next = structuredClone(previous);
      Object.assign(tlsParams(next.resources[0]), nativeParams(desired));
      if (!desired.cipher_suites.length) delete tlsParams(next.resources[0]).cipher_suites;
      next.version_info = createHash('sha256').update(JSON.stringify(next.resources)).digest('hex');
      await persist(next);
      try {
        await waitActive(desired);
      } catch (error) {
        await persist(previous);
        await waitActive(before.posture);
        throw error;
      }
      json(res, 200, {applied: true, version: next.version_info});
    } finally { updating = false; }
  } catch (error) {
    // No payload or secret is returned in an error. The native admin readback
    // and host-agent signed report carry the auditable detail.
    json(res, 503, {error: error.message});
  }
}).listen(port, '0.0.0.0');
