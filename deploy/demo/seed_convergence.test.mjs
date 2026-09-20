// SPDX-License-Identifier: BUSL-1.1

import assert from "node:assert/strict";
import test from "node:test";

import {
  advanceIdentity,
  checkpointSource,
  checkpointDisposition,
  findUniqueLogicalRecord,
  seedInventoryDigest,
  seedCompletionSummary,
  stableDemoValue,
  stableSeedSemantics,
} from "./seed.mjs";

test("demo completion summary never renders one-time credential material", () => {
  const sentinel = "trst_should-never-reach-logs";
  const lines = seedCompletionSummary({
    url: "https://127.0.0.1:9443",
    tenant: "tenant-a",
    plannedEvents: 70,
    owners: 8,
    certificates: 17,
    secrets: 4,
    runs: 4,
    findings: 0,
    notifications: 1,
    oneTimeCredential: sentinel,
  });
  assert.ok(lines.some((line) => line.includes("Raw credential values: withheld")));
  assert.ok(lines.every((line) => !line.includes(sentinel)));
  assert.ok(lines.every((line) => !/One-time share token|Demo API token|Ephemeral incident token|Agent enrollment token/.test(line)));
});

test("AUD-66 stable demo request material survives process-level retries", () => {
  assert.equal(stableDemoValue("payments"), stableDemoValue("payments"));
  assert.notEqual(stableDemoValue("payments"), stableDemoValue("release"));
  assert.match(stableDemoValue("payments"), /^demo-payments-[0-9a-f]{64}$/);
});

test("AUD-66 duplicate logical records fail instead of selecting one", () => {
  const rows = [{ name: "Platform SRE" }, { name: "Platform SRE" }];
  assert.throws(
    () => findUniqueLogicalRecord(rows, (row) => row.name === "Platform SRE", "owner platform"),
    /duplicated 2 times/,
  );
});

test("AUD-66 semantic comparisons ignore only seed observation clocks", () => {
  const preserved = {
    protocol: "acme",
    demo_observed_at: "2025-01-01T00:00:00Z",
    nested: { observed_at: "2025-01-02T00:00:00Z", policy: "strict" },
  };
  const retried = {
    protocol: "acme",
    demo_observed_at: "2026-01-01T00:00:00Z",
    nested: { observed_at: "2026-01-02T00:00:00Z", policy: "strict" },
  };
  assert.deepEqual(stableSeedSemantics(preserved), stableSeedSemantics(retried));
  assert.notDeepEqual(
    stableSeedSemantics(preserved),
    stableSeedSemantics({ ...retried, nested: { ...retried.nested, policy: "permissive" } }),
  );
});

test("AUD-66 identity advancement observes state and reaches each transition once", async () => {
  let status = "requested";
  const transitions = [];
  const request = async (method, _path, body, key) => {
    if (method === "GET") return { id: "identity-1", status };
    transitions.push({ to: body.to, key });
    status = body.to;
    return { id: "identity-1", status };
  };
  let polls = 0;
  const item = { key: "edge", name: "edge.example", targetState: "deployed", connector: "envoy", daysAgo: 10 };
  await advanceIdentity(item, { id: "identity-1" }, 1, request, async () => { polls += 1; });
  assert.deepEqual(transitions.map((transition) => transition.to), ["issued", "deployed"]);
  assert.equal(new Set(transitions.map((transition) => transition.key)).size, 2);
  assert.equal(polls, 1);

  transitions.length = 0;
  await advanceIdentity(item, { id: "identity-1" }, 1, request, async () => { polls += 1; });
  assert.deepEqual(transitions, []);
  assert.equal(polls, 2);
});

test("AUD-66 identity convergence refuses an incompatible terminal state", async () => {
  const request = async () => ({ id: "identity-1", status: "revoked" });
  await assert.rejects(
    advanceIdentity(
      { key: "edge", name: "edge.example", targetState: "deployed", connector: "envoy", daysAgo: 10 },
      { id: "identity-1" },
      1,
      request,
      async () => {},
    ),
    /cannot converge it to deployed/,
  );
});

test("demo identity convergence accepts only the exact state that wins a transition race", async () => {
  let status = "issued";
  let transitionCalls = 0;
  const request = async (method) => {
    if (method === "GET") return { id: "identity-1", status };
    transitionCalls += 1;
    status = "deployed";
    throw new Error("POST transition returned 409: deployed -> deployed");
  };
  const result = await advanceIdentity(
    { key: "edge", name: "edge.example", targetState: "deployed", connector: "envoy", daysAgo: 10 },
    { id: "identity-1" },
    1,
    request,
    async () => {},
  );
  assert.equal(result.status, "deployed");
  assert.equal(transitionCalls, 1);
});

test("AUD-66 checkpoint digest is deterministic and binds manifest plus inventory", () => {
  const first = seedInventoryDigest({ owners: [{ id: "b" }, { id: "a" }], version: 1 });
  const same = seedInventoryDigest({ version: 1, owners: [{ id: "b" }, { id: "a" }] });
  const changed = seedInventoryDigest({ version: 1, owners: [{ id: "a" }, { id: "b" }] });
  assert.equal(first, same);
  assert.notEqual(first, changed);
  assert.equal(checkpointSource(first, changed), `demo-seed-v3:complete:${first}:${changed}`);
  assert.deepEqual(
    checkpointDisposition(`demo-seed-v3:complete:${first}:${changed}`, first),
    { kind: "current", inventoryDigest: changed },
  );
  assert.deepEqual(
    checkpointDisposition(`demo-seed-v2:complete:${first}:${changed}`, first),
    { kind: "migrate", previousVersion: "demo-seed-v2" },
  );
  assert.deepEqual(checkpointDisposition(`demo-seed-v4:complete:${first}:${changed}`, first), { kind: "conflict" });
  assert.deepEqual(checkpointDisposition(`demo-seed-v1:complete:not-a-digest:${changed}`, first), { kind: "conflict" });

  const firstObservation = stableSeedSemantics({
    discovery_sources: [{ config: { findings: [{ ref: "edge:443", metadata: { observed_at: "2025-01-01T00:00:00Z" } }] } }],
  });
  const retriedObservation = stableSeedSemantics({
    discovery_sources: [{ config: { findings: [{ ref: "edge:443", metadata: { observed_at: "2026-01-01T00:00:00Z" } }] } }],
  });
  assert.equal(seedInventoryDigest(firstObservation), seedInventoryDigest(retriedObservation));
});
