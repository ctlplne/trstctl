import assert from "node:assert/strict";
import test from "node:test";
import { verifiedDeliveryMatches } from "./delivery-selection.mjs";

test("retained renewal selects only the current verified transition receipt", () => {
  const expected = {
    targetName: "lab apache", connector: "apache", excludedID: "old-id",
    excludedFingerprint: "sha256:aa:bb", key: "host-renew:renew:transition:new-run",
  };
  const current = {
    id: "new-id", target: "lab apache", connector: "apache", status: "verified",
    fingerprint: "CC:DD", idempotency_key: "host-renew:renew:transition:new-run:verified",
  };
  assert.equal(verifiedDeliveryMatches(current, expected), true);
  assert.equal(verifiedDeliveryMatches({ ...current, idempotency_key: "host-renew:renew:transition:older-run:verified" }, expected), false);
  assert.equal(verifiedDeliveryMatches({ ...current, status: "delivered" }, expected), false);
  assert.equal(verifiedDeliveryMatches({ ...current, fingerprint: "aabb" }, expected), false);
  assert.equal(verifiedDeliveryMatches({ ...current, id: "old-id" }, expected), false);
  assert.equal(verifiedDeliveryMatches({ ...current, target: "other target" }, expected), false);
});
