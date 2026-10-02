import assert from "node:assert/strict";
import test from "node:test";
import { validateRetainedBinding } from "./retained-binding.mjs";

const identity = {
  kind: "x509_certificate", status: "deployed", owner_id: "owner-a",
  attributes: {
    issuing_authority_source: "external", issuing_authority_id: "local-pebble",
    deployment_connector: "apache", deployment_target_id: "target-a", deployment_target: "lab apache",
  },
};
const target = {
  id: "target-a", name: "lab apache", connector: "apache", enabled: true,
  config: {
    executor: "agent", required_agent_role: "host", required_agent_id: "agent-a",
    cert_path: "/lab/tls/apache.crt", key_path: "/lab/tls/apache.key",
    verify_address: "127.0.0.1:10443", verify_server_name: "apache.partner-lab.example.com",
  },
};
const expected = { owner: "owner-a", connector: "apache", config: target.config };

test("retained lab binding accepts only the exact deployed target", () => {
  assert.doesNotThrow(() => validateRetainedBinding(identity, target, expected));
  for (const [field, value] of [["owner", "owner-b"], ["connector", "nginx"]]) {
    assert.throws(() => validateRetainedBinding(identity, target, { ...expected, [field]: value }));
  }
  for (const [field, value] of [["status", "revoked"], ["owner_id", "owner-b"]]) {
    assert.throws(() => validateRetainedBinding({ ...identity, [field]: value }, target, expected));
  }
  for (const [field, value] of [["issuing_authority_id", "other-ca"], ["deployment_target_id", "other-target"]]) {
    assert.throws(() => validateRetainedBinding({ ...identity, attributes: { ...identity.attributes, [field]: value } }, target, expected));
  }
  for (const [field, value] of [["required_agent_id", "agent-b"], ["cert_path", "/other.crt"],
    ["verify_address", "127.0.0.1:19999"]]) {
    assert.throws(() => validateRetainedBinding(identity, { ...target, config: { ...target.config, [field]: value } }, expected));
  }
  assert.throws(() => validateRetainedBinding(identity, { ...target, enabled: false }, expected));
});
