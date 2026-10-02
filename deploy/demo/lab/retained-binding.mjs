// A persisted lab binding is reusable only when it still points at the exact
// actor, issuer, agent, and listener paths that the operator intended.
export function validateRetainedBinding(identity, bindingTarget, expected) {
  const attributes = identity.attributes ?? {};
  if (identity.kind !== "x509_certificate" || identity.status !== "deployed" ||
      identity.owner_id !== expected.owner || attributes.issuing_authority_source !== "external" ||
      attributes.issuing_authority_id !== "local-pebble" ||
      attributes.deployment_connector !== expected.connector || !attributes.deployment_target_id) {
    throw new Error(`${expected.connector} retained identity does not match the expected deployed owner, issuer, and connector`);
  }
  if (bindingTarget.id !== attributes.deployment_target_id ||
      bindingTarget.name !== attributes.deployment_target ||
      bindingTarget.connector !== expected.connector || !bindingTarget.enabled ||
      Object.entries(expected.config).some(([key, value]) => bindingTarget.config?.[key] !== value)) {
    throw new Error(`${expected.connector} retained target does not match the expected agent, paths, or verifier configuration`);
  }
}
