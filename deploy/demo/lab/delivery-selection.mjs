function fingerprint(value) {
  return String(value ?? "").replace(/^sha256:/i, "").replaceAll(":", "").toLowerCase();
}

// UUID-sorted history is not chronological. A retained lab must bind its
// successor proof to this transition, never to an older verified receipt.
export function verifiedDeliveryMatches(item, expected) {
  const current = fingerprint(item.fingerprint);
  return item.id !== expected.excludedID && item.target === expected.targetName &&
    item.connector === expected.connector && item.status === "verified" &&
    (!expected.key || item.idempotency_key === `${expected.key}:verified`) &&
    current !== "" && current !== fingerprint(expected.excludedFingerprint);
}
