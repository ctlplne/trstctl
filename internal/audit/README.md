# Signed records and readable event details

A protected source event has two views. Its audit Record contains the unchanged
ciphertext envelope and source schema, with no readable actor or payload. Hashes,
signed bundles and managed archives use this stable record. Removing the tenant
key leaves those bytes and offline verification intact.

Callers authorize the tenant audit query before requesting readable details.
SearchReadableView returns those details separately from the signed Record. Both views come from one history read and the same privacy,
tenant, content and limit filters. Match details by tenant-local sequence and
source ID. After independently verified key destruction, the readable view marks
the fields erased and returns no actor or payload. It never enters Bundle.
Legacy plaintext records retain their existing representation and redaction.

These service components do not yet expose protected readable details through
the operator API, CLI or console. Production event-key activation, ciphertext
backup/snapshot/archive integration and full restore remain required before the
opt-in erasure feature is served. The audit tests use real NATS/file custody and
a local signing/authority fixture; they do not qualify production authorization,
PostgreSQL recovery or an isolated signing process.
