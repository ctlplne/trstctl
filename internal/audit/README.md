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

The authorized events API returns immutable records as `events` and optional
readable companions as `readable_events`; the CLI preserves both. The console
matches each companion by sequence and ID, distinguishes erased from unavailable
details, and keeps the encrypted source separate. Signed exports retain only the
immutable records. A standing collector receiver resolves details against the
exact queued source before network I/O. Its protected outbox records stay
ciphertext-only; the readable request carries a separate immutable source and
explicit hash scope. Unavailable or altered source fails without delivery.
Already queued records can finish after online retirement because their retained
source remains available; this creates no operator archive-download route.
Readable collector copies already sent follow the collector's retention policy.

Production event-key activation, ciphertext backup/snapshot/archive integration
and full restore remain required before the opt-in erasure feature is served.
The audit and HTTP tests use real NATS/file custody and local signing/authority
fixtures; they do not qualify production activation, PostgreSQL recovery or an
isolated signing process. Frontend and CLI checks exercise presentation and
transport contracts, not the complete offboarding journey.
