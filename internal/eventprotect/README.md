# Protected source bytes and independent key custody

This package is A233 groundwork. The running product does not yet attach it to
event append, offboarding, projection rebuild, backups, snapshots or WORM audit
archives. Its component tests do not establish those workflows.

The optional `internal/events.WithEventProtection` seam now preserves ciphertext
in stored envelopes, identity indexes and exact history transfers, while opening
logical reads. Its admission adapter must serialize activation, append and
destruction for a tenant and verify retained lifecycle authority. Protected
retries recover the original ciphertext beyond the broker's duplicate window.
Missing custody fails; a verified destroyed key produces an explicit erased view.
Projection handling of that view and production admission are still to be built.

`Protect` encrypts the original payload bytes and a separately encoded actor
using `internal/crypto/seal`. It binds the tenant, source ID, event type, schema,
time, storage purpose, key reference and privacy-policy digest. `Open` requires
the same bindings. Parsing and re-encoding a domain payload would change some
immutable command bindings, so the codec preserves its exact bytes.

`FileAuthority` holds tenant keys in a private directory outside the configured
ordinary backup roots. It rejects lexical overlaps, symlink aliases and
filesystem aliases such as case variants. `WithKey` loads a locked key handle
for one callback and destroys that handle before returning. Every authority
user must share the same cross-replica `KeyLocker`; `store.Store` supplies a
bounded PostgreSQL implementation. A missing active key never regenerates.

Destruction requires a `DestructionAuthorizer` and an audit-evidence signing
capability. The production authorizer must verify the exact retained offboard
event, applicable retention policy and committed outbox command. That adapter
is still to be built. Production signatures must use the existing isolated
signer; tests may use an in-memory signing fixture.

The authority writes a durable removal intent before deleting the key. It
syncs the tenant directory, reads back absence, records the removal time, then
signs that complete evidence under its own artifact domain. A retry after
signer failure resumes the journal. Completed retries return the first signed
receipt. `ErrDestroyed` requires a verified receipt and observed key absence;
unexplained loss or unsigned removal returns a custody error instead.

This backend proves logical removal from its configured software custody. It
cannot sanitize independently retained key copies, host snapshots, physical
media or plaintext already exported elsewhere. Ordinary data restore must use
the current independent custodian, and must never restore an old key copy or
fall back to a deployment key. Native Windows, network-filesystem and multiple
host behavior have not been qualified by these Mac tests.
