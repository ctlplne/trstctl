# Protected source bytes and independent key custody

This package supplies protected source bytes and independent tenant-key custody.
The configured runtime attaches source admission/readers before opening history
and uses bounded preparation/destruction workers. Public activation, interrupted
startup recovery and complete erasure-aware artifact restore remain unserved;
component tests do not establish the full opt-in workflow.

The optional `internal/events.WithEventProtection` seam now preserves ciphertext
in stored envelopes, identity indexes and exact history transfers, while opening
logical reads. Its admission adapter must serialize activation, append and
destruction for a tenant and verify retained lifecycle authority. Protected
retries recover the original ciphertext beyond the broker's duplicate window.
Missing custody fails; a verified destroyed key produces an explicit erased view.
Complete erasure-aware projection rebuild and restore remain required.

Tenant lifecycle metadata can now be read without opening a payload or actor.
Its tenant/type index checks each selected pointer against the retained source
digest and scope, keeps source order and pins the history generation. The new
index format rebuilds from source on upgrade; it does not rewrite event bytes.
This metadata is routing evidence, not authentication of an encrypted body.
PostgreSQL custody locks now share the tenant admission fence, so nested key
use borrows one live grant rather than taking a second pool connection. Grants
are scoped to the same store and tenant, expire with the callback and still
honor cancellation. Production activation and destruction must use this fence.
Service, issuance and projection scopes now share their already-held PostgreSQL
session with custody. This preserves a one-connection lock budget through nested
operations instead of waiting for a second connection held by the same work.
Foreign, expired and concurrent projection-session use refuses promptly.

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

An active key must open a sealed probe containing a fixed public value. That
probe binds its reference, creation time and record format. Replacement key
bytes therefore fail before a callback can use them. Activation must retain
`CreationEvidence` and use `WithVerifiedKey` to compare the local identity with
that immutable evidence. The private key-record format is version 2; earlier
unshipped draft records are refused.

Destruction requires a `DestructionAuthorizer` and an audit-evidence signing
capability. The production authorizer must verify the exact retained offboard
event, applicable retention policy and committed outbox command. The assembled
receivers enforce that authority through the actual durable claim and private
grants. Production signatures use the existing isolated signer; tests may use
an in-memory signing fixture.

The signed request includes the registration identity, activation ID/sequence
and creation-evidence digest. Restoring an older data cut must still reconcile
that lifetime's destruction rather than resurrect it or erase a newer lifetime.

`DestructionReceipt` reads the current custodian's signed evidence without
repeating the removal or its source/outbox authorization. It requires verified
key absence; unexplained loss or reintroduced material refuses. Pinned public
`VerificationKeys` preserve receipt verification after audit-signer rotation and
let a restore process read that evidence without a signing capability. A restore
must receive that public trust separately; keys inside a receipt are not trust.
`LoadVerificationKeysFile` reads a bounded operator-pinned public JWKS file outside
managed restore paths. The runtime attaches it before copying admission/read
policies or opening custody. A configured invalid file refuses explicitly.

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

Custody callbacks also hold a per-tenant operating-system file lock in the
independent directory. It remains held if the PostgreSQL session disappears,
and releases only after nested key callbacks finish. Lock inodes are retained;
unlinking them would allow overlapping lock generations. A fence-only callback
can verify source/current custody and join its SQL result without retaining key
bytes. Its private authority/tenant grant expires on return and refuses concurrent
borrows. Native session-loss/close/cancellation tests run on macOS; Windows amd64
and Linux arm64 locking paths have compile-only checks until native qualification.
Independent host snapshots and copied keys remain outside physical-erasure proof.
