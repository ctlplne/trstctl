# Protected source bytes and independent key custody

This package supplies protected source bytes and independent tenant-key custody.
The configured runtime attaches source admission/readers before opening history
and uses bounded preparation/destruction workers. Public activation, protected
snapshot/archive integration and the complete operator workflow remain unserved;
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
receipt. The delivery cleanup sweep separately verifies that retained completion
and current absence before deleting a finalized operational intent. It grants no
new removal or signing authority and leaves immutable source records intact. `ErrDestroyed` requires a verified receipt and observed key absence;
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

Configured full-source reconstruction uses `eventprivacy.ErasurePlanner` to match
retained lifetime coordinates to the original signed current removal. Its finite
plan expires on callback return and rechecks current absence under one custody
fence per omission. Core and optional projection preflights use that view; raw
source, audit commitments and backup record counts do not. An activation-containing
older source cut may omit a later-erased lifetime without inventing its offboard
event. Pre-feature plaintext remains unchanged.

Warm catch-up installs the same finite view before preflight and extension replay.
The infinite tail instead verifies each message's exact retained metadata and
one finite tenant lifetime against current signed absence. It caches no erasure
grant and retains no additional history or custody fence for the worker's lifetime.
Ordinary Apply and checkpoint SQL run after the additional decision callback
releases its locks. The served driver's existing bounded pool and retry loop remain
unchanged. Local controls cover active and erased keys; full backup/snapshot and
isolated process restoration still need their own proof.

`PendingDestruction` is a read-only journal probe against exact retained creation.
It works without a signer or removal authority, changes no files and never reports
pending removal as verified erasure. Active missing material, foreign creation or
material present after recorded removal refuses. Normal configured startup uses
this identity only to select recovery through the original committed outbox
receiver. Exact backup bindings are checked before recovery, sanitation follows
it, and current-custody proof still gates readiness. The source checkpoint stays
unchanged until ordinary ordered catch-up. Raw restore construction never runs
this recovery hook before its authenticated source is resumed.

`LookupKeyState` is a bounded read of one exact reference. No record and no
material means never enabled; orphaned material or unexplained loss is an error.
Active, preparing and interrupted states cannot assert erasure. Completed state
returns original signed absence and public creation identity without signing or
removal authority. The source layer binds them to the deterministic FIRST source
registration for a cut predating activation. Admission and reconstruction share
that floor; growing another tenant's restored branch does not change the identity.
No legacy plaintext bytes become cryptographically erased, and no historical
activation/offboard or key is invented. Current independent custody remains a
required external-to-backup input.

Full backups now retain protected event history in format 3, preserving original
Stored bytes/schema/ciphertext with no readable mirror. Plaintext-only history
keeps format 2, and readers retain v1/v2 compatibility. Configured SQL export uses
format 2 and ScopePostgresRow; it authenticates artifact/cut/ordinal/table/logical
owner/storage owner and closed recovery metadata. Whole-artifact verification and
ownership checks precede the restore-only custody factory and every SQL effect.
Original counts survive; actual applied/omitted/redacted rows are separate.
Current original custody governs an old cut, including legacy pre-activation SQL.
A signer claim keeps only its retired denial digest after verified erasure.
Native tests use fresh PostgreSQL databases, real source/worker removal and the
shipped CA/audit signer child in Mac evaluation mode. Manifest keys and opt-in
requests are explicit fixtures, not a complete public/operator or Linux proof.

A restored activation-containing cut may grow along another tenant's branch past
the original offboard ordinal. The existing receipt-only ordinal guard remains;
read-side omission at that point requires independent current lookup of the exact
source creation, identical signed removal and material absence. Plan, tail and
SQL paths share this check under the existing custody fence. It proves a current
erasure floor, not original offboard retention or authenticated source lineage.
Native isolated full restore continues through catch-up, rebuild and live tail;
current-custody readiness and neighboring SQL remain intact. Missing/pending or
changed current identity/receipt/trust still refuses. Public controls, snapshot/
archive integration and the complete operator workflow remain pending.
