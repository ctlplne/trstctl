# Source-backed event protection

This package derives an opt-in key lifetime from retained registration, request,
activation, offboard and signed destruction records. A tenant rename keeps its
first registration identity; registration after offboarding starts a new lifetime.
SQL rows cannot select a different key or switch an active tenant to plaintext.
Exact historical duplicate identities keep the first sequence; the durable source
identity index refuses changed bodies, actors or ciphertext without opening keys.

`SourceAdmission` holds the tenant custody fence through append. A retained
request blocks ordinary writes until independently verified creation evidence is
activated. Closed activation and destruction controls stay readable so recovery
can find authority without first opening the key it is trying to locate.
`SourceKeys` opens the exact creation identity in that authority. Unknown custody,
unexplained key loss and a signed completion contradicted by current custody fail.
Only independently verified destruction gives the erased logical view.

These are integration components. Production startup does not yet attach the
preparation or offboard paths. Backup rows, audit archives, the destructive
worker and operator routes remain required. Component tests do not qualify
those production workflows.
The software custodian does not prove removal of host snapshots or copied keys.

Preparation now consumes an exact committed outbox invocation, resolves its
retained request under independent custody, creates only a never-activated key,
and independently reads creation evidence before public activation. An active
retry cannot provision missing historical custody. Activation projection settles
that command's old invocation holds only through the configured verifier: it
checks exact retained source and current creation under the custody file fence.
Missing proof retains the holds. Generic outbox status, leases and quiescence
rules stay unchanged. Production startup/routes still do not attach this path.

The optional offboard projection derives the exact destruction intent from its
retained lifetime without opening a key. In one SQL transaction it verifies the
ordinary erase and adds one public, control-plane-only pending outbox row. Its
attestation remains incomplete while that row exists. An exact retry inspects
that sole residue and preserves unresolved invocations; it never erases a new
registration or silently discards unexpected rows. Default-off offboarding keeps
its existing zero-row guarantee. The dedicated post-delete claim check verifies
the processing lease, attempt token, payload, effect lane and receiver role;
source, retention, legal holds and current custody still gate actual removal.

Read-only verification of an exact historical activation can finish after a
later offboard, while preparation still refuses that lifetime. Destruction never
becomes an activation-verification success. Historical receipt trust is explicit
through separately pinned public `VerificationKeys`; an embedded signer does not
grant itself trust. Only the existing allowlist for the reserved historical
Provider audit scope keeps its legacy behavior, under its mapped UUID fence.
Unknown scope, event type or control schema still refuses.
