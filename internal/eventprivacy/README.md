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
preparation or offboard paths. Backup rows, audit archives, production worker
assembly and operator routes remain required. Component tests do not qualify
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

An old lifetime can finish destruction after the tenant UUID is registered and
activated again. The finite source fold routes a pinned signed receipt to its
exact historical key and publishes lifetime results only after the full cut is
verified. Completion admission checks tenant scope before historical lookup and
refuses a different second completion identity before append. An exact retry
keeps its first sequence. The new lifetime keeps its own key and readable data;
neither lifetime's stored ciphertext is rewritten.

Retained hold checks replay only the exact registration-to-offboard source cut,
not SQL hold rows removed by offboarding. Pending, release-pending and failed
archive holds block removal until a fresh release request has a verified released
outcome. Report holds block as well. Neighbor and later-registration holds cannot
change the old cut. Duplicate or unknown JSON members do not grant clearance.

Before a new protected offboard is admitted, the same source check keeps a held
tenant live so its normal permissioned release path stays usable. A closed public
`holds_cleared` fact binds the complete exact destruction request and immutable
old cut. Initial admission independently verifies retained holds; an exact retry
can reuse that fact after key removal makes private hold bodies unreadable. This
fact alone grants no removal, elapsed-retention claim or completed erasure. The
production worker, artifacts, restore and operator feature remain unserved.

Preparation rechecks its committed lease after waiting for independent custody,
before creating a key. The destruction receiver checks its exact committed
invocation and historical source, retains hold clearance before removal, waits
for the real retention deadline, then removes only that lifetime's key. Private
grants expire with their callbacks and bind the complete request or public event.
The assembled orchestrator recorder rechecks SQL authority for post-offboard
controls; a matching event type alone cannot bypass ordinary service admission.

Completion settlement requires the exact retained event identity, sequence,
time and signed receipt, plus matching current independent absence. Tenant UUID
aliases resolve to the same scope. Only the matching command's invocation holds
clear; generic delivery state and leases still finalize normally. Cleanup removes
only that exact delivered, settled row. Component tests cover interruption after
removal, signing/publication failure, SQL rollback, lease expiry and a later
registration's preserved key and rows. They use real PostgreSQL/NATS/file custody
and a local signing transport fixture. Production startup, the isolated signer
journey, operator routes and authenticated backup/restore remain required.

A restored event-history copy can retain the offboard while missing the later
hold clearance and completion. When current independent custody already proves
signed destruction, the receiver rechecks its exact committed claim, historical
lifetime, signature and current absence under the same fences. It records the
existing completion outside those callbacks. This recovery needs only public
receipt trust from the custodian and performs no removal or signing. It leaves
the old source bytes exact and creates no replacement hold-clearance fact.
The raw-history recovery test does not qualify a full authenticated backup or
SQL/snapshot restore; those integrations remain required before this is served.
