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

These are integration components. Production startup, the preparation receiver,
offboarding destruction intents, backup rows, audit archives and operator routes
are not attached here yet. The component tests do not qualify those workflows.
The software custodian does not prove removal of host snapshots or copied keys.
