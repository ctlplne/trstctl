// SPDX-License-Identifier: BUSL-1.1

// Package verify is the proprietary, OFFLINE relying-party verifier for AGID
// agent credentials (patent independent AGID-claim-28, dependent AGID-claim-29, and the
// short-TTL / offline-validity half of AGID-claim-7; establishing the relying-party
// half of INV-A7). A relying party receives an AGID credential a caller presents
// (the caller supplies the credential and the action it wants to take -- this
// package fetches NOTHING) and decides, WITHOUT any network access and WITHOUT
// any control-plane query, whether to honor a requested action:
//
//  1. It verifies the credential's SIGNATURE against a caller-supplied TRUST ROOT
//     across the three interchangeable carriage forms (X.509 non-critical
//     extension, workload-identity document, signed token) -- reusing the AGID-08
//     decoders (internal/agentid/delegation/carriage) and the core internal/crypto AN-3
//     boundary. No network fetch of a JWKS, a CRL, an OCSP responder, or a
//     control-plane status endpoint occurs; the verify path constructs NO network
//     client at all (asserted by TestCredential_ShortTTLNoStatusQuery).
//
//  2. It compares the bound AGENT-STACK REPRESENTATION against the relying party's
//     LOCAL POLICY -- an approved set of agent-stack representation digests (a
//     prompt/tool/model digest set) -- and REFUSES on mismatch (AGID-claim-28).
//
//  3. It REFUSES a requested action that EXCEEDS the authority indication bound in
//     the credential OR falls OUTSIDE the task scope corresponding to the bound
//     task-envelope digest -- enforcing task binding even when the broader
//     authority set would permit the action (AGID-claim-28).
//
//  4. It REFUSES a requested action whose TOOL is absent from the TOOL MANIFEST
//     whose digest is bound in the agent-stack representation (AGID-claim-29): the
//     relying party confines the agent to exactly the bound tool subset.
//
//  5. It determines a short-TTL credential's validity from the CREDENTIAL ALONE
//     (AGID-claim-7, relying-party side): expiry/not-yet-valid is decided from bound
//     validity bounds and the caller's clock, with NO query for a credential's revocation state.
//
// FAIL-CLOSED is the spine. An unverifiable signature, an out-of-policy agent
// stack, an over-authority or out-of-task-scope action, a tool absent from the
// bound manifest, or an expired/not-yet-valid credential all REFUSE the action
// with a typed error a caller matches with errors.Is. Verify never returns "allow"
// on any doubt.
//
// BOUNDED GUARANTEE (spec note 1.5(a)). Binding the agent-stack
// representation proves WHAT CONSTITUTION HELD THE KEY AT ISSUANCE, not that the
// running agent still matches that constitution at request time. Drift between
// issuance and use is BOUNDED by the credential's short TTL (INV-A7), not
// eliminated. This package therefore does NOT, and its documentation must NOT,
// claim to "guarantee the agent's current prompt"; it proves the issuance-time
// binding and confines the agent to the bound subset for the credential's short
// lifetime.
//
// DEPENDENCY-LIGHT / WASM. The verifier is deliberately small and links only the
// AGID-08 carriage decoders, the AGID-05 task-envelope model, and the core
// internal/crypto AN-3 boundary -- all of which build for GOOS=js GOARCH=wasm.
// It does NOT import internal/agentid/agentstack (which pulls internal/attest and, in
// native builds, database/sql): the carriage forms carry the agent-stack
// representation as OPAQUE CANONICAL BYTES, and this package recovers the bound
// prompt/tool/model digests from those bytes with a tiny, allocation-bounded,
// panic-free decoder (agentstack_repr.go) that mirrors the AGID-03 canonical
// framing. A WASM build target for external relying parties lives in
// ./wasm (build tag js), and native/WASM result parity is asserted by
// TestRPVerify_WASMParity.
//
// AN-3: every hash and every signature routes through internal/crypto; this
// package names no crypto/* package. Structural decoding of the opaque
// agent-stack representation (encoding/binary) is canonical framing, not a crypto
// primitive, and matches the discipline the carriage and agentstack packages use.
//
// LICENSE (decision recorded 2026-07-07): this
// package is proprietary LicenseRef-trstctl-EE so NO MPL patent grant attaches to
// independent AGID-claim-28 (or dependent 29). It is deliberately NOT in MPL core and
// is NOT the internal/license offline license checker (a different thing the AN-9
// editions boundary keeps in MPL core). The same ISARA / audit-N-8 grant trap PCAS-07 / XREC-12 /
// GRCA-04 guard applies: shipping this in core would grant AGID-claim-28 away under
// MPL 2.1.
//
// EXCLUDES (this is offline relying-party verification ONLY). No control-plane
// logic -- no minting, no in-signer chain verification, no delegation-chain
// verification inside a signer (that is AGID-04, and the license scope excludes
// it). No network fetching (the caller supplies the credential and the presented
// action). No cascade / revocation evidence (AGID-10/11). No carriage ENCODING
// (AGID-08 provides the encoders; this consumes only the decode side).
//
// DEFERRED / EXTERNAL-CONSUMER TIER (AGID-INT-CALL reachability gate). This package
// is, BY DESIGN, an EXTERNAL relying-party SDK (Go + WASM for third parties). It is
// consumed OUTSIDE this repository -- by a relying party's own service or a browser
// WASM bundle -- and therefore legitimately has NO in-repo control-plane caller on
// the cmd/trstctl attach -> internal/agentid/api -> internal/agentid/orchestrator path. That is
// not a wiring gap: a control-plane "caller" for an offline third-party verifier
// would be a contrived, meaningless invocation, so none is invented. This mirrors the
// PCAS gate's DEFERRED tier (the offline PCAS-07 relying-party verifier is consumed by
// external relying parties, not driven from the control-plane binary). The
// AGID-INT-CALL production-caller gate therefore treats internal/agentid/verify (and its
// ./wasm build) as an ALLOWED EXCEPTION: its reachability is the published SDK and its
// conformance vectors (internal/agentid/verify/vectors.go, sample.go), not a cmd/trstctl
// call path. Every OTHER previously test-only AGID mechanism (reach.NewEngine, the
// cascade/terminal constructors, the ceiling/directive-reader/tool-set constructors)
// DOES gain a non-test control-plane caller on the attach path; only /verify is
// deferred, and only because its consumer is external by construction.
package verify
