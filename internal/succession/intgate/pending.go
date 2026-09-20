// SPDX-License-Identifier: BUSL-1.1

package intgate

// PendingWiring is the RATCHET: the exported internal/succession constructors that the
// enumeration finds test-only TODAY. It is deliberately NOT the hand-written mechanism
// list this gate replaces, and it behaves in the opposite direction:
//
//   - The old scripts/pcas_prod_caller_gate.sh REQUIRED array had to be extended by
//     hand for a new mechanism to be checked at all, so anything nobody remembered to
//     add was simply invisible. Here the constructor set comes from the AST, so a NEW
//     exported constructor is checked immediately and FAILS the floor unless it is
//     wired or consciously listed here.
//
//   - Every entry is a live, observed gap, and it can only be removed, never
//     "satisfied": TestPendingWiring_NoStaleEntry FAILS as soon as a listed constructor
//     acquires a production caller, forcing the entry out. The list therefore shrinks
//     monotonically toward empty and cannot silently absorb a regression.
//
// Each Gap records what the scan actually observed, so the next reader does not have to
// re-derive it. Wiring these is mechanism-owner work on the owning PCAS card, not work
// for this package -- intgate asserts, it does not wire.
type PendingEntry struct {
	Pkg  string
	Name string
	File string
	Gap  string
}

// Qualified renders "pkgbase.Name", matching Constructor.Qualified.
func (p PendingEntry) Qualified() string {
	return lastPathSegment(p.Pkg) + "." + p.Name
}

var PendingWiring = []PendingEntry{
	{
		Pkg: "internal/succession/agent", Name: "NewRemoteCoSigner",
		File: "internal/succession/agent/transport.go",
		Gap:  "gRPC co-signer CLIENT side. cmd/trstctl-agent/cosign_attach.go wires the SERVER (agent.NewCoSignServer); the only caller of the client constructor is internal/succession/agent/transport_test.go.",
	},
	{
		Pkg: "internal/succession/minter", Name: "NewDurableSignedTokenAuthorizer",
		File: "internal/succession/minter/minter.go",
		Gap:  "durable dual-control authorizer; sole caller is internal/succession/minter/spentstore_test.go.",
	},
	{
		Pkg: "internal/succession/minter", Name: "NewHighWater",
		File: "internal/succession/minter/highwater.go",
		Gap:  "monotonic high-water floor; sole caller is internal/succession/minter/highwater_test.go.",
	},
	{
		Pkg: "internal/succession/minter", Name: "NewHistoryFloorStore",
		File: "internal/succession/minter/floor_history.go",
		Gap:  "counter-free history floor store; sole caller is internal/succession/minter/floor_history_test.go.",
	},
	{
		Pkg: "internal/succession/minter", Name: "NewSignedTokenAuthorizer",
		File: "internal/succession/minter/minter.go",
		Gap:  "in-memory dual-control authorizer; callers are internal/succession/minter/minter_test.go and evidence_test.go.",
	},
	{
		Pkg: "internal/succession/minter", Name: "NewSoftHSM",
		File: "internal/succession/minter/hsm.go",
		Gap:  "soft-HSM key custodian; callers are internal/succession/minter/hsm_test.go and internal/succession/conformance/e2e_test.go.",
	},
	{
		Pkg: "internal/succession/policy", Name: "NewMemDecisionLedger",
		File: "internal/succession/policy/verifier.go",
		Gap:  "in-memory decision ledger; sole caller is internal/succession/policy/provenance_test.go.",
	},
	{
		Pkg: "internal/succession/rewrap", Name: "NewLedger",
		File: "internal/succession/rewrap/rewrap.go",
		Gap:  "rewrap ledger; sole caller is internal/succession/rewrap/rewrap_test.go.",
	},
	{
		Pkg: "internal/succession/rewrap", Name: "NewMemProgress",
		File: "internal/succession/rewrap/rewrap.go",
		Gap:  "rewrap progress store; sole caller is internal/succession/rewrap/rewrap_test.go.",
	},
	{
		Pkg: "internal/succession/rewrap", Name: "NewRunner",
		File: "internal/succession/rewrap/rewrap.go",
		Gap:  "rewrap runner; sole caller is internal/succession/rewrap/rewrap_test.go. No shipped binary drives a rewrap pass.",
	},
	{
		Pkg: "internal/succession", Name: "NewGenesis",
		File: "internal/succession/epoch.go",
		Gap:  "genesis epoch-0 identity constructor; sole caller is internal/succession/epoch_test.go.",
	},
}

// isPending reports whether (pkg, name) is a recorded, still-open wiring gap.
func isPending(pkg, name string) bool {
	for _, p := range PendingWiring {
		if p.Pkg == pkg && p.Name == name {
			return true
		}
	}
	return false
}
