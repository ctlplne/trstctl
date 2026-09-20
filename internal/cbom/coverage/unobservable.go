// SPDX-License-Identifier: BUSL-1.1

package coverage

// UnobservableClass is an asset class no configured source can ever observe,
// with the stated reason. These are the honest edges of the product: each
// entry names a class and says plainly that no served source covers it,
// instead of leaving the admission buried in prose comments. Adding a served
// source that covers one of these means removing it here in the same change —
// the classification golden test pins the set.
type UnobservableClass struct {
	Class  AssetClass
	Reason string
}

// StructurallyUnobservable enumerates the classes outside every served
// envelope. Sources: the standing non-goals (no firmware scanner, no passive
// capture, no SAST), the two in-tree blind-spot admissions
// (internal/discovery/cloudcert, internal/discovery/serviceaccount), and the
// unbuilt workstreams of the CBOM coverage card (vendor CBOM ingest,
// data-at-rest posture, dormant KMIP enumeration).
func StructurallyUnobservable() []UnobservableClass {
	return []UnobservableClass{
		{Class: "firmware-embedded-crypto",
			Reason: "no source inspects device firmware; vendor-published CBOM ingest is not built, and a firmware scanner is a standing non-goal"},
		{Class: "vendor-embedded-crypto",
			Reason: "cryptography inside third-party appliances and products is invisible to every served source; vendor CBOM ingest (WS-3) is not built"},
		{Class: "data-at-rest-posture",
			Reason: "volume, database, and KMS at-rest encryption state is invisible to network or API observation; the agent posture source (WS-4) is not built"},
		{Class: "unroutable-segment",
			Reason: "workloads scans cannot reach and where no agent runs are invisible — the cloudcert blind-spot admission generalized: reachability is a precondition of every active source"},
		{Class: "directory-unlinked-account",
			Reason: "a served one-sided source cannot claim AD or cloud directory category coverage from only one side (the serviceaccount admission); accounts visible only in an unconnected directory are not observed"},
		{Class: "passive-wire-traffic",
			Reason: "trstctl probes actively and never captures traffic; taps, span ports, and inline appliances are a deliberate non-goal"},
		{Class: "dormant-kmip-object",
			Reason: "KMIP-managed objects not presently in use are not enumerated (WS-5 not built); traffic- and use-based observation cannot see them by construction"},
	}
}
