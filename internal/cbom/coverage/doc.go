// SPDX-License-Identifier: MPL-2.0

// Package coverage computes cryptographic discovery coverage: which asset
// classes the deployment's discovery sources can observe, which of those have
// actually been observed by a completed, fresh run, and which classes no
// configured source can ever see. It turns the blind spots that previously
// existed only as prose comments (internal/discovery/cloudcert,
// internal/discovery/serviceaccount) into computed, queryable state — the
// system can say what it cannot see.
//
// # Which registry is authoritative for source kinds
//
// Three registries of discovery-source identity exist in this codebase: the
// credential-discovery Source interface (internal/discovery), the
// cryptographic-discovery Source interface (internal/cbom), and the served
// executor dispatch in internal/server keyed on store.DiscoverySource.Kind.
// The AUTHORITATIVE catalog is the served executor set — the kinds the server
// can actually execute when an operator queues a run — because coverage is a
// claim about what this deployment can do, not about which interfaces exist
// in the library. internal/server derives that set from its dispatch table
// (servedDiscoverySourceKinds) rather than a hand-typed list, and
// TestEveryDiscoverySourceDeclaresEnvelope welds this package's envelope
// registry to it in both directions: a served kind without an envelope and an
// envelope for an unserved kind both fail the build. The two Source
// interfaces remain what they are — per-connector implementation seams — and
// no fourth list is introduced.
//
// Classification is pure, clock-explicit data modelling: no crypto imports,
// no I/O, consistent with the package cbom stance. The persisted input (one
// per-source rollup row per tenant, see internal/store discovery_coverage) is
// an AN-2 projection of the existing discovery.source.upserted and
// discovery.run.completed events; freshness is applied at read time against
// the envelope's declared window, never baked into stored rows.
package coverage
