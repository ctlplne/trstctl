// SPDX-License-Identifier: MPL-2.0

// Package graph models the inventory as a queryable credential graph of
// workloads, identities, credentials, resources, and connections (F21).
//
// It is the substrate for blast-radius analysis, attestation chains, and risk
// scoring, and answers both REST and Cypher-style queries. Build projects one
// tenant's store rows into an in-memory Graph, BlastRadius returns the full
// forward-reachable set from a compromised node grouped by kind, and the Cypher
// subset in cypher.go answers those same questions as text queries.
package graph
