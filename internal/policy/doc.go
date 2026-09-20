// SPDX-License-Identifier: BUSL-1.1

// Package policy embeds the OPA/Rego policy engine that gates issuance,
// deployment, and revocation.
//
// It runs inside its own bulkhead (AN-7) so policy evaluation cannot starve
// other subsystems, and it is exercised by property-based tests.
//
// Engine evaluates the compiled lifecycle modules, ABACEngine evaluates the
// attribute-based access rules, LiveEngine lets a served activation workflow
// replace the compiled module without restarting the process, and DryRun
// compiles and evaluates a candidate module without touching live enforcement.
package policy
