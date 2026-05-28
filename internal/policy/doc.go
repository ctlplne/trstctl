// Package policy embeds the OPA/Rego policy engine that gates issuance,
// deployment, and revocation.
//
// It runs inside its own bulkhead (AN-7) so policy evaluation cannot starve
// other subsystems, and it is exercised by property-based tests.
//
// Implementation matures in sprint S8.7; this file reserves the package.
package policy
