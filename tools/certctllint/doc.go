// Package certctllint will provide the custom go/analysis linter that makes the
// architectural non-negotiables un-violable and is wired CI-blocking.
//
// It will enforce, at minimum: no crypto/* import outside internal/crypto
// (AN-3); no repository query missing a tenant_id filter (AN-1); no string-typed
// field or parameter in a key-handling package (AN-8); and an honored
// idempotency key on every mutating API handler (AN-5). The only sanctioned
// escape hatch is fixing a rule (with a test fixture), never a blanket ignore.
//
// This is deliberately a placeholder: the analyzers, their fixtures, and the CI
// wiring are the entire scope of sprint S0.2 and are intentionally NOT
// implemented here in S0.1.
package certctllint
