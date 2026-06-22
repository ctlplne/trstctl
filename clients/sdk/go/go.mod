// The trstctl Go SDK is its own module so importing it never drags the control
// plane's dependency graph (pgx, NATS, OPA, wazero, …) into an integrator's
// build, and so the server module's go.mod/go.sum stay untouched. It depends on
// the standard library only — no third-party packages — which keeps the supply
// chain of a credential-management client minimal and auditable.
module trstctl.com/sdk/go

go 1.26.0
