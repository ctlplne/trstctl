// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

// This file is the single source of truth for the AGID-INT-CALL gate: the in-scope
// packages, the DEFERRED allow-list, the sanctioned production seams, and the tier of
// every exported ee/agentid constructor. The floor check enumerates the live AST and
// cross-checks it against Inventory (TestConstructorInventory_MatchesSource), so a NEW
// exported constructor added without either wiring it or classifying it here fails the
// drift guard. Adding a package to the family means extending InScopePackages and, if
// its constructor is intentionally external-consumer-only, DeferredPackages.

// modulePath is the Go module path; import paths below are module-relative.
const modulePath = "trstctl.com/trstctl"

// InScopePackages is the AGID family's package set whose exported constructors this
// gate governs, expressed as import paths relative to the module root. It mirrors the
// AGID-INT-CALL card's enumeration (ee/agentid + delegation (+ store, carriage,
// brokerstore) + agentstack + taskenv + reach (+ engine) + revoke + verify + api +
// orchestrator). A package with no exported constructor (e.g. carriage, taskenv today)
// is still listed so the floor NOTICES if one later grows a constructor.
var InScopePackages = []string{
	"ee/agentid",
	"ee/agentid/agentstack",
	"ee/agentid/api",
	"ee/agentid/orchestrator",
	"ee/agentid/delegation",
	"ee/agentid/delegation/store",
	"ee/agentid/delegation/carriage",
	"ee/agentid/delegation/brokerstore",
	"ee/agentid/reach",
	"ee/agentid/reach/engine",
	"ee/agentid/revoke",
	"ee/agentid/taskenv",
	"ee/agentid/verify",
}

// DeferredPackages is the allow-list: in-scope packages whose exported constructors are
// EXEMPT from the "must have a non-test caller / must be RTA-reachable" bar because
// they are external-consumer-only by construction. ee/agentid/verify (and its ./wasm
// build) is the proprietary OFFLINE relying-party verifier SDK (claim 28) consumed
// OUTSIDE this repo; a control-plane caller would be a contrived, meaningless
// invocation. This mirrors the PCAS gate's DEFERRED tier (the offline PCAS-07 verifier
// is likewise external-consumer-only). Rationale: ee/agentid/verify/doc.go.
//
// A package is deferred by import-path PREFIX so ee/agentid/verify/wasm is covered too.
var DeferredPackages = []string{
	"ee/agentid/verify",
}

// DeferredSymbols is the SYMBOL-level DEFERRED allow-list: individual exported
// constructors that are external-consumer-only even though their PACKAGE is not wholly
// deferred (the package also holds REQUIRED, control-plane-wired mechanism
// constructors). Keyed by "pkg\x00Name".
//
// ee/agentid/agentstack.New is the AGID-03 agent-stack representation BUILDER: it
// ingests a RAW, secret-class system prompt into an internal/crypto locked buffer,
// digests it (AN-3), and returns the canonical Representation. By construction its
// caller is the party that HOLDS THE PROMPT -- the AGENT OPERATOR / ISSUER, outside this
// repo -- who then submits only the OPAQUE canonical bytes. The control plane MUST NOT
// call it: (a) AN-8 forbids the control plane ever holding the raw plaintext prompt, so
// a cmd/trstctl caller would be an architectural violation, not a wiring fix; and (b)
// AN-4 keeps the in-signer gate from even linking the agentstack package (it verifies
// the representation from opaque bytes, see ee/agentid/delegation/subject.go). Its only
// non-agentstack-test consumer today is the DEFERRED ee/agentid/verify package's
// differential test -- i.e. the external RP SDK's own conformance. It is therefore in
// the SAME external-consumer tier as verify, deferred for the same reason and flagged as
// such. The package's MECHANISM constructors that the control plane genuinely drives
// (NewToolManifest / NewRegisteredToolSet, compared via agentstack.Compare in the
// orchestrator issuance worker) stay REQUIRED and are wired.
//
// NOTE for reviewers: this is a symbol-level extension of the card's DEFERRED tier
// beyond ee/agentid/verify. It is justified by the AN-8/AN-4 boundary (a control-plane
// caller would be an AN-8 violation) and by the fact that the representation BUILDER is
// issuer-side by design, exactly as the card exempts the RP-side verifier. If a future
// card wires an issuer flow through the control plane that legitimately builds a
// Representation, PROMOTE this to TierRequired.
var DeferredSymbols = map[string]bool{
	"ee/agentid/agentstack\x00New": true,
}

// isDeferredPkg reports whether importPath (module-relative) is on the DEFERRED
// package allow-list, matching by prefix so subpackages (e.g. .../verify/wasm) are
// covered.
func isDeferredPkg(importPath string) bool {
	for _, d := range DeferredPackages {
		if importPath == d || hasPathPrefix(importPath, d) {
			return true
		}
	}
	return false
}

// isDeferred reports whether the constructor (pkg, name) is DEFERRED (exempt from the
// caller/reachability bar) -- either because its whole package is deferred (the verify
// RP SDK) or because the specific symbol is symbol-level deferred (agentstack.New, the
// issuer-side representation builder).
func isDeferred(pkg, name string) bool {
	if isDeferredPkg(pkg) {
		return true
	}
	return DeferredSymbols[pkg+"\x00"+name]
}

// hasPathPrefix reports whether p is prefix or a subpackage path of prefix (prefix +
// "/..."). It is a plain string check on the '/'-delimited import path.
func hasPathPrefix(p, prefix string) bool {
	return len(p) > len(prefix) && p[:len(prefix)] == prefix && p[len(prefix)] == '/'
}

// SanctionedSeams are the ONLY production roots through which an ee/agentid constructor
// may become reachable (the ee_attach seam). Files, relative to the module root, all
// carrying //go:build !trstctl_core. The seam assertion (TestProdCaller_
// SeamIsOnlySanctionedRoot) verifies each REQUIRED constructor's non-test caller chain
// roots here and that a purely test-helper caller does not satisfy the gate.
var SanctionedSeams = []string{
	"cmd/trstctl/ee_attach.go",        // control-plane: AGID API + orchestrator worker attach
	"cmd/trstctl-signer/ee_attach.go", // signer: in-signer delegation gate attach
}

// Tier classifies an in-scope exported constructor.
type Tier int

const (
	// TierRequired: on the shipped AGID critical path; MUST have a non-test caller and
	// (strong check) be RTA-reachable from an in-scope cmd/* main built without
	// -tags trstctl_core. A regression to test-only fails the gate.
	TierRequired Tier = iota
	// TierDeferred: external-consumer-only (the ee/agentid/verify RP SDK); EXEMPT from
	// the caller/reachability bar, mirroring the PCAS DEFERRED tier.
	TierDeferred
)

func (t Tier) String() string {
	switch t {
	case TierRequired:
		return "REQUIRED"
	case TierDeferred:
		return "DEFERRED"
	default:
		return "UNKNOWN"
	}
}

// Constructor is one exported ee/agentid constructor / factory / Attach* the gate
// governs. Pkg is the module-relative import path; Name is the function identifier;
// File is the defining file relative to the module root; Tier is its classification;
// SeededVia documents the sanctioned seam (or driving package) through which its
// non-test caller chain roots, for the seam assertion's human-readable output.
type Constructor struct {
	Pkg       string
	Name      string
	File      string
	Tier      Tier
	SeededVia string
}

// Qualified returns "pkgbase.Name" for messages, e.g. "reach/engine.NewEngine".
func (c Constructor) Qualified() string {
	return lastPathSegment(c.Pkg) + "." + c.Name
}

func lastPathSegment(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// Inventory is the canonical list of every exported ee/agentid constructor the gate
// governs, with its tier and the seam its production-caller chain roots at. It is the
// SPEC: the floor enumerates the live AST and asserts this list matches (no missing
// entry, no stale entry) so the gate can never silently drift as the family grows.
//
// The REQUIRED entries were verified (2026-07-07, wiring landed on AGID-INT-CALL) to
// each have a non-test caller on the cmd/trstctl attach -> ee/agentid/api ->
// ee/agentid/orchestrator worker path (or the cmd/trstctl-signer attach for the
// in-signer gate). The DEFERRED entry (verify.NewLocalPolicy) is the external RP SDK.
var Inventory = []Constructor{
	// ---- agentstack (AGID-03): tool manifest / registered tool set ---------------
	{Pkg: "ee/agentid/agentstack", Name: "NewToolManifest", File: "ee/agentid/agentstack/manifest.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (declared tool manifest)"},
	{Pkg: "ee/agentid/agentstack", Name: "NewRegisteredToolSet", File: "ee/agentid/agentstack/manifest.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (registered tool set)"},
	// agentstack.New is the issuer-side representation BUILDER (ingests the raw secret
	// prompt). DEFERRED external-consumer tier: a control-plane caller would violate AN-8
	// (control plane must never hold the raw prompt) and AN-4 (signer doesn't link
	// agentstack). See DeferredSymbols for the full rationale. Flagged for reviewers.
	{Pkg: "ee/agentid/agentstack", Name: "New", File: "ee/agentid/agentstack/representation.go", Tier: TierDeferred, SeededVia: "issuer-side builder / external consumer (AN-8: no control-plane caller)"},

	// ---- api (external AGID surface) ---------------------------------------------
	{Pkg: "ee/agentid/api", Name: "NewAPIOptionsFactory", File: "ee/agentid/api/api.go", Tier: TierRequired, SeededVia: "cmd/trstctl ee_attach (FeatureAgentDelegation API attach)"},
	{Pkg: "ee/agentid/api", Name: "NewService", File: "ee/agentid/api/service.go", Tier: TierRequired, SeededVia: "api.NewAPIOptionsFactory (built by the attach seam)"},

	// ---- orchestrator (licensed-outbox worker: the production caller) ------------
	{Pkg: "ee/agentid/orchestrator", Name: "NewLicensedOutboxFactory", File: "ee/agentid/orchestrator/orchestrator.go", Tier: TierRequired, SeededVia: "cmd/trstctl ee_attach (FeatureAgentDelegation outbox attach)"},
	{Pkg: "ee/agentid/orchestrator", Name: "NewSignerIssuanceGate", File: "ee/agentid/orchestrator/signergate.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (control-plane signer GatedIssue adapter, AGID-INT-WIRE)"},

	// ---- delegation (AGID-01/03/04): registry, binding, signer gate, verifier ----
	{Pkg: "ee/agentid/delegation", Name: "NewToolRegistry", File: "ee/agentid/delegation/authority.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (tool canonicalization)"},
	{Pkg: "ee/agentid/delegation", Name: "NewBindingMaterial", File: "ee/agentid/delegation/bind.go", Tier: TierRequired, SeededVia: "delegation verifier (credential binding on the gate path)"},
	{Pkg: "ee/agentid/delegation", Name: "NewSignerGate", File: "ee/agentid/delegation/signerwiring.go", Tier: TierRequired, SeededVia: "cmd/trstctl-signer ee_attach (WithIssuanceGate)"},
	{Pkg: "ee/agentid/delegation", Name: "NewSignerIssuanceKeyOp", File: "ee/agentid/delegation/signerwiring.go", Tier: TierRequired, SeededVia: "cmd/trstctl-signer ee_attach (WithIssuanceKeyOp)"},
	{Pkg: "ee/agentid/delegation", Name: "NewIssuanceKeyOp", File: "ee/agentid/delegation/issuancekeyop.go", Tier: TierRequired, SeededVia: "delegation.NewSignerIssuanceKeyOp (builds the AGID-INT-WIRE in-signer issuance key op)"},
	{Pkg: "ee/agentid/delegation", Name: "NewGate", File: "ee/agentid/delegation/verifier.go", Tier: TierRequired, SeededVia: "delegation.NewSignerGate (builds the AGID-04b verifier gate)"},
	{Pkg: "ee/agentid/delegation", Name: "NewTrustStore", File: "ee/agentid/delegation/verifier.go", Tier: TierRequired, SeededVia: "delegation.NewSignerGate (builds the root-anchor trust store)"},

	// ---- delegation/store (AGID-02 projection-backed repo) -----------------------
	{Pkg: "ee/agentid/delegation/store", Name: "New", File: "ee/agentid/delegation/store/store.go", Tier: TierRequired, SeededVia: "api.NewService + orchestrator handler (AGID-02 repo)"},

	// ---- delegation/brokerstore (AGID-07b chain-bound issuance precondition) ------
	{Pkg: "ee/agentid/delegation/brokerstore", Name: "NewMemoryIdempotencer", File: "ee/agentid/delegation/brokerstore/precondition.go", Tier: TierRequired, SeededVia: "brokerstore.NewBrokerPrecondition (default Idem)"},
	{Pkg: "ee/agentid/delegation/brokerstore", Name: "NewFailClosedBrokerPrecondition", File: "ee/agentid/delegation/brokerstore/precondition.go", Tier: TierRequired, SeededVia: "cmd/trstctl ee_attach (BrokerIssuancePrecondition)"},
	{Pkg: "ee/agentid/delegation/brokerstore", Name: "NewBrokerPrecondition", File: "ee/agentid/delegation/brokerstore/precondition.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (per-request precondition)"},
	{Pkg: "ee/agentid/delegation/brokerstore", Name: "New", File: "ee/agentid/delegation/brokerstore/recorder.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (issuance recorder)"},

	// ---- reach (AGID-06 pre-issuance reachability bound) -------------------------
	{Pkg: "ee/agentid/reach", Name: "NewCeilingPolicy", File: "ee/agentid/reach/ceiling.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (ceiling policy)"},
	{Pkg: "ee/agentid/reach", Name: "NewVerdict", File: "ee/agentid/reach/verdict.go", Tier: TierRequired, SeededVia: "reach/engine.ProduceVerdict (signed reachability verdict)"},
	{Pkg: "ee/agentid/reach/engine", Name: "NewEngine", File: "ee/agentid/reach/engine/engine.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (reachability engine)"},

	// ---- revoke (AGID-10/11 cascaded + terminal revocation) ----------------------
	{Pkg: "ee/agentid/revoke", Name: "NewCascade", File: "ee/agentid/revoke/cascade.go", Tier: TierRequired, SeededVia: "orchestrator revocation worker (directive cascade)"},
	{Pkg: "ee/agentid/revoke", Name: "NewExecutor", File: "ee/agentid/revoke/executor.go", Tier: TierRequired, SeededVia: "orchestrator revocation worker (per-job executor)"},
	{Pkg: "ee/agentid/revoke", Name: "NewIntervalMonitor", File: "ee/agentid/revoke/interval.go", Tier: TierRequired, SeededVia: "orchestrator revocation worker (interval exceedance)"},
	{Pkg: "ee/agentid/revoke", Name: "NewDirectiveRevocationReader", File: "ee/agentid/revoke/refuse_active.go", Tier: TierRequired, SeededVia: "orchestrator issuance worker (per-hop non-revocation reader)"},
	{Pkg: "ee/agentid/revoke", Name: "NewTerminalTransition", File: "ee/agentid/revoke/terminal.go", Tier: TierRequired, SeededVia: "orchestrator revocation worker (terminal transition)"},

	// ---- verify (AGID-09): DEFERRED external RP SDK (claim 28) --------------------
	{Pkg: "ee/agentid/verify", Name: "NewLocalPolicy", File: "ee/agentid/verify/helpers.go", Tier: TierDeferred, SeededVia: "external relying-party SDK (no in-repo control-plane caller by design)"},
}

// requiredConstructors returns the REQUIRED-tier inventory entries.
func requiredConstructors() []Constructor {
	out := make([]Constructor, 0, len(Inventory))
	for _, c := range Inventory {
		if c.Tier == TierRequired {
			out = append(out, c)
		}
	}
	return out
}
