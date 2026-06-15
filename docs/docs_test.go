package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// requiredPages are the documentation pages S7.6 must deliver, as paths relative
// to the docs directory.
var requiredPages = []string{
	"index.md",
	"getting-started.md",
	"install.md",
	"uninstall.md",
	"configuration.md",
	"compliance.md",
	"observability.md",
	"operations.md",
	"disaster-recovery.md",
	"migrations.md",
	"limitations.md",
	"runbooks/key-ceremony.md",
	"runbooks/incident-response.md",
	"security/threat-model.md",
	"security/vulnerability-management.md",
	"troubleshooting.md",
	"cli.md",
	"telemetry.md",
	"guides/plugin-authoring.md",
	"guides/connector-authoring.md",
	"guides/profile-authoring.md",
	"guides/est-enrollment.md",
}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// allMarkdown returns every Markdown file under the docs directory.
func allMarkdown(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRequiredDocsExist: every required page exists and is a real page (has a
// heading and more than a stub of content).
func TestRequiredDocsExist(t *testing.T) {
	for _, p := range requiredPages {
		body := read(t, p)
		if len(strings.TrimSpace(body)) < 200 {
			t.Errorf("%s is too short to be a real documentation page (%d bytes)", p, len(body))
		}
		if !strings.Contains(body, "#") {
			t.Errorf("%s has no Markdown heading", p)
		}
	}
}

var mdLink = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)

// TestNoBrokenInternalLinks: every relative Markdown link resolves to a file
// that exists. External (http/https/mailto) and pure-anchor links are skipped.
func TestNoBrokenInternalLinks(t *testing.T) {
	for _, f := range allMarkdown(t) {
		body := read(t, f)
		dir := filepath.Dir(f)
		for _, m := range mdLink.FindAllStringSubmatch(body, -1) {
			target := strings.TrimSpace(m[1])
			switch {
			case target == "",
				strings.HasPrefix(target, "http://"),
				strings.HasPrefix(target, "https://"),
				strings.HasPrefix(target, "mailto:"),
				strings.HasPrefix(target, "#"):
				continue
			}
			path := target
			if i := strings.IndexAny(path, "#?"); i >= 0 {
				path = path[:i]
			}
			if path == "" {
				continue
			}
			resolved := filepath.Join(dir, filepath.FromSlash(path))
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s: broken internal link %q (looked for %q)", f, target, resolved)
			}
		}
	}
}

// supportedPlatforms are the platforms trustctl ships for; install and uninstall
// must be documented for each.
var supportedPlatforms = []string{"Linux", "macOS", "Windows", "Docker", "Kubernetes"}

// TestInstallAndUninstallCoverAllPlatforms encodes "install/uninstall are
// documented for all supported platforms".
func TestInstallAndUninstallCoverAllPlatforms(t *testing.T) {
	for _, page := range []string{"install.md", "uninstall.md"} {
		body := read(t, page)
		for _, plat := range supportedPlatforms {
			if !strings.Contains(body, plat) {
				t.Errorf("%s does not document the %s platform", page, plat)
			}
		}
	}
}

// TestGettingStartedMatchesProduct encodes "a new user reaches a first cert in a
// few minutes following the docs, and the page is honest about timing": the
// getting-started page cites the real one-command eval, walks the real first-run
// wizard (S7.3) toward a first certificate, and backs its timing claim with the
// measured issuance figure (R1.4) rather than an unverified marketing number.
func TestGettingStartedMatchesProduct(t *testing.T) {
	body := read(t, "getting-started.md")
	lower := strings.ToLower(body)

	if !strings.Contains(lower, "minute") {
		t.Error("getting-started should set an honest first-cert time expectation in minutes")
	}
	if !strings.Contains(lower, "measured") || !strings.Contains(lower, "millisecond") {
		t.Error("getting-started should cite the measured issuance time (R1.4), not an unverified number")
	}
	if !strings.Contains(body, "docker compose") || !strings.Contains(body, "deploy/docker/docker-compose.yml") {
		t.Error("getting-started should cite the real Compose eval command")
	}
	if _, err := os.Stat(filepath.FromSlash("../deploy/docker/docker-compose.yml")); err != nil {
		t.Fatalf("the Compose file getting-started cites must exist: %v", err)
	}
	for _, step := range []string{"connect a ca", "install an agent", "first cert"} {
		if !strings.Contains(lower, step) {
			t.Errorf("getting-started should walk the wizard step %q", step)
		}
	}
}

// TestObservabilityDocIsReal cross-checks the observability page against the
// code: it documents the real endpoints and a metric the control plane actually
// emits, and the shipped Prometheus rules / dashboard exist.
func TestObservabilityDocIsReal(t *testing.T) {
	body := read(t, "observability.md")
	for _, want := range []string{"/metrics", "/readyz", "traceparent", "trustctl_http_requests_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("observability.md should document %q", want)
		}
	}
	// The documented metric is the one the middleware emits.
	mw := read(t, "../internal/observ/middleware.go")
	if !strings.Contains(mw, "trustctl_http_requests_total") {
		t.Error("observability.md cites trustctl_http_requests_total but the middleware does not emit it")
	}
	// The control plane mounts the documented endpoints.
	srv := read(t, "../internal/server/server.go")
	if !strings.Contains(srv, "/metrics") || !strings.Contains(srv, "/readyz") {
		t.Error("observability.md documents /metrics and /readyz but the server does not mount them")
	}
	// The baseline operator assets exist.
	for _, f := range []string{"../deploy/observability/alerts.yml", "../deploy/observability/dashboard.json"} {
		if _, err := os.Stat(filepath.FromSlash(f)); err != nil {
			t.Errorf("missing operator asset %s: %v", f, err)
		}
	}
}

// TestOperationsDocIsReal cross-checks the resilience page against the code: it
// documents the live-path controls (bulkheads, rate limiting with 429, graceful
// drain, fail-closed signing) and a setting the loader actually reads, and the
// server actually wires the bulkhead.
func TestOperationsDocIsReal(t *testing.T) {
	lower := strings.ToLower(read(t, "operations.md"))
	for _, want := range []string{"bulkhead", "rate limit", "429", "retry-after", "drain", "fail"} {
		if !strings.Contains(lower, want) {
			t.Errorf("operations.md should cover %q", want)
		}
	}
	if !strings.Contains(read(t, "operations.md"), "TRUSTCTL_RATE_LIMIT_REQUESTS") {
		t.Error("operations.md should document the rate-limit budget setting")
	}
	if code := read(t, "../internal/config/config.go"); !strings.Contains(code, "TRUSTCTL_RATE_LIMIT_REQUESTS") {
		t.Error("TRUSTCTL_RATE_LIMIT_REQUESTS is documented but the loader does not read it")
	}
	if srv := read(t, "../internal/server/server.go"); !strings.Contains(srv, "bulkhead") {
		t.Error("operations.md documents bulkheads but the server does not wire one")
	}
}

// TestDisasterRecoveryDocIsReal cross-checks the DR page against the code: it
// documents the real backup/restore commands and recovery objectives, and the
// binary actually implements the flags it cites.
func TestDisasterRecoveryDocIsReal(t *testing.T) {
	body := read(t, "disaster-recovery.md")
	for _, want := range []string{"--backup", "--restore", "RPO", "RTO", "event log", "rebuild"} {
		if !strings.Contains(body, want) {
			t.Errorf("disaster-recovery.md should cover %q", want)
		}
	}
	// The documented flags exist in the binary.
	main := read(t, "../cmd/trustctl/main.go")
	for _, flag := range []string{`"backup"`, `"restore"`} {
		if !strings.Contains(main, flag) {
			t.Errorf("disaster-recovery.md documents a flag the binary does not define: %s", flag)
		}
	}
	// The restore path rebuilds from the event log (the AN-2 guarantee the doc rests on).
	if !strings.Contains(read(t, "../internal/server/backup.go"), "Rebuild") {
		t.Error("restore should rebuild the read model from the restored log")
	}
}

// TestMigrationsDocIsReal cross-checks the migration runbook against the code: it
// documents the real commands and the advisory-lock / forward-only safeguards,
// and the binary and store actually implement what it cites.
func TestMigrationsDocIsReal(t *testing.T) {
	body := read(t, "migrations.md")
	for _, want := range []string{
		"--migrate-status", "--migrate", "TRUSTCTL_MIGRATE_AUTO",
		"advisory lock", "forward-only", "pg_advisory_lock", "rollback",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("migrations.md should cover %q", want)
		}
	}
	// The documented flags exist in the binary.
	main := read(t, "../cmd/trustctl/main.go")
	for _, flag := range []string{`"migrate-status"`, `"migrate"`} {
		if !strings.Contains(main, flag) {
			t.Errorf("migrations.md documents a flag the binary does not define: %s", flag)
		}
	}
	// The migration runner really takes the advisory lock the doc rests on.
	migrate := read(t, "../internal/store/migrate.go")
	if !strings.Contains(migrate, "pg_advisory_lock") || !strings.Contains(migrate, "MigrateAdvisoryLockKey") {
		t.Error("Migrate should serialize the run on a PostgreSQL advisory lock")
	}
	// The gate (TRUSTCTL_MIGRATE_AUTO) is honored by config.
	if !strings.Contains(read(t, "../internal/config/config.go"), "TRUSTCTL_MIGRATE_AUTO") {
		t.Error("the config loader should read TRUSTCTL_MIGRATE_AUTO (the pre-migration backup gate)")
	}
}

var mdRef = regexp.MustCompile(`[\w./-]+\.md`)

// TestMkdocsNavResolves: every page the MkDocs nav references exists under the
// docs directory.
func TestMkdocsNavResolves(t *testing.T) {
	cfg := read(t, "../mkdocs.yml")
	refs := mdRef.FindAllString(cfg, -1)
	if len(refs) < len(requiredPages) {
		t.Fatalf("mkdocs.yml lists %d pages, fewer than the %d required", len(refs), len(requiredPages))
	}
	seen := map[string]bool{}
	for _, r := range refs {
		if seen[r] {
			continue
		}
		seen[r] = true
		if _, err := os.Stat(filepath.FromSlash(r)); err != nil {
			t.Errorf("mkdocs.yml nav references %q, which does not exist under docs/", r)
		}
	}
}

// TestConnectorGuideTracksSDK: the connector authoring guide names the real SDK
// surface, and those symbols still exist in the SDK.
func TestConnectorGuideTracksSDK(t *testing.T) {
	body := read(t, "guides/connector-authoring.md")
	for _, sym := range []string{"Connector", "Deploy", "Capabilities", "Sandbox"} {
		if !strings.Contains(body, sym) {
			t.Errorf("connector guide should reference the SDK symbol %q", sym)
		}
	}
	sdk := read(t, "../internal/connector/connector.go")
	for _, sym := range []string{"Connector", "Sandbox"} {
		if !strings.Contains(sdk, sym) {
			t.Errorf("internal/connector no longer defines %q; the guide is stale", sym)
		}
	}
}

// TestPluginGuideTracksHost: the plugin authoring guide covers the capability
// model of the real WASM plugin host.
func TestPluginGuideTracksHost(t *testing.T) {
	lower := strings.ToLower(read(t, "guides/plugin-authoring.md"))
	for _, term := range []string{"capabilit", "grant", "wazero", "conformance"} {
		if !strings.Contains(lower, term) {
			t.Errorf("plugin guide should cover %q", term)
		}
	}
}

// TestConfigurationDocCitesRealEnvVars: the configuration reference documents
// environment variables that the config loader actually reads.
func TestConfigurationDocCitesRealEnvVars(t *testing.T) {
	body := read(t, "configuration.md")
	code := read(t, "../internal/config/config.go")
	for _, env := range []string{"TRUSTCTL_POSTGRES_MODE", "TRUSTCTL_NATS_URL", "TRUSTCTL_TELEMETRY_ENABLED", "TRUSTCTL_SERVER_ADDR", "TRUSTCTL_AUDIT_SIGNING_KEY_FILE", "TRUSTCTL_AUDIT_RETENTION", "TRUSTCTL_RATE_LIMIT_REQUESTS", "TRUSTCTL_SECRETS_KEK_FILE", "TRUSTCTL_SIGNER_MODE", "TRUSTCTL_CA_CERT_FILE"} {
		if !strings.Contains(body, env) {
			t.Errorf("configuration.md should document %s", env)
		}
		if !strings.Contains(code, env) {
			t.Errorf("%s is documented but internal/config does not read it; the doc is stale", env)
		}
	}
}

// TestComplianceDocIsHonest encodes the R2.1 acceptance "state explicitly which
// framework controls this enables vs. what the operator must still do (no
// overclaiming)": the compliance page must frame controls as enabled (not
// certified), assign the operator their responsibilities, document the
// tamper-evidence model, and cite the real audit signing-key setting.
func TestComplianceDocIsHonest(t *testing.T) {
	body := read(t, "compliance.md")
	lower := strings.ToLower(body)

	for _, marker := range []string{"operator", "enables", "tamper", "retention"} {
		if !strings.Contains(lower, marker) {
			t.Errorf("compliance.md should address %q", marker)
		}
	}
	// No-overclaiming: an explicit disclaimer that deploying trustctl is not itself
	// compliance/certification.
	if !strings.Contains(lower, "not a claim") && !strings.Contains(lower, "certification is yours") {
		t.Error("compliance.md must explicitly disclaim that trustctl alone makes you compliant/certified")
	}
	// Reality cross-check: it points at a setting the config loader actually reads.
	if !strings.Contains(body, "TRUSTCTL_AUDIT_SIGNING_KEY_FILE") {
		t.Error("compliance.md should reference the persistent audit signing-key setting")
	}
	code := read(t, "../internal/config/config.go")
	if !strings.Contains(code, "TRUSTCTL_AUDIT_SIGNING_KEY_FILE") {
		t.Error("TRUSTCTL_AUDIT_SIGNING_KEY_FILE is referenced in docs but the config loader does not read it")
	}
}

// TestCLIDocCitesRealCommands: the CLI reference documents command groups that
// the CLI actually serves.
func TestCLIDocCitesRealCommands(t *testing.T) {
	body := read(t, "cli.md")
	cmd := read(t, "../internal/cli/command.go")
	for _, group := range []string{"owners", "issuers", "identities", "certificates", "risk", "agents"} {
		if !strings.Contains(body, group) {
			t.Errorf("cli.md should document the %q command group", group)
		}
		if !strings.Contains(cmd, group) {
			t.Errorf("%q is documented but is not a real CLI command group", group)
		}
	}
}

// --- R2.6: documentation honesty -------------------------------------------

// TestNoFullyFunctionalClaim: the docs must not claim the product is "fully
// functional" (the overclaim the audit flagged). "No feature gating" is the real,
// intended point and is allowed; "fully functional" is not.
func TestNoFullyFunctionalClaim(t *testing.T) {
	for _, f := range []string{"index.md", "../README.md"} {
		lower := strings.ToLower(read(t, f))
		if strings.Contains(lower, "fully functional") || strings.Contains(lower, "fully-functional") {
			t.Errorf("%s still claims the product is \"fully functional\" — replace with an honest statement", f)
		}
	}
}

// TestLimitationsStatementIsHonest: a current-limitations page exists and is
// honest about what the running binary serves today vs. what is library-level,
// naming the not-yet-served surfaces the audit called out.
func TestLimitationsStatementIsHonest(t *testing.T) {
	lower := strings.ToLower(read(t, "limitations.md"))
	// It distinguishes served-from-the-binary from built-as-a-library.
	if !strings.Contains(lower, "served") && !strings.Contains(lower, "runtime") {
		t.Error("limitations.md should distinguish what the running binary serves from what is library-level")
	}
	// It names the concrete not-yet-served surfaces (honesty, not vibes).
	for _, surface := range []string{"est", "scep", "spiffe", "wasm", "http-01"} {
		if !strings.Contains(lower, surface) {
			t.Errorf("limitations.md should be specific about %q (a known not-yet-served surface)", surface)
		}
	}
	// index.md links to it so a reader actually finds it.
	if !strings.Contains(read(t, "index.md"), "limitations.md") {
		t.Error("index.md should link to the limitations page")
	}
}

// servedClaim describes a capability whose served-vs-library status the docs must
// state HONESTLY, with the disclosure bound to the code so it cannot drift.
//
// codeServed(t) reports whether the running binary ACTUALLY serves the capability
// today (by inspecting the served composition / wiring). The reality-bind:
//   - while the code does NOT serve it, the disclosure markers MUST be present
//     and a "served" claim MUST be absent (catches an over-claim);
//   - if a future change DOES serve it (codeServed flips true), the test demands
//     the not-yet-served disclosure be removed (catches a stale under-claim that
//     would now itself be a lie).
//
// This is what makes a future over-claim of OIDC login / the React console / the
// AI surface as "served" fail `go test ./docs/...` (SEC-001, WIRE-001,
// SURFACE-001/002/003 — the served-vs-library honesty cluster).
type servedClaim struct {
	name string
	// disclosureMarkers are lowercase phrases limitations.md must contain while the
	// capability is not served (the honest "built/tested, not yet served" wording).
	disclosureMarkers []string
	// epic is the wire-in epic id limitations.md must link so the closure path is
	// traceable (EXC-WIRE-01 for auth, EXC-WIRE-04 for the console + AI surface).
	epic string
	// servedClaims are phrasings that would over-claim the capability as served;
	// none may appear in limitations.md while codeServed is false.
	overClaims []string
	// codeServed inspects the repo and reports whether the served binary wires the
	// capability today.
	codeServed func(t *testing.T) bool
}

// serverComposesAuth reports whether the served composition (internal/server)
// wires interactive OIDC browser login via api.WithAuth. Today it does not — the
// flow is library-complete but unserved (SEC-001/WIRE-001). When EXC-WIRE-01 wires
// it, this flips true and the disclosure must be retired.
func serverComposesAuth(t *testing.T) bool {
	t.Helper()
	for _, f := range nonTestGoFiles(t, "../internal/server") {
		if strings.Contains(read(t, f), "WithAuth(") {
			return true
		}
	}
	return false
}

// apiServesAISurface reports whether the served API/server wires the AI surface
// (the model adapter, RCA pipeline, or MCP server) into a served endpoint. Today
// it does not — these are library islands (SURFACE-003). When EXC-WIRE-04 wires an
// authenticated, tenant-scoped surface, this flips true.
func apiServesAISurface(t *testing.T) bool {
	t.Helper()
	for _, dir := range []string{"../internal/api", "../internal/server"} {
		for _, f := range nonTestGoFiles(t, dir) {
			src := read(t, f)
			for _, imp := range []string{
				`trustctl.io/trustctl/internal/aimodel"`,
				`trustctl.io/trustctl/internal/rca"`,
				`trustctl.io/trustctl/internal/mcpserver"`,
			} {
				if strings.Contains(src, imp) {
					return true
				}
			}
		}
	}
	return false
}

// binaryServesIssuanceProtocols reports whether the served binary mounts ANY of the
// non-ACME-DNS issuance protocol servers (EST, SCEP, CMP, SPIFFE, SSH) or the ACME
// server itself — i.e. whether the running control plane imports an
// internal/protocols/* package on its served path. Today none is mounted: the
// composition (internal/api, internal/server) and cmd/trustctl reference no protocol
// package, so every protocol is library-only (INTEROP-001/004). When EXC-WIRE-02
// wires a protocol onto the served listener, the corresponding import appears and
// this flips true, forcing the not-yet-served disclosure to be retired.
//
// It deliberately ignores the DNS-01 *solver* import path: the acme DNS solver
// packages legitimately reference internal/protocols/acme without the ACME server
// being served, so a substring match on "internal/protocols" alone would
// false-positive. We match the specific server packages.
func binaryServesIssuanceProtocols(t *testing.T) bool {
	t.Helper()
	protocolImports := []string{
		`trustctl.io/trustctl/internal/protocols/acme"`,
		`trustctl.io/trustctl/internal/protocols/est"`,
		`trustctl.io/trustctl/internal/protocols/scep"`,
		`trustctl.io/trustctl/internal/protocols/cmp"`,
		`trustctl.io/trustctl/internal/protocols/spiffe"`,
		`trustctl.io/trustctl/internal/protocols/ssh"`,
	}
	for _, dir := range []string{"../internal/api", "../internal/server", "../cmd/trustctl"} {
		for _, f := range nonTestGoFiles(t, dir) {
			src := read(t, f)
			for _, imp := range protocolImports {
				if strings.Contains(src, imp) {
					return true
				}
			}
		}
	}
	return false
}

// serverComposesPolicyGate reports whether the served composition (internal/api or
// internal/server) wires the OPA/Rego policy engine onto a served route by
// importing internal/policy. Today it does not — the engine is library-only
// (SEC-005). When EXC-WIRE-03 gates the served mutation path on it, the import
// appears and this flips true, forcing the not-yet-served disclosure to be retired.
func serverComposesPolicyGate(t *testing.T) bool {
	t.Helper()
	for _, dir := range []string{"../internal/api", "../internal/server"} {
		for _, f := range nonTestGoFiles(t, dir) {
			if strings.Contains(read(t, f), `trustctl.io/trustctl/internal/policy"`) {
				return true
			}
		}
	}
	return false
}

// serverEnforcesRASeparation reports whether a served route enforces the RA
// request/approve/issue separation — either by importing the approval workflow
// package into the served composition or by GATING a served route on the
// certs:request / certs:issue permissions (the route registry binds a route to a
// permission via `perm: authz.X`, and a handler may also call guard(authz.X, …)).
// Today none holds (SEC-002): the served issuance path is an identities:write
// transition and the approval package has no served importer. It deliberately
// does NOT match a bare mention of the constant — e.g. `string(authz.CertsRequest)`
// in the token-create command lists it as an available token SCOPE, which does not
// gate a served route — so only a real route binding flips this true (EXC-WIRE-03).
func serverEnforcesRASeparation(t *testing.T) bool {
	t.Helper()
	for _, dir := range []string{"../internal/api", "../internal/server"} {
		for _, f := range nonTestGoFiles(t, dir) {
			src := read(t, f)
			if strings.Contains(src, `trustctl.io/trustctl/internal/approval"`) {
				return true
			}
			// A served route GATED on an RA permission: the route-registry binding
			// (`perm: authz.CertsIssue`) or a direct guard(authz.CertsIssue, …) call.
			for _, perm := range []string{"CertsIssue", "CertsRequest"} {
				if strings.Contains(src, "perm: authz."+perm) || strings.Contains(src, "guard(authz."+perm) {
					return true
				}
			}
		}
	}
	return false
}

// binaryMapsPerUserTenant reports whether the served browser-login path maps a
// user to a real per-user tenant rather than the single configured DefaultTenant.
// Today it does not (TENANT-004): authCallback issues the session with
// a.auth.DefaultTenant. When EXC-WIRE-01 derives the tenant from the OIDC
// subject/claims at session issue, that DefaultTenant-at-issue pattern is gone and
// this flips true, forcing the disclosure to be retired.
func binaryMapsPerUserTenant(t *testing.T) bool {
	t.Helper()
	auth := read(t, "../internal/api/auth.go")
	// The unwired state: the session is issued with the configured DefaultTenant. If
	// that exact pattern is no longer present, per-user mapping has landed.
	return !strings.Contains(auth, "Sessions.Issue(claims.Subject, a.auth.DefaultTenant")
}

// binaryServesReactConsole reports whether the embedded web UI is a real built
// bundle (a hashed Vite asset) rather than the committed placeholder shell. Today
// it is the placeholder, so the binary serves a "not built" page (SURFACE-001).
// When EXC-WIRE-04 embeds a real bundle, the placeholder text is gone.
func binaryServesReactConsole(t *testing.T) bool {
	t.Helper()
	idx := read(t, "../internal/webui/dist/index.html")
	// The placeholder explicitly says the UI has not been built. A real Vite build
	// has no such text and injects a hashed module script.
	placeholder := strings.Contains(strings.ToLower(idx), "has not been built")
	hashedBundle := strings.Contains(idx, "assets/index-") || strings.Contains(idx, "<script")
	return hashedBundle && !placeholder
}

// nonTestGoFiles returns the non-test .go files directly under dir.
func nonTestGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.FromSlash(dir))
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, dir+"/"+e.Name())
	}
	return out
}

// TestServedVsLibraryStatusIsHonestAndCodeBound is the anti-vacuous-green guard for
// the served-vs-library honesty cluster (SEC-001, WIRE-001, SURFACE-001/002/003):
// the served-vs-library status of OIDC browser login, the React console, and the
// AI/RCA/MCP surface in limitations.md is asserted to MATCH THE CODE, in both
// directions. A future PR that re-claims any of these as "served" while the binary
// still does not wire it — or that quietly drops the disclosure — fails here.
func TestServedVsLibraryStatusIsHonestAndCodeBound(t *testing.T) {
	lim := read(t, "limitations.md")
	// Collapse whitespace so a marker/over-claim is matched even when the Markdown
	// source wraps it across lines (the disclosures are prose, not single tokens).
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	claims := []servedClaim{
		{
			name:              "OIDC browser login & sessions (F13)",
			disclosureMarkers: []string{"oidc", "/auth/login", "not yet served by the binary"},
			epic:              "EXC-WIRE-01",
			// Must not assert the browser login routes are served.
			overClaims: []string{
				"oidc sso login is served",
				"/auth/login is served",
				"browser login is served",
			},
			codeServed: serverComposesAuth,
		},
		{
			// SURFACE-001: EXC-WIRE-04 now SERVES the console (the committed
			// internal/webui/dist embed is a real Vite build, so binaryServesReactConsole
			// returns true and the served branch retires the disclosure below). The
			// not-served marker is the CONSOLE-SPECIFIC "embedded build is a placeholder"
			// (not the generic "not yet served by the binary", which other still-unserved
			// claims like the AI surface legitimately use — pairing on the generic phrase
			// would false-positive once the console is served while AI is not). If the
			// console ever regresses to the placeholder, binaryServesReactConsole flips to
			// false and this requires the honest "placeholder" disclosure to reappear.
			name:              "React web console (F12)",
			disclosureMarkers: []string{"react web console", "embedded build is a placeholder"},
			epic:              "EXC-WIRE-04",
			overClaims: []string{
				"web ui is served",
			},
			codeServed: binaryServesReactConsole,
		},
		{
			name:              "AI / RCA / MCP surface (F76/F77/F78)",
			disclosureMarkers: []string{"mcp server", "rca", "not yet served by the binary"},
			epic:              "EXC-WIRE-04",
			overClaims: []string{
				"the mcp server is served",
				"the rca pipeline is served",
				"the ai surface is served",
			},
			codeServed: apiServesAISurface,
		},
		{
			// INTEROP-001/004: the issuance protocol servers (ACME, EST, SCEP, CMP,
			// SPIFFE Workload API, SSH CA) are library-complete and tested but not
			// served end-to-end by the binary. A future PR that mounts a protocol on
			// the served listener (EXC-WIRE-02) must retire this disclosure; a PR that
			// claims a protocol is served while the binary still does not import it
			// fails here.
			name:              "Issuance protocols served end-to-end (ACME/EST/SCEP/CMP/SPIFFE/SSH)",
			disclosureMarkers: []string{"not served end-to-end by the running binary", "spiffe workload api"},
			epic:              "EXC-WIRE-02",
			overClaims: []string{
				"the est server is served",
				"the scep server is served",
				"the cmp server is served",
				"the spiffe workload api is served",
				"the ssh ca is served end-to-end",
				"these protocols are served end-to-end by the running binary",
			},
			codeServed: binaryServesIssuanceProtocols,
		},
		{
			// SEC-005: the OPA/Rego policy gate (default-deny on issue/deploy/revoke)
			// is real, tested library code but the served binary never invokes it. A
			// future PR that wires internal/policy into the served mutation path
			// (EXC-WIRE-03) must retire this disclosure; a PR that claims it is served
			// while the binary still does not import internal/policy fails here.
			name:              "OPA/Rego policy gate on the served mutation path (SEC-005)",
			disclosureMarkers: []string{"opa/rego policy gate", "the served binary never invokes it"},
			epic:              "EXC-WIRE-03",
			overClaims: []string{
				"the opa policy gate is served",
				"the rego policy gate is served",
				"the policy engine gates the served",
			},
			codeServed: serverComposesPolicyGate,
		},
		{
			// SEC-002: RA separation & dual-control approval are modeled and tested in
			// the RBAC/approval libraries but enforced on no served route. A future PR
			// that gates a served request/approve/issue flow on certs:request/certs:issue
			// (EXC-WIRE-03) must retire this disclosure; a PR that claims RA separation is
			// served while no served route uses it fails here.
			name:              "RA separation & dual-control on a served route (SEC-002)",
			disclosureMarkers: []string{"registration-authority (ra) separation", "not yet enforced on any served route"},
			epic:              "EXC-WIRE-03",
			overClaims: []string{
				"ra separation is served",
				"dual control is served",
				"the approval workflow is served",
			},
			codeServed: serverEnforcesRASeparation,
		},
		{
			// TENANT-004: browser/OIDC logins all map to a single DefaultTenant; per-user
			// tenant mapping is not yet wired. A future PR that maps the OIDC subject/claims
			// to the real tenant at session issue (EXC-WIRE-01) must retire this disclosure;
			// a PR that claims per-user tenant mapping is served while auth.go still issues
			// sessions with the configured DefaultTenant fails here.
			name:              "Per-user tenant mapping for browser logins (TENANT-004)",
			disclosureMarkers: []string{"per-user tenant mapping is not yet wired", "defaulttenant"},
			epic:              "EXC-WIRE-01",
			overClaims: []string{
				"per-user tenant mapping is served",
				"per-user tenant mapping is wired",
			},
			codeServed: binaryMapsPerUserTenant,
		},
	}

	for _, c := range claims {
		served := c.codeServed(t)
		if served {
			// The capability is now genuinely served: the not-yet-served disclosure
			// would itself be an (under-)claim, so it must have been retired. If all of
			// this claim's specific not-served markers are still present, the
			// disclosure was not updated.
			if containsAll(low, c.disclosureMarkers) {
				t.Errorf("%s appears to be SERVED in code now, but limitations.md still discloses it as not-yet-served — update the disclosure (the wire-in epic %s closed)", c.name, c.epic)
			}
			continue
		}
		// Not served: the honest disclosure must be present, link the epic, and
		// carry no over-claim.
		for _, m := range c.disclosureMarkers {
			if !strings.Contains(low, m) {
				t.Errorf("limitations.md must disclose %s as built/tested-but-not-served (missing marker %q)", c.name, m)
			}
		}
		if !strings.Contains(lim, c.epic) {
			t.Errorf("limitations.md must link the wire-in epic %s for %s so the closure path is traceable", c.epic, c.name)
		}
		for _, oc := range c.overClaims {
			if strings.Contains(low, oc) {
				t.Errorf("limitations.md over-claims %s as served (%q) while the binary does not wire it", c.name, oc)
			}
		}
	}

	// Reality anchor: api.WithAuth is the seam the OIDC disclosure rests on. It must
	// keep existing even while the server does not call it, so the
	// not-yet-served-but-built claim is grounded in real code (fail loudly, rather
	// than silently-stale green, if the seam is ever removed).
	if !serverComposesAuth(t) && !apiHasWithAuthOption(t) {
		t.Error("internal/api no longer exposes WithAuth; the OIDC served-vs-library disclosure has no code anchor — revisit this reality test")
	}

	// Reality anchors for the SEC-005 / SEC-002 / TENANT-004 disclosures: the library
	// code each rests on must keep existing while it is not served, so a "built but
	// not served" claim is grounded (fail loudly if a seam is removed, rather than a
	// silently-stale green disclosure).
	if !strings.Contains(read(t, "../internal/policy/policy.go"), "func (e *Engine) Evaluate(") {
		t.Error("internal/policy no longer exposes Engine.Evaluate; the SEC-005 policy-gate disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/authz/authz.go"), "CertsIssue") ||
		!strings.Contains(read(t, "../internal/authz/authz.go"), "CertsRequest") {
		t.Error("internal/authz no longer defines the certs:request/certs:issue RA-separation permissions; the SEC-002 disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/api/auth.go"), "DefaultTenant") {
		t.Error("internal/api/auth.go no longer references DefaultTenant; the TENANT-004 single-tenant disclosure has no code anchor — revisit this reality test")
	}
}

// apiHasWithAuthOption reports whether internal/api still exposes the WithAuth
// option (the OIDC/session seam the disclosure rests on).
func apiHasWithAuthOption(t *testing.T) bool {
	t.Helper()
	return strings.Contains(read(t, "../internal/api/api.go"), "func WithAuth(")
}

// containsAll reports whether s contains every substring in subs.
func containsAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// binaryServesSecretsFrameworks reports whether the served binary (internal/api,
// internal/server, cmd/trustctl) imports ANY of the five secrets/identity
// frameworks — the workload auth-method framework, secret-sync, the secrets SDK,
// PKI-as-a-secret, and secret sharing. Today none is imported on the served path:
// they are library-only (GAP-006). When a future change mounts one of these on the
// served listener (EXC-WIRE-03), the corresponding import appears and this flips
// true, forcing the not-yet-served disclosure to be retired.
func binaryServesSecretsFrameworks(t *testing.T) bool {
	t.Helper()
	imports := []string{
		`trustctl.io/trustctl/internal/authmethod"`,
		`trustctl.io/trustctl/internal/secretsync"`,
		`trustctl.io/trustctl/internal/secretsdk"`,
		`trustctl.io/trustctl/internal/pkisecret"`,
		`trustctl.io/trustctl/internal/secretshare"`,
	}
	for _, dir := range []string{"../internal/api", "../internal/server", "../cmd/trustctl"} {
		for _, f := range nonTestGoFiles(t, dir) {
			src := read(t, f)
			for _, imp := range imports {
				if strings.Contains(src, imp) {
					return true
				}
			}
		}
	}
	return false
}

// TestSecretsFrameworksDisclosedAsLibraryOnly is the reality-bound disclosure for
// GAP-006: the five secrets/identity frameworks (authmethod F58, secretsync F60,
// secretsdk F64, pkisecret F67, secretshare F68) are library-complete but not
// served end-to-end by the binary. While the binary does not import them on the
// served path, limitations.md must name each and link the wire-in epic; if a
// future change serves one (the import appears) the stale not-served disclosure
// must be retired. The package directories must also still exist, anchoring the
// disclosure in real code.
func TestSecretsFrameworksDisclosedAsLibraryOnly(t *testing.T) {
	for _, pkg := range []string{"authmethod", "secretsync", "secretsdk", "pkisecret", "secretshare"} {
		if _, err := os.Stat(filepath.FromSlash("../internal/" + pkg)); err != nil {
			t.Fatalf("internal/%s no longer exists; revisit this reality test (GAP-006)", pkg)
		}
	}

	lim := read(t, "limitations.md")
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	if binaryServesSecretsFrameworks(t) {
		// Now genuinely served: the not-yet-served disclosure would be a stale
		// under-claim and must have been retired.
		if strings.Contains(low, "not yet served by the binary") && strings.Contains(low, "five frameworks") {
			t.Error("a secrets framework appears to be SERVED now, but limitations.md still discloses the five as not-yet-served — update the disclosure (EXC-WIRE-03 closed)")
		}
		return
	}

	// Not served: every package and its feature id is disclosed, and the epic is linked.
	for _, pkg := range []string{"authmethod", "secretsync", "secretsdk", "pkisecret", "secretshare"} {
		if !strings.Contains(low, pkg) {
			t.Errorf("limitations.md must disclose the library-only %s framework", pkg)
		}
	}
	for _, fid := range []string{"F58", "F60", "F64", "F67", "F68"} {
		if !strings.Contains(lim, fid) {
			t.Errorf("limitations.md should cite the feature id %s in the secrets-frameworks disclosure", fid)
		}
	}
	if !strings.Contains(lim, "EXC-WIRE-03") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-03 for the secrets/identity frameworks")
	}
}

// agentImportsSSHTrust reports whether the agent binary or its (non-sshtrust)
// agent packages import the privileged SSH-trust rewrite package. Today nothing
// links it (SIGNER-004): it is library-only. When a future change wires it behind
// an operator opt-in (EXC-WIRE-05), the import appears and this flips true, forcing
// the not-yet-served disclosure to be retired.
func agentImportsSSHTrust(t *testing.T) bool {
	t.Helper()
	const imp = `trustctl.io/trustctl/internal/agent/sshtrust"`
	dirs := []string{"../cmd/trustctl-agent", "../internal/agent"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(filepath.FromSlash(dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			if strings.Contains(read(t, dir+"/"+e.Name()), imp) {
				return true
			}
		}
	}
	return false
}

// TestSSHTrustRewriteDisclosedAsLibraryOnly is the reality-bound disclosure for
// SIGNER-004: the privileged SSH-trust rewrite applier (internal/agent/sshtrust)
// is built and tested but linked into no binary. While the agent does not import
// it, limitations.md must disclose the discover-not-mutate split and link
// EXC-WIRE-05; if a future change wires it, the stale disclosure must be retired.
func TestSSHTrustRewriteDisclosedAsLibraryOnly(t *testing.T) {
	if _, err := os.Stat(filepath.FromSlash("../internal/agent/sshtrust/sshtrust.go")); err != nil {
		t.Fatalf("internal/agent/sshtrust no longer exists; revisit this reality test (SIGNER-004)")
	}
	lim := read(t, "limitations.md")
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	if agentImportsSSHTrust(t) {
		if strings.Contains(low, "not linked into any binary") {
			t.Error("sshtrust appears to be WIRED now, but limitations.md still discloses it as not-linked — update the disclosure (EXC-WIRE-05 closed)")
		}
		return
	}
	for _, m := range []string{"sshtrust", "not linked into any binary", "signer-004"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the library-only SSH-trust rewrite (missing marker %q)", m)
		}
	}
	if !strings.Contains(lim, "EXC-WIRE-05") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-05 for the SSH-trust rewrite")
	}
	// Over-claim guard: do not claim the rewrite is served/active.
	for _, oc := range []string{"ssh trust rewrite is served", "the agent rewrites a host's trust"} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims the SSH-trust rewrite as active (%q) while it is unlinked", oc)
		}
	}
}

// pluginHostVerifiesSignatures reports whether internal/pluginhost's Load path
// performs any signature / provenance / trusted-key check before instantiating a
// .wasm module. Today it does not (SUPPLY-004): Load goes straight to
// InstantiateWithConfig. When a future change adds a cosign/Ed25519/hash gate, one
// of these markers appears in the host source and this flips true, forcing the
// not-yet-verified disclosure to be retired.
func pluginHostVerifiesSignatures(t *testing.T) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.FromSlash("../internal/pluginhost/*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		low := strings.ToLower(read(t, f))
		// A real provenance gate would reference one of these in the load path.
		for _, marker := range []string{"cosign", "ed25519.verify", "verifysignature", "trustedkey", "trusted_key", "loadverified"} {
			if strings.Contains(low, marker) {
				return true
			}
		}
	}
	return false
}

// TestPluginHostProvenanceDisclosedAsAbsent is the reality-bound disclosure for
// SUPPLY-004: the WASM plugin host loads .wasm bytes with NO signature/provenance
// verification. While the host source contains no signature/trusted-key check,
// limitations.md must disclose the absent gate and link EXC-WIRE-05; if a future
// change adds verification, the stale "no verification" disclosure must be retired.
// The reality anchor (Host.Load instantiating raw bytes) must keep existing so the
// disclosure is grounded in real code.
func TestPluginHostProvenanceDisclosedAsAbsent(t *testing.T) {
	host := read(t, "../internal/pluginhost/host.go")
	// Reality anchor: Load still instantiates the supplied bytes directly.
	if !strings.Contains(host, "InstantiateWithConfig(ctx, wasm") {
		t.Fatal("internal/pluginhost/host.go no longer instantiates raw wasm bytes in Load; revisit this reality test (SUPPLY-004)")
	}

	lim := read(t, "limitations.md")
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	if pluginHostVerifiesSignatures(t) {
		// Verification has landed: the not-yet-verified disclosure would be a stale
		// under-claim and must have been retired.
		if strings.Contains(low, "without any signature") || strings.Contains(low, "no plugin signature/provenance verification") {
			t.Error("the plugin host appears to verify signatures now, but limitations.md still discloses provenance verification as absent — update the disclosure (EXC-WIRE-05 closed)")
		}
		return
	}

	// Not verified: limitations.md must disclose the absent gate, cite SUPPLY-004,
	// and link the wire-in epic.
	for _, m := range []string{"supply-004", "signature", "provenance"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the absent plugin signature/provenance gate (missing marker %q) (SUPPLY-004)", m)
		}
	}
	if !strings.Contains(lim, "EXC-WIRE-05") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-05 for plugin provenance verification (SUPPLY-004)")
	}
	// Over-claim guard: do not claim the host verifies plugin signatures today.
	for _, oc := range []string{"plugins are signature-verified", "the host verifies plugin signatures", "signed plugins are verified"} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims plugin signature verification (%q) while the host performs none (SUPPLY-004)", oc)
		}
	}
}

// serverMountsAgentGRPCListener reports whether the served composition mounts an
// agent-facing gRPC listener (the steady-state agent<->control-plane channel).
// Today it does not (OPS-005/WIRE-004): the only served grpc.Server is the signer's
// UDS, and internal/server registers no agent RPC service. When a future change
// mounts an agent gRPC gateway, one of these markers appears and this flips true.
func serverMountsAgentGRPCListener(t *testing.T) bool {
	t.Helper()
	for _, f := range nonTestGoFiles(t, "../internal/server") {
		src := read(t, f)
		// An agent gRPC gateway would register an agent service and/or import the
		// agent transport's server side into the served composition.
		for _, marker := range []string{"RegisterAgentServer", "RegisterEnrollServer", "agent/transport", "AgentServiceServer"} {
			if strings.Contains(src, marker) {
				return true
			}
		}
	}
	return false
}

// TestAgentSteadyStateChannelDisclosedAsUnexposed is the reality-bound disclosure
// for OPS-005: the advertised steady-state agent<->control-plane mTLS gRPC channel
// (the manifests point agents at :9443) has no served control-plane listener/Service.
// While the served binary mounts no agent gRPC listener, limitations.md must disclose
// the gap, cite OPS-005, and link EXC-WIRE-02; if a future change serves it, the stale
// disclosure must be retired. The manifest fact (daemonset :9443) and the control-plane
// Service exposing only the API port anchor the disclosure in real artifacts.
func TestAgentSteadyStateChannelDisclosedAsUnexposed(t *testing.T) {
	// Reality anchor (manifest): the daemonset advertises the :9443 agent server, but
	// the control-plane Service template exposes only the API port.
	ds := read(t, "../deploy/kubernetes/daemonset.yaml")
	if !strings.Contains(ds, "9443") {
		t.Fatal("daemonset.yaml no longer advertises the :9443 agent server; revisit this reality test (OPS-005)")
	}
	svc := read(t, "../deploy/helm/trustctl/templates/service.yaml")
	if strings.Contains(svc, "9443") {
		// A control-plane Service now exposes the agent port — the gap may be closing.
		t.Log("control-plane service.yaml now references 9443; verify the agent gateway is actually served (OPS-005)")
	}

	lim := read(t, "limitations.md")
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	if serverMountsAgentGRPCListener(t) {
		if strings.Contains(low, "no agent grpc listener is mounted") {
			t.Error("an agent gRPC listener appears to be served now, but limitations.md still discloses it as unmounted — update the disclosure (EXC-WIRE-02 closed)")
		}
		return
	}

	for _, m := range []string{"ops-005", "no agent grpc listener is mounted", "9443"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the unexposed agent steady-state channel (missing marker %q) (OPS-005)", m)
		}
	}
	if !strings.Contains(lim, "EXC-WIRE-02") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-02 for the agent steady-state channel (OPS-005)")
	}
}

// binaryServesPluginHost reports whether the served binary (internal/api,
// internal/server, cmd/trustctl) imports the WASM plugin host on its served path.
// Today nothing does (ARCH-007): the host and the CA/connector plugins are
// library-only, so the running control plane cannot load a third-party plugin.
// When a future change wires the host into the served binary (EXC-WIRE-05), the
// import appears and this flips true, forcing the not-yet-served disclosure to be
// retired.
func binaryServesPluginHost(t *testing.T) bool {
	t.Helper()
	const imp = `trustctl.io/trustctl/internal/pluginhost"`
	for _, dir := range []string{"../internal/api", "../internal/server", "../cmd/trustctl"} {
		for _, f := range nonTestGoFiles(t, dir) {
			if strings.Contains(read(t, f), imp) {
				return true
			}
		}
	}
	return false
}

// TestPluginHostDisclosedAsLibraryOnly is the reality-bound disclosure for
// ARCH-007: the WASM plugin host and the CA/connector plugins are built and tested
// but not wired into the served binary, so advertised plugin extensibility
// (CA-via-plugin, connector-via-plugin) is not production capability. While the
// served binary does not import internal/pluginhost, limitations.md must disclose
// this and link EXC-WIRE-05; if a future change serves it, the stale disclosure
// must be retired. The host package must still exist, anchoring the disclosure in
// real code.
func TestPluginHostDisclosedAsLibraryOnly(t *testing.T) {
	if _, err := os.Stat(filepath.FromSlash("../internal/pluginhost/host.go")); err != nil {
		t.Fatalf("internal/pluginhost no longer exists; revisit this reality test (ARCH-007)")
	}
	lim := read(t, "limitations.md")
	low := strings.Join(strings.Fields(strings.ToLower(lim)), " ")

	if binaryServesPluginHost(t) {
		// Now genuinely served: the not-yet-served disclosure would be a stale
		// under-claim and must have been retired.
		if strings.Contains(low, "plugin extensibility is library-only") {
			t.Error("the plugin host appears to be SERVED now, but limitations.md still discloses plugin extensibility as library-only — update the disclosure (EXC-WIRE-05 closed)")
		}
		return
	}

	// Not served: the honest disclosure must be present, cite the finding, and link the epic.
	for _, m := range []string{"plugin extensibility is library-only", "cannot load a third-party plugin", "arch-007"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the library-only plugin host (missing marker %q)", m)
		}
	}
	if !strings.Contains(lim, "EXC-WIRE-05") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-05 for the plugin host (ARCH-007)")
	}
	// Over-claim guard: do not claim plugin extensibility is served/production.
	for _, oc := range []string{"plugin extensibility is served", "ca-via-plugin is served", "connector-via-plugin is served"} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims plugin extensibility as served (%q) while the binary does not import the host", oc)
		}
	}
}

// repoHasFIPSBuildTarget reports whether the repository defines any FIPS-validated
// build path — a boringcrypto build target, a GOEXPERIMENT=boringcrypto invocation,
// or a //go:build boringcrypto-tagged file. Today none exists (PKIGOV-007): the
// default build uses Go's standard crypto, not a CMVP-validated module. When a
// future change adds a validated-module build target (EXC-CRYPTO-01), this flips
// true, forcing the "no FIPS build" disclosure to be retired.
func repoHasFIPSBuildTarget(t *testing.T) bool {
	t.Helper()
	for _, f := range []string{"../Makefile", "../go.mod"} {
		b, err := os.ReadFile(filepath.FromSlash(f))
		if err != nil {
			continue
		}
		s := strings.ToLower(string(b))
		if strings.Contains(s, "boringcrypto") || strings.Contains(s, "goexperiment=boringcrypto") {
			return true
		}
	}
	// A build-tagged FIPS source file anywhere under internal/crypto would also count.
	matches, _ := filepath.Glob(filepath.FromSlash("../internal/crypto/*fips*.go"))
	return len(matches) > 0
}

// TestFIPSBuildDisclosedAsUnavailable is the reality-bound disclosure for
// PKIGOV-007: there is no FIPS-validated build path today. While the repo has no
// boringcrypto/validated-module target, compliance.md must disclose FIPS as not
// available and link EXC-CRYPTO-01; if a future change adds a validated build
// target, the stale "not available" disclosure must be retired.
func TestFIPSBuildDisclosedAsUnavailable(t *testing.T) {
	comp := read(t, "compliance.md")
	low := strings.ToLower(comp)

	if repoHasFIPSBuildTarget(t) {
		if strings.Contains(low, "no fips-validated build path today") {
			t.Error("a FIPS build target appears to exist now, but compliance.md still says none does — update the disclosure (EXC-CRYPTO-01 closed)")
		}
		return
	}
	for _, m := range []string{"no fips-validated build path", "boringcrypto"} {
		if !strings.Contains(low, m) {
			t.Errorf("compliance.md must disclose FIPS as unavailable (missing marker %q)", m)
		}
	}
	if !strings.Contains(comp, "EXC-CRYPTO-01") {
		t.Error("compliance.md must link the regulated-controls epic EXC-CRYPTO-01 for the FIPS build")
	}
	if !strings.Contains(comp, "PKIGOV-007") {
		t.Error("compliance.md should cite PKIGOV-007 in the FIPS disclosure so the finding is traceable")
	}
}

// TestProtocolDocsNoLongerClaimPlaceholders is the reality-bound guard for
// INTEROP-008: the EST/SCEP/CMP/SPIFFE/SSH protocol packages are complete, tested
// implementations, so their doc.go comments must NOT call themselves placeholders
// ("reserves the package" / "implementation begins"). A regression that re-adds a
// placeholder line fails here, keeping the package docs honest to the code.
func TestProtocolDocsNoLongerClaimPlaceholders(t *testing.T) {
	stale := []string{"reserves the package", "implementation begins"}
	for _, f := range []string{
		"../internal/protocols/doc.go",
		"../internal/protocols/est/doc.go",
		"../internal/protocols/scep/doc.go",
	} {
		src := strings.ToLower(read(t, f))
		for _, phrase := range stale {
			if strings.Contains(src, phrase) {
				t.Errorf("%s still calls a complete, tested protocol a placeholder (%q) — INTEROP-008", f, phrase)
			}
		}
	}
	// The protocols grouping doc must now name CMP (the finding noted it was absent).
	if !strings.Contains(strings.ToLower(read(t, "../internal/protocols/doc.go")), "cmp") {
		t.Error("internal/protocols/doc.go does not mention CMP; INTEROP-008 wants it listed with the other protocols")
	}
}

// TestContinuousFuzzingIsRealNotOverclaimed is the reality-bound guard for
// FUZZ-003: the "wired for OSS-Fuzz / continuous fuzzing" claim must match what
// exists. The signer design doc must NOT assert the hosted OSS-Fuzz project runs
// continuous fuzzing today (the over-claim), and the concrete continuous-fuzzing
// mechanism it points at must EXIST in the repo: a CI fuzz step, a ClusterFuzzLite
// config, and a committed seed corpus. If the hosted project is later onboarded
// (EXC-FUZZ-01), the doc can be updated; until then a re-introduced over-claim or
// a removed mechanism fails here.
func TestContinuousFuzzingIsRealNotOverclaimed(t *testing.T) {
	design := strings.ToLower(read(t, "design/signing-service.md"))

	// The specific over-claim the audit flagged: that OSS-Fuzz (the hosted project)
	// runs continuous fuzzing now. The honest wording references ClusterFuzzLite /
	// the CI fuzz job and tracks hosted onboarding as an epic.
	if strings.Contains(design, "oss-fuzz runs continuous fuzzing") {
		t.Error("signing-service.md still claims the hosted OSS-Fuzz project runs continuous fuzzing (FUZZ-003 over-claim); describe the ClusterFuzzLite/CI mechanism and track hosted onboarding as EXC-FUZZ-01")
	}
	if strings.Contains(design, "wired for oss-fuzz") {
		t.Error("signing-service.md still says 'wired for OSS-Fuzz' (FUZZ-003 over-claim); state what actually runs")
	}

	// The mechanisms the honest claim rests on must exist (code-bound). The
	// verifiable, running layer is the Go-native fuzz-smoke CI job; the
	// .clusterfuzzlite/ config is the OSS-Fuzz-family onboarding artifact
	// (EXC-FUZZ-01 wires the hosted runner once a maintainer can pin its action).
	for _, f := range []string{
		"../.clusterfuzzlite/project.yaml",
		"../.clusterfuzzlite/Dockerfile",
		"../.clusterfuzzlite/build.sh",
	} {
		if _, err := os.Stat(filepath.FromSlash(f)); err != nil {
			t.Errorf("the OSS-Fuzz-readiness ClusterFuzzLite config the docs rest on is missing: %s (FUZZ-003)", f)
		}
	}

	// The per-PR/nightly Go-native smoke job and its make target must exist — this
	// is the continuous-fuzzing layer that actually RUNS in CI today.
	if !strings.Contains(read(t, "../Makefile"), "fuzz-smoke:") {
		t.Error("Makefile no longer defines the fuzz-smoke target (FUZZ-003)")
	}
	ci := strings.ToLower(read(t, "../.github/workflows/ci.yml"))
	if !strings.Contains(ci, "fuzz-smoke") {
		t.Error(".github/workflows/ci.yml no longer runs the fuzz-smoke step (FUZZ-003)")
	}

	// A committed seed corpus must exist (the regression net the finding required:
	// "no committed corpus"). At minimum the CMS-family crashers are committed.
	matches, _ := filepath.Glob(filepath.FromSlash("../internal/*/testdata/fuzz/*/*"))
	deep, _ := filepath.Glob(filepath.FromSlash("../internal/*/*/testdata/fuzz/*/*"))
	if len(matches)+len(deep) == 0 {
		t.Error("no committed fuzz seed corpus found under internal/**/testdata/fuzz (FUZZ-003)")
	}
}

// TestCloneAndImageURLsConsistent: every GitHub/GHCR reference uses the one
// canonical namespace (imfeelingtheagi). The audit flagged trustctl/trustctl vs
// imfeelingtheagi/trustctl drift; this fails if it ever returns.
func TestCloneAndImageURLsConsistent(t *testing.T) {
	files := []string{
		"../README.md",
		"install.md", "uninstall.md", "observability.md",
		"../deploy/docker/README.md", "../deploy/docker/docker-compose.yml",
		"../deploy/kubernetes/daemonset.yaml",
	}
	for _, f := range files {
		body, err := os.ReadFile(filepath.FromSlash(f))
		if err != nil {
			continue // not all referenced files must exist
		}
		s := string(body)
		if strings.Contains(s, "github.com/trustctl/trustctl") {
			t.Errorf("%s uses github.com/trustctl/trustctl; standardize on github.com/imfeelingtheagi/trustctl", f)
		}
		if strings.Contains(s, "ghcr.io/trustctl/trustctl") {
			t.Errorf("%s uses ghcr.io/trustctl/trustctl; standardize on ghcr.io/imfeelingtheagi/trustctl", f)
		}
	}
}

// TestFirstCertDocBackedByRealIssuance: the documented first-cert flow is backed
// by code that mints and records a real certificate, not a stub. This is the
// static companion to the behavioral projections test, and would also have caught
// DRIFT-1 (a hard-coded success screen records no certificate).
func TestFirstCertDocBackedByRealIssuance(t *testing.T) {
	if !strings.Contains(strings.ToLower(read(t, "getting-started.md")), "first cert") {
		t.Error("getting-started.md should document reaching a first certificate")
	}
	code := read(t, "../internal/server/issuance.go")
	if !strings.Contains(code, "ca.issue") || !strings.Contains(code, "RecordCertificate") {
		t.Error("the issuance handler should mint on ca.issue and RecordCertificate (the documented flow must be real)")
	}
}

// --- R2.6: enterprise runbooks & security whitepaper -----------------------

// TestKeyCeremonyRunbookIsReal: the CA key-ceremony runbook documents the real
// m-of-n ceremony the hierarchy manager implements.
func TestKeyCeremonyRunbookIsReal(t *testing.T) {
	lower := strings.ToLower(read(t, "runbooks/key-ceremony.md"))
	for _, term := range []string{"m-of-n", "threshold", "quorum", "custodian"} {
		if !strings.Contains(lower, term) {
			t.Errorf("key-ceremony runbook should cover %q", term)
		}
	}
	code := read(t, "../internal/ca/hierarchy/hierarchy.go")
	for _, sym := range []string{"StartCeremony", "Approve", "ErrQuorumNotMet"} {
		if !strings.Contains(code, sym) {
			t.Errorf("the key-ceremony runbook describes %q but the hierarchy manager no longer implements it", sym)
		}
	}
}

// TestIncidentResponseRunbookCoversEssentials: the incident-response runbook
// covers the essentials for a private CA — key compromise, revocation, rotation,
// and using the audit chain for forensics.
func TestIncidentResponseRunbookCoversEssentials(t *testing.T) {
	lower := strings.ToLower(read(t, "runbooks/incident-response.md"))
	for _, term := range []string{"compromise", "revoc", "rotat", "audit"} {
		if !strings.Contains(lower, term) {
			t.Errorf("incident-response runbook should cover %q", term)
		}
	}
	// The forensic claim is backed by the real tamper-evidence verifier (R2.1).
	if strings.Contains(lower, "verifychain") || strings.Contains(lower, "verify the chain") || strings.Contains(lower, "chain") {
		if !strings.Contains(read(t, "../internal/audit/audit.go"), "VerifyChain") {
			t.Error("the runbook cites audit-chain verification but internal/audit no longer exposes VerifyChain")
		}
	}
}

// TestThreatModelExtendsSigner: the product threat model covers the architectural
// trust boundaries and points at the deeper signer design/threat-model doc.
func TestThreatModelExtendsSigner(t *testing.T) {
	body := read(t, "security/threat-model.md")
	for _, an := range []string{"AN-1", "AN-3", "AN-4"} {
		if !strings.Contains(body, an) {
			t.Errorf("threat-model.md should address the %s trust boundary", an)
		}
	}
	if !strings.Contains(body, "design/signing-service.md") {
		t.Error("threat-model.md should link to the signing-service design/threat-model doc it extends")
	}
	if _, err := os.Stat(filepath.FromSlash("design/signing-service.md")); err != nil {
		t.Fatalf("the signer design doc the threat model extends must exist: %v", err)
	}
}

// TestESTEnrollmentGuide (S8.2): the EST device-enrollment guide documents the
// RFC 7030 endpoints, profile control, and the fail-closed behavior.
func TestESTEnrollmentGuide(t *testing.T) {
	low := strings.ToLower(read(t, "guides/est-enrollment.md"))
	for _, want := range []string{"rfc 7030", "/cacerts", "/simpleenroll", "/simplereenroll", "/csrattrs", "pkcs#7", "profile", "bulkhead"} {
		if !strings.Contains(low, want) {
			t.Errorf("EST guide should cover %q", want)
		}
	}
}

// TestProfileAuthoringGuide (S8.1): the operator guide documents how to author
// versioned, tenant-scoped certificate profiles and the registration-authority
// separation (a requester cannot self-issue).
func TestProfileAuthoringGuide(t *testing.T) {
	low := strings.ToLower(read(t, "guides/profile-authoring.md"))
	for _, want := range []string{"profile", "version", "ra-officer", "certs:issue", "allowed_key_algorithms", "max_validity", "trustctl-cli profiles"} {
		if !strings.Contains(low, strings.ToLower(want)) {
			t.Errorf("profile-authoring guide should cover %q", want)
		}
	}
	if !strings.Contains(low, "cannot self-issue") && !strings.Contains(low, "cannot issue") {
		t.Error("guide must explain the RA separation (a requester cannot self-issue)")
	}
}

// TestVulnerabilityManagementProcess (SF.2): the security process an enterprise
// vendor-risk review expects exists in-repo and is linked. The vulnerability-
// management doc must carry a coordinated-disclosure pointer, a CVE triage flow,
// a patch SLA with per-severity timelines, a security-release/advisory process,
// and a worked end-to-end dry-run against a sample advisory; README and
// SECURITY.md must link to it.
func TestVulnerabilityManagementProcess(t *testing.T) {
	body := read(t, "security/vulnerability-management.md")
	low := strings.ToLower(body)

	// Coordinated disclosure is anchored on SECURITY.md.
	if !strings.Contains(body, "SECURITY.md") || !strings.Contains(low, "coordinated disclosure") {
		t.Error("vulnerability-management.md should reference SECURITY.md and coordinated disclosure")
	}
	// CVE triage and a security-release/advisory process.
	for _, want := range []string{"triage", "advisory", "security release"} {
		if !strings.Contains(low, want) {
			t.Errorf("vulnerability-management.md should document the %q process", want)
		}
	}
	// A patch SLA with every severity and timeline language.
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if !strings.Contains(low, sev) {
			t.Errorf("the patch SLA must cover %q severity", sev)
		}
	}
	if !strings.Contains(low, "sla") || !(strings.Contains(low, "day") || strings.Contains(low, "hour")) {
		t.Error("the patch SLA must state timelines (hours/days) by severity")
	}
	// Worked dry-run against a sample advisory, end to end.
	if !strings.Contains(low, "dry-run") && !strings.Contains(low, "dry run") {
		t.Error("vulnerability-management.md must include a triage dry-run against a sample advisory")
	}

	// Linked from README and SECURITY.md so it is discoverable.
	if !strings.Contains(read(t, "../README.md"), "security/vulnerability-management.md") {
		t.Error("README.md should link to the vulnerability-management process")
	}
	if !strings.Contains(read(t, "../SECURITY.md"), "vulnerability-management.md") {
		t.Error("SECURITY.md should link to the vulnerability-management process")
	}
}

// TestSemanticQueryLayerDesignSpike (SF.6): the catastrophic-risk scoping-boundary
// design spike is committed and complete — it specifies by-construction enforcement
// over AN-1 RLS, enumerates every required leak/abuse vector with a mitigation,
// defines the cost/timeout guard model, and enumerates the adversarial test plan
// SF.7 must pass. This is a design gate (no code behavior), so the test locks the
// design's completeness rather than any runtime behavior.
func TestSemanticQueryLayerDesignSpike(t *testing.T) {
	body := read(t, "design/semantic-query-layer.md")
	low := strings.ToLower(body)

	// By-construction enforcement over the AN-1 floor, not post-filtering.
	for _, want := range []string{"by construction", "withtenant", "post-filtering", "rbac"} {
		if !strings.Contains(low, want) {
			t.Errorf("design must specify %q enforcement", want)
		}
	}
	// Every required leak/abuse vector is enumerated.
	for _, vector := range []string{
		"cross-tenant join", "rbac-scope bypass", "injection",
		"projection-staleness", "cost-exhaustion",
	} {
		if !strings.Contains(low, vector) {
			t.Errorf("design must enumerate the %q vector with a mitigation", vector)
		}
	}
	// Mitigations and the guard model are present.
	for _, want := range []string{"mitigation", "statement_timeout", "deadline", "bulkhead"} {
		if !strings.Contains(low, want) {
			t.Errorf("design must specify %q (cost/timeout guard model)", want)
		}
	}
	// The adversarial test plan SF.7 must pass is defined, incl. the property test.
	if !strings.Contains(low, "adversarial test plan") || !strings.Contains(low, "property-based") {
		t.Error("design must define the adversarial test plan, including the property-based no-leak test")
	}
	// Non-negotiables honored.
	for _, an := range []string{"AN-1", "AN-2", "AN-7"} {
		if !strings.Contains(body, an) {
			t.Errorf("design must honor %s", an)
		}
	}
}

// TestSecretsAtRestDocIsReal cross-checks the credentials-at-rest documentation
// against the code: the docs describe envelope encryption with a KEK, and the
// crypto boundary actually implements Seal/Open.
func TestSecretsAtRestDocIsReal(t *testing.T) {
	cfgDoc := strings.ToLower(read(t, "configuration.md"))
	for _, want := range []string{"envelope", "encrypted at rest", "kek"} {
		if !strings.Contains(cfgDoc, want) {
			t.Errorf("configuration.md should describe credentials at rest (%q)", want)
		}
	}
	if !strings.Contains(read(t, "configuration.md"), "TRUSTCTL_SECRETS_KEK_FILE") {
		t.Error("configuration.md should document the KEK file setting")
	}
	if tm := strings.ToLower(read(t, "security/threat-model.md")); !strings.Contains(tm, "envelope") || !strings.Contains(tm, "at rest") {
		t.Error("threat-model.md should cover secrets at rest (envelope encryption)")
	}
	// The boundary really implements the seal/open the docs rest on.
	code := read(t, "../internal/crypto/seal/seal.go")
	if !strings.Contains(code, "func Seal(") || !strings.Contains(code, "func Open(") {
		t.Error("internal/crypto/seal should implement Seal/Open (the envelope-encryption primitive the docs cite)")
	}
}

// TestSignerCustodyAndTopologyIsReal cross-checks the R3.2 docs against the code
// and deployment: the CA key is documented as persisted/sealed, the signer runs
// as its own Compose service, and the code actually implements persistence.
func TestSignerCustodyAndTopologyIsReal(t *testing.T) {
	cfgDoc := read(t, "configuration.md")
	for _, want := range []string{"TRUSTCTL_SIGNER_MODE", "TRUSTCTL_CA_CERT_FILE", "external", "sealed"} {
		if !strings.Contains(cfgDoc, want) {
			t.Errorf("configuration.md should document the signer topology / CA custody (%q)", want)
		}
	}
	// DR runbook covers recovering the CA key (sealed key store + KEK).
	dr := strings.ToLower(read(t, "disaster-recovery.md"))
	for _, want := range []string{"key store", "kek", "ca key"} {
		if !strings.Contains(dr, want) {
			t.Errorf("disaster-recovery.md should cover CA-key backup/restore (%q)", want)
		}
	}
	// The signer really persists keys (sealed) and reloads them on restart.
	ks := read(t, "../internal/signing/keystore.go")
	if !strings.Contains(ks, "Save") || !strings.Contains(read(t, "../internal/signing/server.go"), "NewPersistentServer") {
		t.Error("the signer should persist keys via a sealed KeyStore + NewPersistentServer")
	}
	// Compose runs the signer as its own service, in external mode.
	compose := read(t, "../deploy/docker/docker-compose.yml")
	for _, want := range []string{"signer:", "trustctl-signer", "TRUSTCTL_SIGNER_MODE: external"} {
		if !strings.Contains(compose, want) {
			t.Errorf("docker-compose.yml should run the signer as its own service (%q)", want)
		}
	}
}

// TestACMEChallengeValidationIsReal cross-checks the R3.3 docs against the code:
// the limitations page must no longer claim "only HTTP-01" is validated, and the
// acme package must implement real DNS-01 and TLS-ALPN-01 validators behind a
// fail-closed multiplexer — with NO accept-everything validator anywhere in the
// production (non-test) build. This is the static companion to the behavioral
// validator tests and closes B9/N3.
func TestACMEChallengeValidationIsReal(t *testing.T) {
	lim := read(t, "limitations.md")
	if strings.Contains(lim, "only HTTP-01") || strings.Contains(lim, "only **HTTP-01**") {
		t.Error("limitations.md still says only HTTP-01 is validated; DNS-01 and TLS-ALPN-01 are real now")
	}
	lower := strings.ToLower(lim)
	for _, want := range []string{"dns-01", "tls-alpn-01"} {
		if !strings.Contains(lower, want) {
			t.Errorf("limitations.md should state that %q is validated for real", want)
		}
	}

	// The acme package really implements all three validators and the fail-closed
	// multiplexer the docs rest on.
	for file, syms := range map[string][]string{
		"../internal/protocols/acme/dns01.go":    {"DNS01Validator", "LookupTXT"},
		"../internal/protocols/acme/tlsalpn.go":  {"TLSALPN01Validator", "acme-tls/1", "ACMEIdentifier"},
		"../internal/protocols/acme/dvmethod.go": {"Validators", "fail closed", "SelectMethod"},
	} {
		code := read(t, file)
		for _, sym := range syms {
			if !strings.Contains(code, sym) {
				t.Errorf("%s should reference %q (the validator the docs describe)", file, sym)
			}
		}
	}

	// No accept-everything validator in any production (non-test) source file: the
	// removal of AcceptAll from a production-reachable path is the heart of B9.
	files, err := filepath.Glob(filepath.FromSlash("../internal/protocols/acme/*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if strings.Contains(read(t, f), "AcceptAll") {
			t.Errorf("%s references AcceptAll in the production build; it must be test-only", f)
		}
	}
}

// TestPluginSandboxClaimIsHonest cross-checks the R3.4 rescope (B8/N2): the docs
// no longer claim the shipped connectors are sandboxed, the in-process trust model
// and its blast radius are documented, and the plugin host genuinely holds no
// privileged handle (it imports neither the store nor the signer) — so the
// sandbox trustctl DOES still advertise, for third-party WASM plugins, is real and
// is proven by a containment test.
func TestPluginSandboxClaimIsHonest(t *testing.T) {
	// (1) No "sandboxed connector(s)" overclaim in the README: the shipped
	// connectors run in-process, not in the WASM sandbox. Whitespace is collapsed
	// first so the phrase is caught even when it wraps across a line.
	readme := strings.Join(strings.Fields(strings.ToLower(read(t, "../README.md"))), " ")
	if strings.Contains(readme, "sandboxed connector") {
		t.Error("README still calls the shipped connectors \"sandboxed\"; they run trusted in-process")
	}

	// (2) The in-process trust model and its blast radius are documented.
	lim := strings.ToLower(read(t, "limitations.md"))
	for _, want := range []string{"in-process", "trusted", "blast radius"} {
		if !strings.Contains(lim, want) {
			t.Errorf("limitations.md should document the in-process plugin trust model (%q)", want)
		}
	}
	tm := strings.ToLower(read(t, "security/threat-model.md"))
	for _, want := range []string{"blast radius", "in-process"} {
		if !strings.Contains(tm, want) {
			t.Errorf("threat-model.md should document the plugin blast radius (%q)", want)
		}
	}

	// (3) The plugin host holds no privileged handle: it imports neither the store
	// (the DB pool) nor the signer, so a plugin on it cannot reach them by
	// construction — the containment the docs claim is structurally real.
	files, err := filepath.Glob(filepath.FromSlash("../internal/pluginhost/*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src := read(t, f)
		for _, forbidden := range []string{"internal/store", "internal/signing"} {
			if strings.Contains(src, forbidden) {
				t.Errorf("%s imports %s; the plugin host must hold no DB pool or signer handle", f, forbidden)
			}
		}
	}

	// (4) The containment guarantee is actually tested with a hostile plugin.
	if !strings.Contains(read(t, "../internal/pluginhost/containment_test.go"), "TestMisbehavingPluginIsContained") {
		t.Error("the plugin host should have a misbehaving-plugin containment test")
	}
}

// TestKubernetesControlPlaneDeploymentIsReal cross-checks the R3.6 deployment
// story: the install docs point at a real control-plane Helm chart (closing the
// "Helm/Operator advertised, only agent manifests" gap), the chart exists with
// the signer isolated, and the Kubernetes Operator is described honestly as
// planned (S15.1) rather than advertised as shipped.
func TestKubernetesControlPlaneDeploymentIsReal(t *testing.T) {
	install := read(t, "install.md")
	// The docs install the control plane via the Helm chart.
	for _, want := range []string{"deploy/helm/trustctl", "helm install"} {
		if !strings.Contains(install, want) {
			t.Errorf("install.md should document the control-plane Helm chart (%q)", want)
		}
	}
	// The chart actually exists, with the signer isolated.
	if _, err := os.Stat(filepath.FromSlash("../deploy/helm/trustctl/Chart.yaml")); err != nil {
		t.Fatalf("the Helm chart the docs cite must exist: %v", err)
	}
	dep := read(t, "../deploy/helm/trustctl/templates/deployment.yaml")
	for _, want := range []string{"trustctl-signer", "/run/trustctl", "readOnlyRootFilesystem"} {
		if !strings.Contains(dep, want) {
			t.Errorf("the chart's deployment should isolate the signer (%q)", want)
		}
	}
	// The Operator is framed as planned (S15.1), not advertised as shipped now.
	combined := strings.ToLower(install + read(t, "limitations.md"))
	if !strings.Contains(combined, "operator") || !strings.Contains(combined, "s15.1") {
		t.Error("docs should describe the Kubernetes Operator as planned for S15.1, not shipped")
	}
}

// TestSSOIsOIDCOnlyAndDisclosed encodes the R4.1 decision (Path B): trustctl's SSO
// is OIDC-only, and SAML 2.0 (PRD F13) is formally rescoped out and DISCLOSED —
// not silently dropped. limitations.md must say so, no shipped doc may claim SAML
// support, and the auth package must not frame SAML as a "planned" login method.
func TestSSOIsOIDCOnlyAndDisclosed(t *testing.T) {
	// (1) limitations.md discloses the OIDC-only scope honestly.
	lim := strings.ToLower(read(t, "limitations.md"))
	disclosed := strings.Contains(lim, "saml") &&
		(strings.Contains(lim, "not supported") || strings.Contains(lim, "oidc only") || strings.Contains(lim, "oidc-only"))
	if !disclosed {
		t.Error("limitations.md should disclose that SSO is OIDC-only and SAML 2.0 is not supported")
	}

	// (2) The SAML disclosure lives only in limitations.md (the canonical scope
	// page). No other shipped doc may mention SAML, which would risk a stray
	// feature claim re-appearing.
	for _, f := range append(allMarkdown(t), "../README.md") {
		if f == "limitations.md" {
			continue
		}
		if strings.Contains(strings.ToLower(read(t, f)), "saml") {
			t.Errorf("%s mentions SAML; the OIDC-only disclosure belongs only in limitations.md", f)
		}
	}

	// (3) The auth package must not frame SAML as a planned/coming login method.
	oidc := strings.ToLower(read(t, "../internal/auth/oidc.go"))
	if strings.Contains(oidc, "planned login method") || strings.Contains(oidc, "saml 2.0 sso is a planned") {
		t.Error("internal/auth/oidc.go still frames SAML as a planned login method; SSO is OIDC-only")
	}
}

// TestSecurityPolicyExists: a SECURITY.md exists at the repo root (GitHub's
// disclosure-policy convention) with a private reporting path and supported
// versions.
func TestSecurityPolicyExists(t *testing.T) {
	body, err := os.ReadFile(filepath.FromSlash("../SECURITY.md"))
	if err != nil {
		t.Fatalf("SECURITY.md should exist at the repo root: %v", err)
	}
	lower := strings.ToLower(string(body))
	for _, term := range []string{"report", "security", "version"} {
		if !strings.Contains(lower, term) {
			t.Errorf("SECURITY.md should cover %q", term)
		}
	}
}

// TestSignerChannelDocumentedAsUDS (R4.6 #1a): the control-plane↔signer channel is
// a peer-authenticated Unix domain socket (SO_PEERCRED, 0600), NOT mTLS — cross-node
// mTLS is the deferred S15.1 item (documented as planned in install/design docs).
// The docs must match the code: no "mTLS, always enabled" overclaim, no "UDS / mTLS"
// hedge on the live channel.
func TestSignerChannelDocumentedAsUDS(t *testing.T) {
	// Code reality: the signer listens on a unix socket and authenticates the peer
	// uid via SO_PEERCRED.
	if !strings.Contains(read(t, "../internal/signing/serve.go"), `net.Listen("unix"`) {
		t.Fatal("signer no longer listens on a unix socket; revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/signing/peercred_linux.go"), "SO_PEERCRED") {
		t.Fatal("signer no longer uses SO_PEERCRED; revisit this reality test")
	}
	// configuration.md must not use the false "mutual-TLS [always enabled]" framing
	// for the signer channel, and must describe the real UDS channel. An honest
	// mention of cross-node mTLS is allowed ONLY as the deferred, not-yet-implemented
	// item (see below) — never as the live transport.
	cfg := read(t, "configuration.md")
	for _, bad := range []string{"mutual-TLS", "mutual TLS"} {
		if strings.Contains(cfg, bad) {
			t.Errorf("configuration.md uses %q for the signer channel; it is a peer-authenticated UDS", bad)
		}
	}
	if !strings.Contains(cfg, "SO_PEERCRED") {
		t.Error("configuration.md should describe the signer channel as a peer-authenticated UDS (SO_PEERCRED)")
	}
	if !strings.Contains(cfg, "peer-authenticated") {
		t.Error("configuration.md should call the signer channel a peer-authenticated UDS")
	}
	// If mTLS is mentioned at all, it must be disclosed as the deferred (S15.1),
	// not-yet-implemented cross-node option — never framed as live or always-on.
	if strings.Contains(cfg, "mTLS") {
		low := strings.ToLower(cfg)
		if !strings.Contains(low, "deferred") || !strings.Contains(low, "not yet implemented") {
			t.Error("configuration.md mentions mTLS but does not disclose it as the deferred, not-yet-implemented cross-node option")
		}
		if strings.Contains(low, "always enabled") {
			t.Error("configuration.md frames the signer mTLS channel as always enabled (false; the live channel is UDS)")
		}
	}
	// The architecture diagram and threat model must not hedge the implemented local
	// channel as "UDS / mTLS" (cross-node mTLS is future S15.1, marked planned).
	if strings.Contains(read(t, "../README.md"), "UDS / mTLS") {
		t.Error("README architecture diagram hedges the signer channel as 'UDS / mTLS'; the implemented channel is UDS")
	}
	if strings.Contains(read(t, "security/threat-model.md"), "UDS/mTLS") {
		t.Error("threat-model.md hedges the signer channel as 'UDS/mTLS'; the implemented channel is UDS")
	}
}

// TestSignerCAKeyDocumentedAsPersisted (R4.6 #1b): post-R3.2 the signer seals and
// persists the CA key and preserves it across restart. The runbook and threat model
// must not say it regenerates on restart, nor that it is RAM-only/not persisted.
func TestSignerCAKeyDocumentedAsPersisted(t *testing.T) {
	// Code reality: the signer keystore seals keys at rest.
	if !strings.Contains(read(t, "../internal/signing/keystore.go"), "seal") {
		t.Fatal("signer keystore no longer seals keys; revisit this reality test")
	}
	ir := strings.ToLower(read(t, "runbooks/incident-response.md"))
	if strings.Contains(ir, "regenerates its ca") {
		t.Error("incident-response.md still says the signer regenerates its CA key on restart (false post-R3.2)")
	}
	if !strings.Contains(ir, "rotat") {
		t.Error("incident-response.md should give a deliberate CA rotation procedure")
	}
	if strings.Contains(read(t, "security/threat-model.md"), "RAM-generated and not") {
		t.Error("threat-model.md still says the CA key is RAM-generated and not persisted (false post-R3.2)")
	}
}

// TestLicenseStatusIsConsistent (R4.6 #1c; updated): README and docs/index state the
// same current license status — source-available but NOT open-source, the license
// undecided, no license file published yet, all rights reserved — without claiming a
// specific license or calling the project open-source.
func TestLicenseStatusIsConsistent(t *testing.T) {
	for name, body := range map[string]string{
		"README.md":     strings.ToLower(read(t, "../README.md")),
		"docs/index.md": strings.ToLower(read(t, "index.md")),
	} {
		for _, want := range []string{"source-available", "not open-source", "all rights reserved"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s should state the current license status (missing %q): source-available but not open-source, license undecided, all rights reserved", name, want)
			}
		}
		if strings.Contains(body, "open-source edition") {
			t.Errorf("%s must not call trustctl an \"open-source edition\" — it is source-available, not OSS", name)
		}
	}
}

// TestOpenAPISpecIsAdvertised (R4.6 #2): the served OpenAPI 3.1 spec
// (/api/v1/openapi.json) is advertised to users, and the route exists in the API.
func TestOpenAPISpecIsAdvertised(t *testing.T) {
	if !strings.Contains(read(t, "../internal/api/api.go"), "/api/v1/openapi.json") {
		t.Fatal("the API no longer serves /api/v1/openapi.json; revisit this reality test")
	}
	if !strings.Contains(read(t, "../README.md"), "openapi.json") && !strings.Contains(read(t, "cli.md"), "openapi.json") {
		t.Error("the served OpenAPI spec /api/v1/openapi.json is not advertised in README or the CLI/API docs")
	}
}

// TestPQCAlgorithmsDisclosed (R4.7, reconciled to Path B): the docs disclose
// trustctl's real post-quantum posture and it matches the code. The crypto boundary
// (AN-3) provides ML-DSA, ML-KEM, and a hybrid scheme (internal/crypto/pqc) AND
// SLH-DSA / SPHINCS+ signing (FIPS 205, internal/crypto/slhdsa.go, via CIRCL),
// delivered in the Epoch-14 PQC-migration work. SLH-DSA signing is therefore a
// SUPPORTED algorithm, so limitations.md must disclose it as available — not as
// deferred. If SLH-DSA signing is ever removed from the crypto boundary this reverts
// to Path A and the disclosure must say "deferred" again.
func TestPQCAlgorithmsDisclosed(t *testing.T) {
	// Code reality: ML-DSA / ML-KEM / hybrid schemes exist behind the AN-3 boundary.
	pqc := read(t, "../internal/crypto/pqc/pqc.go")
	for _, want := range []string{"MLDSA", "MLKEM", "HybridEd25519Dilithium3"} {
		if !strings.Contains(pqc, want) {
			t.Fatalf("internal/crypto/pqc no longer provides %q; revisit this reality test", want)
		}
	}
	// Code reality: the CBOM scanner recognizes SLH-DSA as a post-quantum algorithm.
	if !strings.Contains(read(t, "../internal/cbom/classify.go"), "SLH-DSA") {
		t.Fatal("the CBOM classifier no longer recognizes SLH-DSA; revisit this reality test")
	}
	// Code reality (Path B): SLH-DSA signing IS implemented behind the AN-3 boundary.
	slh := read(t, "../internal/crypto/slhdsa.go")
	for _, want := range []string{"GenerateSLHDSAKey", "SLHDSASigner", "circl/sign/slhdsa"} {
		if !strings.Contains(slh, want) {
			t.Fatalf("internal/crypto/slhdsa.go no longer provides %q; if SLH-DSA signing was removed this is Path A again — restore the deferred disclosure and revert this test", want)
		}
	}
	// Docs reality: limitations.md names the supported set, including SLH-DSA (FIPS 205).
	lim := read(t, "limitations.md")
	for _, want := range []string{"ML-DSA", "ML-KEM", "SLH-DSA", "FIPS 205"} {
		if !strings.Contains(lim, want) {
			t.Errorf("limitations.md should name %q in the post-quantum disclosure", want)
		}
	}
	// Docs honesty: now that SLH-DSA signing is implemented, the disclosure must NOT
	// still carry the stale Path-A claim that it is deferred / not offered.
	low := strings.ToLower(lim)
	for _, stale := range []string{"slh-dsa is deferred", "not offered as an issuance algorithm", "cannot itself issue under it"} {
		if strings.Contains(low, stale) {
			t.Errorf("limitations.md still carries the stale Path-A claim %q; SLH-DSA signing is implemented now", stale)
		}
	}
}
