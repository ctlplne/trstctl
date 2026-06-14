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
