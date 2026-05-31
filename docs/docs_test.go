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
	"troubleshooting.md",
	"cli.md",
	"telemetry.md",
	"guides/plugin-authoring.md",
	"guides/connector-authoring.md",
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

// supportedPlatforms are the platforms certctl ships for; install and uninstall
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
	for _, want := range []string{"/metrics", "/readyz", "traceparent", "certctl_http_requests_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("observability.md should document %q", want)
		}
	}
	// The documented metric is the one the middleware emits.
	mw := read(t, "../internal/observ/middleware.go")
	if !strings.Contains(mw, "certctl_http_requests_total") {
		t.Error("observability.md cites certctl_http_requests_total but the middleware does not emit it")
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
	if !strings.Contains(read(t, "operations.md"), "CERTCTL_RATE_LIMIT_REQUESTS") {
		t.Error("operations.md should document the rate-limit budget setting")
	}
	if code := read(t, "../internal/config/config.go"); !strings.Contains(code, "CERTCTL_RATE_LIMIT_REQUESTS") {
		t.Error("CERTCTL_RATE_LIMIT_REQUESTS is documented but the loader does not read it")
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
	main := read(t, "../cmd/certctl/main.go")
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
		"--migrate-status", "--migrate", "CERTCTL_MIGRATE_AUTO",
		"advisory lock", "forward-only", "pg_advisory_lock", "rollback",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("migrations.md should cover %q", want)
		}
	}
	// The documented flags exist in the binary.
	main := read(t, "../cmd/certctl/main.go")
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
	// The gate (CERTCTL_MIGRATE_AUTO) is honored by config.
	if !strings.Contains(read(t, "../internal/config/config.go"), "CERTCTL_MIGRATE_AUTO") {
		t.Error("the config loader should read CERTCTL_MIGRATE_AUTO (the pre-migration backup gate)")
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
	for _, env := range []string{"CERTCTL_POSTGRES_MODE", "CERTCTL_NATS_URL", "CERTCTL_TELEMETRY_ENABLED", "CERTCTL_SERVER_ADDR", "CERTCTL_AUDIT_SIGNING_KEY_FILE", "CERTCTL_AUDIT_RETENTION", "CERTCTL_RATE_LIMIT_REQUESTS", "CERTCTL_SECRETS_KEK_FILE", "CERTCTL_SIGNER_MODE", "CERTCTL_CA_CERT_FILE"} {
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
	// No-overclaiming: an explicit disclaimer that deploying certctl is not itself
	// compliance/certification.
	if !strings.Contains(lower, "not a claim") && !strings.Contains(lower, "certification is yours") {
		t.Error("compliance.md must explicitly disclaim that certctl alone makes you compliant/certified")
	}
	// Reality cross-check: it points at a setting the config loader actually reads.
	if !strings.Contains(body, "CERTCTL_AUDIT_SIGNING_KEY_FILE") {
		t.Error("compliance.md should reference the persistent audit signing-key setting")
	}
	code := read(t, "../internal/config/config.go")
	if !strings.Contains(code, "CERTCTL_AUDIT_SIGNING_KEY_FILE") {
		t.Error("CERTCTL_AUDIT_SIGNING_KEY_FILE is referenced in docs but the config loader does not read it")
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
// canonical namespace (imfeelingtheagi). The audit flagged certctl/certctl vs
// imfeelingtheagi/certctl drift; this fails if it ever returns.
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
		if strings.Contains(s, "github.com/certctl/certctl") {
			t.Errorf("%s uses github.com/certctl/certctl; standardize on github.com/imfeelingtheagi/certctl", f)
		}
		if strings.Contains(s, "ghcr.io/certctl/certctl") {
			t.Errorf("%s uses ghcr.io/certctl/certctl; standardize on ghcr.io/imfeelingtheagi/certctl", f)
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
	if !strings.Contains(read(t, "configuration.md"), "CERTCTL_SECRETS_KEK_FILE") {
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
	for _, want := range []string{"CERTCTL_SIGNER_MODE", "CERTCTL_CA_CERT_FILE", "external", "sealed"} {
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
	for _, want := range []string{"signer:", "certctl-signer", "CERTCTL_SIGNER_MODE: external"} {
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
// sandbox certctl DOES still advertise, for third-party WASM plugins, is real and
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
	for _, want := range []string{"deploy/helm/certctl", "helm install"} {
		if !strings.Contains(install, want) {
			t.Errorf("install.md should document the control-plane Helm chart (%q)", want)
		}
	}
	// The chart actually exists, with the signer isolated.
	if _, err := os.Stat(filepath.FromSlash("../deploy/helm/certctl/Chart.yaml")); err != nil {
		t.Fatalf("the Helm chart the docs cite must exist: %v", err)
	}
	dep := read(t, "../deploy/helm/certctl/templates/deployment.yaml")
	for _, want := range []string{"certctl-signer", "/run/certctl", "readOnlyRootFilesystem"} {
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

// TestSSOIsOIDCOnlyAndDisclosed encodes the R4.1 decision (Path B): certctl's SSO
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
