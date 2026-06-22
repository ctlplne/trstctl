package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAPITokenPrefixMatchesCode is the DOCS-002 reality-test: the API-token prefix
// the docs tell users to expect must equal the constant the code actually mints and
// resolves (auth.TokenPrefix == "trst_"). The audit caught two pages documenting the
// stale "trstctl_pat_" prefix while the code uses "trst_"; this binds the docs to the
// constant so the two cannot drift again. It asserts (1) the code constant is "trst_",
// (2) no shipped doc still references the stale prefix, and (3) the pages that show a
// token example use the real prefix.
func TestAPITokenPrefixMatchesCode(t *testing.T) {
	// (1) The source of truth: internal/auth defines TokenPrefix = "trst_".
	tok := read(t, "../internal/auth/token.go")
	m := regexp.MustCompile(`TokenPrefix\s*=\s*"([^"]+)"`).FindStringSubmatch(tok)
	if m == nil {
		t.Fatal("internal/auth/token.go no longer defines TokenPrefix; revisit this reality test (DOCS-002)")
	}
	prefix := m[1]
	if prefix != "trst_" {
		t.Fatalf("auth.TokenPrefix = %q, expected \"trst_\"; update the docs and this test together (DOCS-002)", prefix)
	}

	// (2) No shipped doc (or README) may reference the stale trstctl_pat_ prefix.
	for _, f := range append(allMarkdown(t), "../README.md") {
		if strings.Contains(read(t, f), "trstctl_pat_") {
			t.Errorf("%s references the stale API-token prefix trstctl_pat_; the code mints %q (DOCS-002)", f, prefix)
		}
	}

	// (3) The pages that demonstrate a token use the real prefix.
	for _, f := range []string{"cli.md", "getting-started.md"} {
		body := read(t, f)
		if !strings.Contains(body, prefix) {
			t.Errorf("%s should show the real API-token prefix %q in its examples (DOCS-002)", f, prefix)
		}
	}
}

// TestTSAWireFormatDocMatchesCode is the DOCS-003 reality-test: INTEROP-005 made the
// TSA emit a real RFC 3161 CMS TimeStampToken (not a bespoke JSON manifest), so the
// feature page must no longer claim the wire format is "signed JSON". It binds the
// doc to the code: while crypto.BuildTimeStampToken / EncodeTSTInfo exist and the TSA
// builds a CMS token, the page's "RFC 3161" mention must co-occur with the real CMS
// framing and must not carry the stale "encodes TSTInfo as signed JSON" wire claim.
func TestTSAWireFormatDocMatchesCode(t *testing.T) {
	// Code reality: the crypto boundary builds an RFC 3161 CMS TimeStampToken, and
	// the TSA uses it as the wire artifact.
	cr := read(t, "../internal/crypto/tsa.go")
	for _, want := range []string{"func EncodeTSTInfo(", "func BuildTimeStampToken("} {
		if !strings.Contains(cr, want) {
			t.Fatalf("internal/crypto/tsa.go no longer provides %q; if the CMS TSA was removed, restore the JSON disclosure and revert this test (DOCS-003/INTEROP-005)", want)
		}
	}
	tsa := read(t, "../internal/tsa/tsa.go")
	if !strings.Contains(tsa, "EncodeTSTInfo") || !strings.Contains(tsa, "application/timestamp-reply") {
		t.Fatal("internal/tsa no longer builds a CMS TimeStampToken / serves application/timestamp-reply; revisit this reality test (DOCS-003)")
	}

	page := read(t, "features/code-signing-and-timestamping.md")
	low := strings.ToLower(page)
	// The stale over-disclosure must be gone: the TSA does NOT encode TSTInfo as
	// signed JSON on the wire anymore.
	if strings.Contains(low, "tsa encodes `tstinfo` as signed json") || strings.Contains(low, "encodes tstinfo as signed json") {
		t.Error("the code-signing/TSA feature page still says the TSA encodes TSTInfo as signed JSON; INTEROP-005 emits a real RFC 3161 CMS TimeStampToken now (DOCS-003)")
	}
	// And the page must describe the real CMS wire format.
	if !strings.Contains(low, "rfc 3161") {
		t.Error("the feature page should reference RFC 3161 for the TSA (DOCS-003)")
	}
	for _, want := range []string{"cms", "timestamp-reply"} {
		if !strings.Contains(low, want) {
			t.Errorf("the feature page should describe the real RFC 3161 CMS wire format (missing %q) (DOCS-003)", want)
		}
	}
}

// TestConnectorCountMatchesCode is the DOCS-004 reality-test: the documented
// deployment-connector count must equal the number of real connector packages under
// internal/connector/ (excluding the `example` sample). The audit caught
// limitations.md undercounting as ~10-11 while README and the code have 13. This
// counts the directories and asserts limitations.md and README both state that
// number, and that the appliance connectors the old text omitted are named.
func TestConnectorCountMatchesCode(t *testing.T) {
	entries, err := os.ReadDir(filepath.FromSlash("../internal/connector"))
	if err != nil {
		t.Fatalf("read internal/connector: %v (DOCS-004)", err)
	}
	var real []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "example" {
			continue
		}
		real = append(real, e.Name())
	}
	count := len(real)
	if count == 0 {
		t.Fatal("found no connector packages under internal/connector (DOCS-004)")
	}
	countStr := itoa(count)

	// limitations.md and README must state the real count ON THE LINE that talks
	// about the connector set — not merely have the digits appear somewhere in the
	// file (e.g. a port number). This catches the audit's exact bug: limitations.md
	// said "~10-11 under internal/connector/" while the real count is 13.
	for _, f := range []string{"limitations.md", "../README.md"} {
		body := read(t, f)
		if !lineWithAll(body, countStr, "connector") {
			t.Errorf("%s should state the real connector count (%s) on a line describing the connector set (DOCS-004)", f, countStr)
		}
	}

	// The stale "~10-11" wording the finding flagged must be gone from limitations.md.
	limRaw := read(t, "limitations.md")
	for _, stale := range []string{"~10–11 under", "~10-11 under", "10–11 under `internal/connector", "10-11 under `internal/connector"} {
		if strings.Contains(limRaw, stale) {
			t.Errorf("limitations.md still undercounts connectors (%q); the real count is %s (DOCS-004)", stale, countStr)
		}
	}

	// The appliance connectors the old text omitted must now be named in
	// limitations.md (if they exist in code).
	lim := strings.ToLower(limRaw)
	for _, appliance := range []struct{ dir, name string }{
		{"cisco", "cisco"},
		{"fortigate", "fortigate"},
		{"paloalto", "palo alto"},
	} {
		if containsDir(real, appliance.dir) && !strings.Contains(lim, appliance.name) {
			t.Errorf("internal/connector/%s exists but limitations.md does not name the %q connector (DOCS-004)", appliance.dir, appliance.name)
		}
	}
}

// lineWithAll reports whether any single line of body contains every substring in
// subs (case-insensitive on the line, exact on each sub except case).
func lineWithAll(body string, subs ...string) bool {
	for _, line := range strings.Split(body, "\n") {
		low := strings.ToLower(line)
		ok := true
		for _, s := range subs {
			if !strings.Contains(low, strings.ToLower(s)) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestChangelogExistsAndIsLinked is the DOCS-005 reality-test: a CHANGELOG.md exists
// at the repo root, is in Keep-a-Changelog shape (has an Unreleased section and at
// least one tagged version), backfills the existing git tags, and is referenced from
// both the README and SECURITY.md so a reader can find the release history.
func TestChangelogExistsAndIsLinked(t *testing.T) {
	cl, err := os.ReadFile(filepath.FromSlash("../CHANGELOG.md"))
	if err != nil {
		t.Fatalf("CHANGELOG.md should exist at the repo root (DOCS-005): %v", err)
	}
	body := string(cl)
	low := strings.ToLower(body)
	if !strings.Contains(low, "## [unreleased]") {
		t.Error("CHANGELOG.md should have an Unreleased section (Keep a Changelog) (DOCS-005)")
	}
	// Backfilled tags: the latest tag must be present.
	if !strings.Contains(body, "[0.5.0]") {
		t.Error("CHANGELOG.md should backfill the tagged versions (e.g. 0.5.0) (DOCS-005)")
	}
	// Referenced from README and SECURITY.md.
	if !strings.Contains(read(t, "../README.md"), "CHANGELOG.md") {
		t.Error("README.md should link to CHANGELOG.md (DOCS-005)")
	}
	if !strings.Contains(read(t, "../SECURITY.md"), "CHANGELOG.md") {
		t.Error("SECURITY.md should link to CHANGELOG.md (DOCS-005)")
	}
}

// TestServedSurfaceDocsMatchCodeReality is the DOCS-001/DOCS-002/DOCS-005 drift
// guard for surfaces that recently moved from library-only to served: OIDC, the
// embedded web UI, graph/risk, AI/RCA/MCP, public revocation, the isolated signer
// transport, and the minimal Kubernetes Operator. If the route/config anchors are in
// code, the docs must not keep telling operators those surfaces are unwired.
func TestServedSurfaceDocsMatchCodeReality(t *testing.T) {
	api := read(t, "../internal/api/api.go")
	server := read(t, "../internal/server/server.go")
	webIndex := read(t, "../internal/webui/dist/index.html")

	requireAnchor := func(name, body string, needles ...string) {
		t.Helper()
		for _, needle := range needles {
			if !strings.Contains(body, needle) {
				t.Fatalf("%s no longer contains %q; revisit this docs reality test", name, needle)
			}
		}
	}

	requireAnchor("internal/api/api.go", api,
		`path: "/api/v1/ai/query"`,
		`path: "/api/v1/ai/rca"`,
		`path: "/api/v1/mcp/tools"`,
		`path: "/api/v1/graph"`,
		`path: "/api/v1/risk/credentials"`,
		`mux.HandleFunc("GET /auth/login"`,
	)
	requireAnchor("internal/server/server.go", server,
		"api.WithAISurface",
		`mux.Handle("/auth/"`,
		`mux.Handle("/api/v1/graph"`,
		`mux.Handle("/api/v1/risk/"`,
		`mux.Handle("/ocsp/"`,
		`mux.Handle("/crl/"`,
	)
	requireAnchor("internal/webui/dist/index.html", webIndex, "assets/index-", "<script")
	requireAnchor("internal/signing/serve.go", read(t, "../internal/signing/serve.go"), "ServeServerMTLS")
	requireAnchor("internal/signing/client.go", read(t, "../internal/signing/client.go"), "DialMTLS")
	if _, err := os.Stat(filepath.FromSlash("../cmd/trstctl-operator")); err != nil {
		t.Fatalf("cmd/trstctl-operator should exist while install docs describe a shipped minimal operator: %v", err)
	}

	platform := strings.ToLower(read(t, "features/platform-and-api.md"))
	for _, stale := range []string{
		"library / not yet served",
		"interactive oidc login is not wired",
		"web console and `/auth/login` are not yet served",
		"trstctl_oidc_",
	} {
		if strings.Contains(platform, stale) {
			t.Errorf("features/platform-and-api.md still carries stale served-surface wording %q", stale)
		}
	}
	for _, want := range []string{
		"served by the binary",
		"/auth/login",
		"trstctl_auth_oidc_issuer",
		"trstctl_auth_oidc_client_id",
		"trstctl_auth_oidc_redirect_uri",
	} {
		if !strings.Contains(platform, want) {
			t.Errorf("features/platform-and-api.md should document served OIDC/web reality (missing %q)", want)
		}
	}

	graphAI := strings.ToLower(read(t, "features/graph-query-ai.md"))
	for _, want := range []string{
		"/api/v1/graph",
		"/api/v1/ai/query",
		"/api/v1/ai/rca",
		"/api/v1/mcp/tools",
		"ai.enable_api",
		"read-only",
	} {
		if !strings.Contains(graphAI, want) {
			t.Errorf("features/graph-query-ai.md should document the served graph/AI/MCP surface (missing %q)", want)
		}
	}
	for _, stale := range []string{
		"mcp server` | library",
		"grounded rca / nl query` | library",
		"not yet served by the binary",
	} {
		if strings.Contains(graphAI, stale) {
			t.Errorf("features/graph-query-ai.md still frames a served AI/MCP surface as library-only (%q)", stale)
		}
	}

	lim := strings.ToLower(read(t, "limitations.md"))
	for _, want := range []string{
		"/api/v1/graph",
		"/api/v1/risk/credentials",
		"/api/v1/ai/query",
		"/api/v1/ai/rca",
		"/api/v1/mcp/tools",
		"ai.enable_api",
	} {
		if !strings.Contains(lim, want) {
			t.Errorf("limitations.md should name the served graph/risk/AI/MCP routes (missing %q)", want)
		}
	}
	for _, stale := range []string{
		"posture**: the **credential graph",
		"risk scoring read apis are not yet served",
		"ai/rca/mcp**: the packages",
		"oidc**, **web console**, and **ai/rca/mcp** are covered in",
	} {
		if strings.Contains(lim, stale) {
			t.Errorf("limitations.md still groups a served surface into the not-yet-served bucket (%q)", stale)
		}
	}

	incident := strings.ToLower(read(t, "runbooks/incident-response.md"))
	for _, want := range []string{"/api/v1/graph/blast-radius/{id}", "/ocsp/{tenant}", "/crl/{tenant}", "served revocation surface"} {
		if !strings.Contains(incident, want) {
			t.Errorf("incident-response.md should document served graph/revocation reality (missing %q)", want)
		}
	}
	for _, stale := range []string{"crl/ocsp is library-only", "graph is library-only", "not yet served"} {
		if strings.Contains(incident, stale) {
			t.Errorf("incident-response.md still contains stale library-only language (%q)", stale)
		}
	}

	for _, f := range []string{"install.md", "disaster-recovery.md", "../deploy/helm/trstctl/values.yaml"} {
		body := strings.ToLower(read(t, f))
		for _, stale := range []string{
			"isolated signer is not yet implemented",
			"isolated mode not yet implemented",
			"not-yet-built isolated signer",
			"still-deferred isolated signer",
		} {
			if strings.Contains(body, stale) {
				t.Errorf("%s still says isolated signer mode is deferred even though signer mTLS is implemented (%q)", f, stale)
			}
		}
	}

	install := strings.ToLower(read(t, "install.md"))
	if !strings.Contains(install, "cmd/trstctl-operator") || !strings.Contains(install, "helm remains") {
		t.Error("install.md should explain the shipped minimal operator and that Helm remains the full install path")
	}
}

// TestKeyPackagesHaveLeafClaudeMd is the CODE-004 reality-test: the hub-and-spoke
// per-package CLAUDE.md convention (root CLAUDE.md §4) is actually followed for the
// internal packages that carry significant local invariants — the AN-3 crypto
// boundary, the AN-4 signer, the protocol servers, and the semantic-query scoping
// layer. Each named package must exist and carry a non-stub leaf CLAUDE.md. The
// audit flagged that only 1 of 74 packages followed the convention; this keeps the
// high-value leaves present so the guidance for those packages is local and current.
func TestKeyPackagesHaveLeafClaudeMd(t *testing.T) {
	for _, pkg := range []string{
		"crypto",    // AN-3 boundary (CRYPTO-*)
		"signing",   // AN-4 isolated signer (SIGNER-*)
		"protocols", // issuance/enrollment protocol servers (INTEROP-*)
		"query",     // semantic-query scoping layer (the pre-existing example)
	} {
		dir := filepath.FromSlash("../internal/" + pkg)
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("internal/%s no longer exists; revisit this reality test (CODE-004): %v", pkg, err)
			continue
		}
		f := filepath.Join(dir, "CLAUDE.md")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("internal/%s should carry a leaf CLAUDE.md capturing its package-specific rules (CODE-004): %v", pkg, err)
			continue
		}
		if len(strings.TrimSpace(string(b))) < 200 || !strings.Contains(string(b), "#") {
			t.Errorf("internal/%s/CLAUDE.md is too short/stub to be a real per-package guide (CODE-004)", pkg)
		}
	}
}

func TestKeyPackagesHaveAgentsMdShims(t *testing.T) {
	required := []string{
		"../AGENTS.md",
		"../internal/crypto/AGENTS.md",
		"../internal/signing/AGENTS.md",
		"../internal/protocols/AGENTS.md",
		"../internal/query/AGENTS.md",
	}
	for _, f := range required {
		b, err := os.ReadFile(filepath.FromSlash(f))
		if err != nil {
			t.Errorf("%s must exist so AGENTS.md-only tools load the package rules (CODE-006): %v", f, err)
			continue
		}
		text := string(b)
		if len(strings.TrimSpace(text)) < 120 || !strings.Contains(text, "AGENTS.md") {
			t.Errorf("%s is too short/stub to be a useful AGENTS.md instruction file (CODE-006)", f)
		}
	}

	legacyFiles, err := filepath.Glob(filepath.FromSlash("../internal/*/CLAUDE.md"))
	if err != nil {
		t.Fatalf("glob legacy package rules: %v", err)
	}
	if len(legacyFiles) == 0 {
		t.Fatal("expected at least one legacy CLAUDE.md package rule file to guard")
	}
	for _, legacy := range legacyFiles {
		agentFile := filepath.Join(filepath.Dir(legacy), "AGENTS.md")
		if _, err := os.Stat(agentFile); err != nil {
			t.Errorf("%s has legacy package rules but no sibling AGENTS.md shim (CODE-006): %v", legacy, err)
		}
	}
}

// TestServedProtocolDocsNotStaleNotMounted is the CODE-004 reality-test for the
// served issuance/enrollment protocol packages: their package doc.go headers must not
// keep telling readers the handler is "not yet mounted" / "not mounted" once
// internal/server/protocol_mounts.go actually mounts it on the served listener. The
// EST/SCEP/CMP handlers ARE wired in (EXC-WIRE-02) via servedProtocols.routes; a
// stale not-served claim in their doc comment is drift that this guard fails closed.
// Served/not-served claims are kept distinct from durable-state caveats: a doc may
// still describe transport-key / shared-storage caveats, but may not deny that the
// handler is served while the mount code anchors are present.
func TestServedProtocolDocsNotStaleNotMounted(t *testing.T) {
	// Code anchor: protocol_mounts.go must still construct AND route the EST/SCEP
	// handlers, otherwise the "served" disclosure has lost its anchor and this guard
	// should be revisited rather than silently passing.
	mounts := read(t, "../internal/server/protocol_mounts.go")
	for _, anchor := range []string{
		"sp.est = est.New(",
		"sp.scep = scep.New(",
		"func (sp *servedProtocols) routes(",
		"mux.Handle(pattern, wrap(h))",
	} {
		if !strings.Contains(mounts, anchor) {
			t.Fatalf("internal/server/protocol_mounts.go no longer contains %q; the EST/SCEP served-vs-library disclosure has lost its code anchor — revisit this reality test (CODE-004)", anchor)
		}
	}

	// Reality check: the doc.go of each served protocol package must not carry a stale
	// "not yet mounted" / "not mounted" served-claim. (The durable-state caveat wording
	// — sealed transport key, shared persistent storage — is allowed and is NOT one of
	// these phrases.)
	stalePhrases := []string{"not yet mounted", "not mounted"}
	for _, rel := range []string{
		"../internal/protocols/est/doc.go",
		"../internal/protocols/scep/doc.go",
	} {
		body := strings.ToLower(read(t, rel))
		for _, stale := range stalePhrases {
			if strings.Contains(body, stale) {
				t.Errorf("%s still claims the handler is %q, but internal/server/protocol_mounts.go mounts it on the served listener (EXC-WIRE-02) — update the package doc (CODE-004)", rel, stale)
			}
		}
		// Positive anchor: the doc should now disclose that the handler is served/mounted.
		if !strings.Contains(body, "mounted") && !strings.Contains(body, "served") {
			t.Errorf("%s no longer discloses that the handler is served/mounted; the served-vs-library status must stay current (CODE-004)", rel)
		}
	}
}

// itoa renders a small non-negative int without importing strconv into this test's
// already-small surface.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// containsDir reports whether name is in dirs.
func containsDir(dirs []string, name string) bool {
	for _, d := range dirs {
		if d == name {
			return true
		}
	}
	return false
}
