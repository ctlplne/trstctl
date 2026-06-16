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
