package docs

import (
	"strings"
	"testing"
)

func TestIdempotencyClaimsTrackComposeE2EReceipt(t *testing.T) {
	compose := read(t, "../scripts/ci/compose-e2e.sh")
	for _, want := range []string{
		"served issuance lifecycle: issue -> idempotent retry -> revoke",
		`IDEM="${IDEM_BASE}-issue"`,
		`issue() { post "$IDEM" "/api/v1/identities/$IDENT/transitions" '{"to":"issued"}'; }`,
		"A retried transition with the SAME Idempotency-Key must NOT mint a second one",
		"AN-5 VIOLATED",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("compose-e2e.sh no longer pins the identity-transition issuance retry receipt; missing %q", want)
		}
	}

	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{
		"compose-e2e:",
		"name: compose e2e + PKI conformance (EXC-GATE-01)",
		"run: bash scripts/ci/compose-e2e.sh",
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml no longer runs the compose E2E issuance retry receipt; missing %q", want)
		}
	}

	for _, doc := range []struct {
		name string
		body string
	}{
		{"README.md", read(t, "../README.md")},
		{"docs/features/issuance-and-cas.md", read(t, "features/issuance-and-cas.md")},
	} {
		low := strings.ToLower(doc.body)
		for _, stale := range []string{
			"a retried request can't accidentally mint two certificates",
			"returns the *same* certificate instead of minting a second one",
		} {
			if strings.Contains(low, stale) {
				t.Errorf("%s still overclaims idempotent issuance while the compose E2E receipt owns that proof (%q)", doc.name, stale)
			}
		}
		for _, want := range []string{
			"identity-transition issuance retry",
			"compose e2e",
			"known an-5 blocker",
		} {
			if !strings.Contains(low, want) {
				t.Errorf("%s must disclose the current identity-transition issuance retry blocker with the compose E2E receipt (missing %q)", doc.name, want)
			}
		}
	}
}
