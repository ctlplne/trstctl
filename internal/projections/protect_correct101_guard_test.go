package projections_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// CORRECT-101 (15-CORRECT) PROTECT regression guard.
//
// Confirmed strength: the served issue/renew/revoke/OCSP/CRL paths PLUS idempotent
// replay have real end-to-end coverage. The anchor is
// internal/projections/issuance_e2e_test.go, which proves (a) a certificate appears
// in the inventory after a real issuance through the assembled control plane and a
// real out-of-process signer, and (b) an idempotent replay of the same mutation does
// NOT mint or record a second certificate (the fingerprint is unchanged).
//
// This is an ANCHOR-LOCK, not a behavioral re-run: the e2e test it protects stands up
// embedded Postgres + NATS + a signer child and is gated out under -short, so it
// cannot be the guard itself within the <30s PG-free budget. Instead this guard reads
// the real e2e source file and asserts the two load-bearing assertions are still
// present and wired the way the strength describes. If a future edit deletes the
// "inventory appears after issuance" assertion or the "idempotent replay keeps one
// cert / same fingerprint" assertion, this guard goes RED — locking the strength so
// the e2e proof cannot be silently gutted while the file still compiles.
func TestProtectCORRECT101_IssuanceAndIdempotentReplayE2EAnchorIntact(t *testing.T) {
	const anchor = "issuance_e2e_test.go"
	src, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatalf("CORRECT-101 anchor: cannot read %s (the served issue/renew/revoke e2e proof must exist in this package): %v", anchor, err)
	}
	body := string(src)

	// The e2e test must drive the real assembled control plane (not a mock) and run
	// the outbox so the ca.issue handler actually mints through the signer.
	mustContainAll(t, "CORRECT-101", body, []string{
		"server.Build(",        // assembles the real control plane
		"Signer:",              // with a real signer wired in
		"/api/v1/identities/",  // drives a served lifecycle transition
		"/transitions",         // the issued transition that enqueues ca.issue
		`"to":"issued"`,        // the requested->issued transition
		".Drain(",              // runs the outbox (the real ca.issue handler mints)
		"/api/v1/certificates", // reads the served inventory
	})

	// (a) Inventory appears after issuance: empty before, exactly one minted cert after.
	mustContainAll(t, "CORRECT-101 (issuance -> inventory)", body, []string{
		"inventory should be empty before issuance",
		"want 1 (the flagship flow must mint one)",
		"fingerprint", // a real minted cert carries a fingerprint
	})

	// (b) Idempotent replay: a second identical transition + drain must not mint a
	// second certificate, and the fingerprint must be unchanged.
	mustContainAll(t, "CORRECT-101 (idempotent replay)", body, []string{
		"idempotent replay",
		"want still 1",
		"idempotent replay changed the issued certificate fingerprint",
	})

	// Lock the shape of the "still exactly one cert after replay" assertion: the test
	// must compare the replayed inventory length against 1, not against a looser bound.
	replayLenOne := regexp.MustCompile(`len\(replayed\)\s*!=\s*1`)
	if !replayLenOne.MatchString(body) {
		t.Errorf("CORRECT-101: idempotent-replay assertion no longer checks len(replayed) != 1; the at-most-once issuance guarantee is no longer locked in %s", anchor)
	}

	// Defense against a hollow edit: the assertion bodies must still reference the
	// recorded first fingerprint to detect a *changed* cert on replay.
	if !strings.Contains(body, "firstFingerprint") {
		t.Errorf("CORRECT-101: %s no longer captures firstFingerprint to compare across the idempotent replay; replay-stability is unguarded", anchor)
	}
}

// mustContainAll fails the test (with the finding id) for each needle missing from body.
func mustContainAll(t *testing.T, id, body string, needles []string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("%s anchor-lock: expected the e2e proof to still contain %q, but it does not (the confirmed strength may have regressed)", id, n)
		}
	}
}
