// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// The custody table is a claim about code, so CI checks it against the code
// (epic B1).
//
// "Private keys never leave your environment" is the kind of sentence that is
// true when it is written and quietly false two releases later. docs/custody.md
// states, per credential kind, who generates the key and whether the control
// plane ever holds it. These tests keep that page tied to the surfaces it
// describes: every kind is listed, the paths that still generate keys in the
// control plane are named as such along with what replaces them, and the CSR
// path that removes one of them is actually wired.

// custodyKinds are the credential kinds the table must account for. Adding a
// credential kind to the product without adding a row here fails the build,
// which is the point: an unlisted kind is an unanswered custody question.
var custodyKinds = []string{
	"ACME leaf",
	"EST leaf",
	"SCEP leaf",
	"CMP leaf",
	"Identity leaf, `subject_csr_pem` supplied",
	"Identity leaf, no CSR supplied",
	"CA root / intermediate",
	"Agent enrollment identity",
	"SSH host / user certificate",
	"SPIFFE X.509-SVID",
	"PKI-as-a-secret",
}

// custodyControlPlaneKeygen are the paths that still generate a subject key
// inside the control plane. Each must be named on the page together with what
// replaces it — a disclosure with no successor is a confession, not a plan.
var custodyControlPlaneKeygen = map[string]string{
	"Identity leaf without a CSR": "subject_csr_pem",
	"SPIFFE X.509-SVID":           "host agent",
	"PKI-as-a-secret":             "brain-local convenience",
}

func TestCustodyTableCoversEveryCredentialKind(t *testing.T) {
	t.Parallel()
	custody := read(t, "custody.md")
	for _, kind := range custodyKinds {
		if !strings.Contains(custody, kind) {
			t.Errorf("docs/custody.md has no row for %q; a credential kind with no custody row is an unanswered question about where its key lives", kind)
		}
	}
}

func TestCustodyTableNamesEveryControlPlaneKeygenPathAndItsSuccessor(t *testing.T) {
	t.Parallel()
	custody := read(t, "custody.md")
	for path, successor := range custodyControlPlaneKeygen {
		if !strings.Contains(custody, path) {
			t.Errorf("docs/custody.md does not name the control-plane keygen path %q", path)
			continue
		}
		if !strings.Contains(custody, successor) {
			t.Errorf("docs/custody.md names %q but not what replaces it (%q); disclosing a custody gap without its successor is a confession, not a plan",
				path, successor)
		}
	}
}

// TestCSRFirstIssuanceIsActuallyWired stops the table from describing a path the
// code does not have. The row that says "no" for a caller-supplied CSR is only
// true if the served surface accepts one and the mint signs it.
func TestCSRFirstIssuanceIsActuallyWired(t *testing.T) {
	t.Parallel()
	for _, want := range []struct{ file, token, why string }{
		{"../internal/api/handlers.go", "SubjectCSRPEM", "the transition request must accept a caller-supplied CSR"},
		{"../internal/api/handlers.go", "validateSubjectCSRPEM", "a malformed CSR must be rejected at the API edge, not in the outbox worker"},
		{"../internal/orchestrator/orchestrator.go", "TransitionWithSubjectCSR", "the CSR must reach the issuance dispatcher on the transition"},
		{"../internal/server/issuance.go", "mintServedLeafFromCSR", "the mint must sign the caller's request instead of generating a key"},
		{"../internal/server/issuance.go", "issuance.server_side_keygen", "the legacy keygen path must record its own deprecation"},
	} {
		body := read(t, want.file)
		if !strings.Contains(body, want.token) {
			t.Errorf("%s does not contain %q: %s", want.file, want.token, want.why)
		}
	}
}

// TestCSRFirstMintReturnsNoKeyMaterial pins the property the custody row depends
// on: the CSR path constructs no private key, so there is nothing to leak,
// wipe, or accidentally encode into a deploy intent.
func TestCSRFirstMintReturnsNoKeyMaterial(t *testing.T) {
	t.Parallel()
	body := read(t, "../internal/server/issuance.go")
	start := strings.Index(body, "func (d *issuanceDispatcher) mintServedLeafFromCSR(")
	if start < 0 {
		t.Fatal("mintServedLeafFromCSR is gone; the custody table's CSR row depends on it")
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatal("cannot delimit mintServedLeafFromCSR")
	}
	fn := body[start : start+end]
	for _, banned := range []string{"GenerateLockedKey", "PrivateKeyPEM", "KeyPEM:"} {
		if strings.Contains(fn, banned) {
			t.Errorf("mintServedLeafFromCSR references %q; the CSR path must not create or return subject key material — that is the whole custody difference", banned)
		}
	}
}

// TestLimitationsNoLongerClaimsTheIdentityAPIHasNoCSRInput keeps the served-state
// page from carrying a limitation that has been fixed. A stale limitation is as
// misleading as a missing one, just in the other direction.
func TestLimitationsNoLongerClaimsTheIdentityAPIHasNoCSRInput(t *testing.T) {
	t.Parallel()
	limitations := read(t, "limitations.md")
	if strings.Contains(limitations, "direct identity API intentionally has no CSR input at all") {
		t.Error("docs/limitations.md still says the direct identity API has no CSR input; it accepts subject_csr_pem now")
	}
	if !strings.Contains(limitations, "subject_csr_pem") {
		t.Error("docs/limitations.md must record the CSR-first issuance path")
	}
}
