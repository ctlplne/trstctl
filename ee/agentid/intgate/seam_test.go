// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

import (
	"sort"
	"testing"
)

// TestProdCaller_SeamIsOnlySanctionedRoot proves the SEAM property: the ONLY sanctioned
// production root is the ee_attach seam (cmd/trstctl/ee_attach.go +
// cmd/trstctl-signer/ee_attach.go, both //go:build !trstctl_core), and reachability
// through a test helper does NOT count.
//
// It checks three things:
//
//  1. Each sanctioned seam file exists and carries //go:build !trstctl_core (it is the
//     EE-only attach, dropped in the core build).
//  2. Every REQUIRED constructor is seam-rooted: there is a chain of NON-TEST callers
//     from a seam file down to it. Since the non-test caller scan excludes *_test.go,
//     /mock, /fake, /testkit, testdata, and test-only build tags, a constructor
//     reachable ONLY from a test helper has an empty non-test caller set and is NOT
//     seam-rooted -- so this same check enforces "a test-helper-only root fails".
//  3. A negative control: a synthetic constructor whose only caller is a *_test.go file
//     is confirmed to have ZERO non-test callers, demonstrating the gate rejects
//     test-helper-only reachability by construction.
func TestProdCaller_SeamIsOnlySanctionedRoot(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	// (1) Seam files exist and are EE-only (!trstctl_core).
	if err := verifySeamFilesExist(root); err != nil {
		t.Fatalf("seam file check: %v", err)
	}
	for _, s := range SanctionedSeams {
		ok, err := seamFileHasCoreExclusionTag(root, s)
		if err != nil {
			t.Fatalf("parse seam %s: %v", s, err)
		}
		if !ok {
			t.Errorf("sanctioned seam %s does not carry //go:build !trstctl_core: the production attach must be EE-only (dropped in the core build) so the seam is inert there (INV-A10)", s)
		}
	}

	// (2) Every REQUIRED constructor is seam-rooted through non-test callers.
	results, err := AssertSeamOnlyRoot(root)
	if err != nil {
		t.Fatalf("compute seam roots: %v", err)
	}
	var notRooted []string
	directCount := 0
	for _, r := range results {
		if r.DirectFromSeam {
			directCount++
		}
		if !r.SeamRooted {
			notRooted = append(notRooted, r.Constructor.Qualified()+" (expected via: "+r.Constructor.SeededVia+")")
			continue
		}
		via := "transitively from the ee_attach seam"
		if r.DirectFromSeam {
			via = "DIRECTLY from a sanctioned ee_attach seam file"
		}
		t.Logf("SEAM-ROOTED %-46s %s", r.Constructor.Qualified(), via)
	}
	if directCount == 0 {
		t.Errorf("no REQUIRED constructor is called DIRECTLY from a sanctioned seam file: the ee_attach seam must be the attach root (expected api.NewAPIOptionsFactory, orchestrator.NewLicensedOutboxFactory, brokerstore.NewFailClosedBrokerPrecondition, delegation.NewSignerGate)")
	}
	if len(notRooted) > 0 {
		sort.Strings(notRooted)
		t.Fatalf("SEAM ASSERTION FAILED: %d REQUIRED constructor(s) are NOT reachable through a non-test caller chain rooted at the ee_attach seam (a mechanism reachable only via a test helper does NOT satisfy the gate):\n  - %s",
			len(notRooted), joinLines(notRooted))
	}

	// (3) Negative control: a name defined only for tests must have zero non-test
	// callers. We assert the DEFERRED verify.NewLocalPolicy (used only from *_test.go and
	// the verify package's own SDK sample helper) is NOT seam-rooted from cmd/*, proving
	// the gate does not count a non-seam / test-only reference as a production root.
	refs, err := NonTestCallers(root, "NewLocalPolicy", "ee/agentid/verify/helpers.go", []string{"cmd"})
	if err != nil {
		t.Fatalf("negative-control scan: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("negative control failed: verify.NewLocalPolicy has %d cmd/* caller(s) %v — the external RP SDK must have NO control-plane (seam) caller", len(refs), refs)
	}
}

// TestSeam_DirectAttachTargets documents the exact constructors the ee_attach seam
// invokes directly, so a change to the seam's attach set is a visible, reviewed diff.
// These four are the roots from which every other REQUIRED constructor is transitively
// reachable.
func TestSeam_DirectAttachTargets(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	targets, err := seamAttachTargets(root)
	if err != nil {
		t.Fatalf("seam attach targets: %v", err)
	}
	want := []struct{ pkg, name string }{
		{"ee/agentid/api", "NewAPIOptionsFactory"},
		{"ee/agentid/orchestrator", "NewLicensedOutboxFactory"},
		{"ee/agentid/delegation/brokerstore", "NewFailClosedBrokerPrecondition"},
		{"ee/agentid/delegation", "NewSignerGate"},
	}
	for _, w := range want {
		if !targets[ctorKey(w.pkg, w.name)] {
			t.Errorf("expected sanctioned seam to call %s.%s directly, but no seam file does (the AGID attach root changed — verify cmd/trstctl/ee_attach.go and cmd/trstctl-signer/ee_attach.go)", lastPathSegment(w.pkg), w.name)
		}
	}
}
