// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestProfileDNSNamesValidatesBothSources is the regression guard for the
// profile-policy bypass. profileDNSNames returned the CSR's SANs when it had
// any, and only otherwise fell back to req.DNSNames. In-process CAs take the
// issued names from the CSR, but several external-CA adapters build the UPSTREAM
// order's CN/SANs from req.DNSNames — so whenever the CSR carried any SAN, the
// req.DNSNames set travelled to the upstream CA having never been checked
// against the tenant's profile suffix policy.
func TestProfileDNSNamesValidatesBothSources(t *testing.T) {
	info := crypto.CSRInfo{DNSNames: []string{"allowed.corp.example"}}
	requested := []string{"smuggled.other.example"}

	got := profileDNSNames(info, requested)

	if !slices.Contains(got, "allowed.corp.example") {
		t.Errorf("CSR SAN missing from the profile-checked set: %v", got)
	}
	if !slices.Contains(got, "smuggled.other.example") {
		t.Fatalf("req.DNSNames %q is not profile-checked when the CSR carries a SAN (%v); "+
			"external-CA adapters build the upstream order from it, so it reaches a certificate unvetted",
			"smuggled.other.example", got)
	}
}

// TestProfileDNSNamesDeduplicates keeps the union tidy: the same name from both
// sources must be checked once, not twice, and case/trailing-dot variants of one
// name are one name.
func TestProfileDNSNamesDeduplicates(t *testing.T) {
	info := crypto.CSRInfo{DNSNames: []string{"host.corp.example"}}
	got := profileDNSNames(info, []string{"HOST.corp.example.", "host.corp.example"})
	if len(got) != 1 {
		t.Fatalf("union = %v, want a single deduplicated name", got)
	}
}

// TestProfileDNSNamesFallbackStillWorks pins the original behaviour that was
// correct: a CSR with no SANs must still have req.DNSNames checked.
func TestProfileDNSNamesFallbackStillWorks(t *testing.T) {
	got := profileDNSNames(crypto.CSRInfo{}, []string{"only.corp.example"})
	if !slices.Contains(got, "only.corp.example") {
		t.Fatalf("fallback names lost: %v", got)
	}
}
