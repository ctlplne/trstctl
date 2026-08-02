// SPDX-License-Identifier: MPL-2.0

package servedstatus

import "testing"

// TestAuditIsCleanForTheShippedVocabulary is the contract itself: no status value
// trstctl serves today spells an action its own flags say the code did not take.
// If this fails, either the code grew a capability and the flags should follow, or
// somebody reached for a word the code has not earned.
func TestAuditIsCleanForTheShippedVocabulary(t *testing.T) {
	for _, v := range Audit() {
		t.Errorf("served status overstates its action: %v", v.Error())
	}
}

// TestAuditCatchesTheDefectsThatMotivatedTheContract pins the two historical
// regressions the gap analysis found, so the guard cannot rot into a no-op: a
// success-shaped status on a path that never contacts the target, and a
// verdict-shaped gate status that evaluated nothing.
func TestAuditCatchesTheDefectsThatMotivatedTheContract(t *testing.T) {
	saved := Registries
	t.Cleanup(func() { Registries = saved })

	Registries = []Registry{{
		Surface: "regression fixture",
		Claims: []Claim{
			// truth-integrity 3: the former connector target "test".
			{Value: "test_succeeded", Meaning: "validated config only"},
			// truth-integrity 2: the former hardcoded fleet gate.
			{Value: "passed", Meaning: "assumed, not computed"},
			// truth-integrity 4 shape: a memo spelled as an executed restore.
			{Value: "rolled_back", Meaning: "recorded an intent"},
		},
	}}

	got := map[string]string{}
	for _, v := range Audit() {
		got[v.Value] = v.Flag
	}
	want := map[string]string{
		"test_succeeded": "ContactedTarget",
		"passed":         "Evaluated",
		"rolled_back":    "MutatedTarget",
	}
	if len(got) != len(want) {
		t.Fatalf("audit found %d violations, want %d: %v", len(got), len(want), got)
	}
	for value, flag := range want {
		if got[value] != flag {
			t.Errorf("audit for %q blamed %q, want %q", value, got[value], flag)
		}
	}
}

// TestFlaggedWordsAreLicensedNotBanned proves the contract is about honesty, not
// vocabulary policing: the same words are fine once the corresponding flag is true.
func TestFlaggedWordsAreLicensedNotBanned(t *testing.T) {
	saved := Registries
	t.Cleanup(func() { Registries = saved })

	Registries = []Registry{{
		Surface: "licensed fixture",
		Claims: []Claim{
			{Value: "test_succeeded", ContactedTarget: true, Meaning: "really opened a connection"},
			{Value: "passed", Evaluated: true, Meaning: "computed from receipts"},
			{Value: "rolled_back", MutatedTarget: true, Meaning: "restored the predecessor bundle"},
			{Value: "verified", Verified: true, Meaning: "handshaked the live listener"},
		},
	}}

	if v := Audit(); len(v) != 0 {
		t.Fatalf("licensed words should pass the audit, got %v", v)
	}
}

// TestContainsWordDoesNotFireOnSubstrings keeps the matcher from producing false
// positives that would push authors toward vaguer, less useful status names.
func TestContainsWordDoesNotFireOnSubstrings(t *testing.T) {
	cases := []struct {
		value, word string
		want        bool
	}{
		{"test_succeeded", "succeeded", true},
		{"succeeded", "succeeded", true},
		{"unsuccessful_precondition", "success", false},
		{"passed", "passed", true},
		{"bypassed", "passed", false},
		{"rollback_recorded", "rolled_back", false},
		{"rolled_back_and_verified", "rolled_back", true},
		{"config_validated", "verified", false},
	}
	for _, tc := range cases {
		if got := containsWord(tc.value, tc.word); got != tc.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", tc.value, tc.word, got, tc.want)
		}
	}
}

// TestEveryClaimStatesItsMeaning keeps the registry usable as documentation: a
// status with no meaning cannot be explained to an operator or a console tooltip.
func TestEveryClaimStatesItsMeaning(t *testing.T) {
	for _, reg := range Registries {
		if reg.Surface == "" {
			t.Error("a registry has no surface name")
		}
		seen := map[string]bool{}
		for _, claim := range reg.Claims {
			if claim.Value == "" {
				t.Errorf("%s: a claim has an empty value", reg.Surface)
			}
			if claim.Meaning == "" {
				t.Errorf("%s: status %q has no meaning; state plainly what the code did", reg.Surface, claim.Value)
			}
			if seen[claim.Value] {
				t.Errorf("%s: status %q declared twice", reg.Surface, claim.Value)
			}
			seen[claim.Value] = true
		}
	}
}

// TestVerifiedImpliesContact stops a future edit from claiming independent
// verification on a path that never reached the target.
func TestVerifiedImpliesContact(t *testing.T) {
	for _, reg := range Registries {
		for _, claim := range reg.Claims {
			if claim.Verified && !claim.ContactedTarget {
				t.Errorf("%s: status %q claims Verified without ContactedTarget; nothing was re-read",
					reg.Surface, claim.Value)
			}
			if claim.MutatedTarget && !claim.ContactedTarget && reg.Surface == ConnectorDelivery.Surface {
				t.Errorf("%s: status %q claims MutatedTarget without ContactedTarget",
					reg.Surface, claim.Value)
			}
		}
	}
}

// TestLookupAndValues covers the accessors the OpenAPI enum and docs table use.
func TestLookupAndValues(t *testing.T) {
	values := ConnectorDelivery.Values()
	want := len(ConnectorDelivery.Claims) + len(ConnectorDelivery.Retired)
	if len(values) != want {
		t.Fatalf("Values() returned %d entries for %d writable + %d retired",
			len(values), len(ConnectorDelivery.Claims), len(ConnectorDelivery.Retired))
	}
	if values[0] != ConnectorQueued {
		t.Errorf("Values() lost declaration order: first entry is %q", values[0])
	}
	claim, ok := ConnectorDelivery.Lookup(ConnectorConfigValidated)
	if !ok {
		t.Fatalf("Lookup(%q) missed", ConnectorConfigValidated)
	}
	if claim.ContactedTarget {
		t.Errorf("%q must not claim target contact until epic D5 ships the real dry-run", ConnectorConfigValidated)
	}
	if _, ok := ConnectorDelivery.Lookup("test_succeeded"); ok {
		t.Error("the retired overstating status test_succeeded is back in the writable vocabulary")
	}
}

// TestRetiredValuesStayReadableButNotWritable pins the compatibility half of the
// contract. Receipts written before the rename still carry the old string, so the
// served enum must keep describing it; what changes is that the code stops writing
// it. Dropping it from the enum would narrow a published enum and put stored rows
// outside the contract that describes them.
func TestRetiredValuesStayReadableButNotWritable(t *testing.T) {
	if !ConnectorDelivery.IsRetired("test_succeeded") {
		t.Error("test_succeeded must stay declared as retired; historical receipts still carry it")
	}
	values := ConnectorDelivery.Values()
	if !contains(values, "test_succeeded") {
		t.Error("the served enum must still include test_succeeded so historical receipts stay in contract")
	}
	if contains(ConnectorDelivery.WritableValues(), "test_succeeded") {
		t.Error("test_succeeded must not be writable")
	}
	if !contains(FleetBatch.Values(), "completed") {
		t.Error("the served batch enum must still include completed for historical runs")
	}
	if contains(FleetBatch.WritableValues(), "completed") {
		t.Error("completed must not be writable for batches until batches are real execution units (epic D6)")
	}

	for _, r := range AllRetired() {
		if r.Replacement == "" {
			t.Errorf("retired status %q names no replacement; an operator reading history needs the current spelling", r.Value)
		}
		if r.Why == "" {
			t.Errorf("retired status %q records no reason; the retirement is the evidence that the surface was corrected", r.Value)
		}
	}
}

// TestRetiredValuesAreNotAlsoWritableAnywhere stops a value from being retired on
// one surface while quietly remaining writable there.
func TestRetiredValuesAreNotAlsoWritableAnywhere(t *testing.T) {
	for _, reg := range Registries {
		for _, r := range reg.Retired {
			if _, ok := reg.Lookup(r.Value); ok {
				t.Errorf("%s: %q is declared both writable and retired", reg.Surface, r.Value)
			}
			if r.Replacement != "" {
				if _, ok := reg.Lookup(r.Replacement); !ok {
					t.Errorf("%s: retired %q points at replacement %q, which is not a writable status on this surface",
						reg.Surface, r.Value, r.Replacement)
				}
			}
		}
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
