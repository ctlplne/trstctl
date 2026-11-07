// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/crypto"
)

func TestReconcileIntentPinsSeparateAuthorityAndPreservesLegacyDigestA267(t *testing.T) {
	original, inputs := workflowFixture(t)
	legacy, err := json.Marshal(struct {
		Plan            RotationPlan   `json:"plan"`
		ExpectedVersion int            `json:"expected_version"`
		ProviderBinding string         `json:"provider_binding"`
		Probes          []ProbeBinding `json:"probes"`
	}{original.Plan, original.ExpectedVersion, original.ProviderBinding, original.Probes})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := original.Digest()
	if err != nil || digest != crypto.SHA256Hex(append([]byte("trstctl.service-account.rotation-intent.v1\x00"), legacy...)) {
		t.Fatal("ordinary published intent changed its canonical digest", err)
	}
	intent := original
	intent.Mode = Reconcile
	intent.Reconcile = &ReconcilePrincipal{DN: "CN=reconcile,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1101", GUID: strings.Repeat("b", 32)}
	if err := intent.Validate(inputs); err != nil {
		t.Fatal(err)
	}
	if next, e := intent.Digest(); e != nil || next == digest {
		t.Fatal("reconcile authority omitted from immutable digest", e)
	}
	for name, change := range map[string]func(*RotationIntent){
		"ordinary with pins": func(v *RotationIntent) { v.Mode = "" },
		"unknown mode":       func(v *RotationIntent) { v.Mode = "guess" },
		"missing authority":  func(v *RotationIntent) { v.Reconcile = nil },
		"target SID":         func(v *RotationIntent) { v.Reconcile.SID = v.Plan.Account.SID },
		"target GUID":        func(v *RotationIntent) { v.Reconcile.GUID = v.Plan.Account.GUID },
		"target DN alias":    func(v *RotationIntent) { v.Reconcile.DN = `CN=\73vc,DC=lab,DC=test` },
		"malformed DN":       func(v *RotationIntent) { v.Reconcile.DN = "invalid" },
		"invalid SID":        func(v *RotationIntent) { v.Reconcile.SID = "S-1-5-18" },
		"noncanonical GUID":  func(v *RotationIntent) { v.Reconcile.GUID = strings.Repeat("B", 32) },
		"zero GUID":          func(v *RotationIntent) { v.Reconcile.GUID = strings.Repeat("0", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := intent
			pins := *intent.Reconcile
			bad.Reconcile = &pins
			change(&bad)
			if bad.Validate(inputs) == nil {
				t.Fatal("ambiguous reconcile effect accepted")
			}
			if _, e := bad.Digest(); e == nil {
				t.Fatal("ambiguous mode received an authority digest")
			}
		})
	}
}
