// SPDX-License-Identifier: LicenseRef-trstctl-EE

package plan_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/reconcile/plan"
	"trstctl.com/trstctl/internal/crypto"
)

func TestPlanTrustBundle_RoundTrip(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	defer key.Destroy()

	dir := t.TempDir()
	if err := plan.WriteTrustBundle(dir, plan.TrustBundle{
		PlanKeys: []plan.TrustedKey{{
			KeyID:        "plan-key-1",
			Algorithm:    key.Public().Algorithm,
			PublicKeyDER: key.Public().DER,
		}},
	}); err != nil {
		t.Fatalf("WriteTrustBundle: %v", err)
	}
	got, err := plan.LoadTrustedPlanKeys(dir)
	if err != nil {
		t.Fatalf("LoadTrustedPlanKeys: %v", err)
	}
	if got["plan-key-1"].Algorithm != key.Public().Algorithm || len(got["plan-key-1"].DER) == 0 {
		t.Fatalf("loaded trust = %+v, want plan-key-1", got)
	}
}

func TestPlanTrustBundle_RejectsInvalid(t *testing.T) {
	err := plan.WriteTrustBundle(t.TempDir(), plan.TrustBundle{
		PlanKeys: []plan.TrustedKey{{KeyID: "missing-material"}},
	})
	if !errors.Is(err, plan.ErrInvalidTrustBundle) {
		t.Fatalf("WriteTrustBundle invalid = %v, want ErrInvalidTrustBundle", err)
	}
}
