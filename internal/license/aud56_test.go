// SPDX-License-Identifier: MPL-2.0

package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestAUD56SignedDeploymentEntitlementBindsProductionAndNonProduction(t *testing.T) {
	priv, pub := testKeypair(t)
	now := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC)
	claims := testClaims(TierEnterprise, now.Add(365*24*time.Hour))
	claims.V = 2
	claims.DeploymentEntitlement = &DeploymentEntitlement{
		ProductionDeploymentID:     "acme-prod",
		NonProductionDeploymentIDs: []string{"acme-stage", "acme-dev", "acme-test"},
		NonProductionAllowance:     BundledNonProductionDeployments,
	}
	raw, err := Sign(claims, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		identity    DeploymentIdentity
		wantUnits   int
		wantRemain  int
		wantLegacy  bool
		wantErrPart string
	}{
		{
			name:      "production consumes one production unit",
			identity:  DeploymentIdentity{ID: "acme-prod", Environment: EnvironmentProduction},
			wantUnits: 1, wantRemain: 0,
		},
		{
			name:      "staging is bundled and consumes no production unit",
			identity:  DeploymentIdentity{ID: "acme-stage", Environment: EnvironmentNonProduction},
			wantUnits: 0, wantRemain: 0,
		},
		{
			name:        "production id cannot claim non production",
			identity:    DeploymentIdentity{ID: "acme-prod", Environment: EnvironmentNonProduction},
			wantErrPart: "not licensed as non-production",
		},
		{
			name:        "non production id cannot claim production",
			identity:    DeploymentIdentity{ID: "acme-stage", Environment: EnvironmentProduction},
			wantErrPart: "does not match licensed production deployment",
		},
		{
			name:        "unlisted clone is refused",
			identity:    DeploymentIdentity{ID: "acme-shadow", Environment: EnvironmentNonProduction},
			wantErrPart: "not licensed as non-production",
		},
		{name: "missing runtime identity is refused", wantErrPart: "deployment id is required"},
		{
			name:        "unknown runtime environment is refused",
			identity:    DeploymentIdentity{ID: "acme-stage", Environment: "staging"},
			wantErrPart: "environment must be production or non_production",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, err := LoadForDeployment(path, [][]byte{pub}, tc.identity)
			if tc.wantErrPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("LoadForDeployment() error = %v, want contains %q", err, tc.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			posture := manager.Info().DeploymentEntitlement
			if posture == nil {
				t.Fatal("served deployment entitlement is absent")
			}
			if posture.DeploymentID != tc.identity.ID || posture.Environment != tc.identity.Environment {
				t.Fatalf("served identity = %+v, want %+v", posture, tc.identity)
			}
			if posture.ProductionUnitsConsumed != tc.wantUnits || posture.NonProductionSlotsRemaining != tc.wantRemain {
				t.Fatalf("served consumption = %+v, want units=%d remaining=%d", posture, tc.wantUnits, tc.wantRemain)
			}
			if posture.LegacyUnbound != tc.wantLegacy || posture.BundledNonProductionDeployments != 3 {
				t.Fatalf("served entitlement truth = %+v", posture)
			}
		})
	}
}

func TestAUD56SignedEntitlementValidationRejectsOverAllocationAndAmbiguity(t *testing.T) {
	priv, pub := testKeypair(t)
	now := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC)
	base := testClaims(TierEnterprise, now.Add(time.Hour))
	base.V = 2

	for name, entitlement := range map[string]*DeploymentEntitlement{
		"missing entitlement":   nil,
		"missing production id": {NonProductionAllowance: 3},
		"wrong allowance":       {ProductionDeploymentID: "prod", NonProductionAllowance: 2},
		"too many non production deployments": {
			ProductionDeploymentID: "prod", NonProductionAllowance: 3,
			NonProductionDeploymentIDs: []string{"dev-1", "dev-2", "dev-3", "dev-4"},
		},
		"duplicate non production deployment": {
			ProductionDeploymentID: "prod", NonProductionAllowance: 3,
			NonProductionDeploymentIDs: []string{"dev", "dev"},
		},
		"production repeated as non production": {
			ProductionDeploymentID: "prod", NonProductionAllowance: 3,
			NonProductionDeploymentIDs: []string{"prod"},
		},
		"unsafe deployment id": {
			ProductionDeploymentID: " prod ", NonProductionAllowance: 3,
		},
	} {
		t.Run(name, func(t *testing.T) {
			claims := base
			claims.DeploymentEntitlement = entitlement
			raw, err := Sign(claims, priv)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(raw, [][]byte{pub}); err == nil {
				t.Fatal("Verify() accepted an ambiguous or under-entitled signed claim")
			}
		})
	}
}

func TestAUD56LegacyLicenseIsProductionOnlyAndExpiryPreservesCore(t *testing.T) {
	priv, pub := testKeypair(t)
	expires := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC)
	raw, err := Sign(testClaims(TierEnterprise, expires), priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadForDeployment(path, [][]byte{pub}, DeploymentIdentity{ID: "legacy-stage", Environment: EnvironmentNonProduction}); err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("legacy non-production use error = %v", err)
	}
	manager, err := LoadForDeployment(path, [][]byte{pub}, DeploymentIdentity{Environment: EnvironmentProduction})
	if err != nil {
		t.Fatal(err)
	}
	manager.clock = func() time.Time { return expires.Add(GracePeriod + time.Hour) }
	if manager.State() != StateReadOnly || manager.Mode(FeatureGovernance) != ModeReadOnly {
		t.Fatalf("expired commercial posture = state %s mode %s", manager.State(), manager.Mode(FeatureGovernance))
	}
	posture := manager.Info().DeploymentEntitlement
	if posture == nil || !posture.LegacyUnbound || posture.Environment != EnvironmentProduction || posture.ProductionUnitsConsumed != 1 || posture.BundledNonProductionDeployments != 0 || posture.NonProductionSlotsRemaining != 0 {
		t.Fatalf("legacy served posture = %+v", posture)
	}
	if Community().State() != StateCommunity {
		t.Fatal("commercial expiry must not remove or disable the core license path")
	}
}

func FuzzAUD56VerifyBoundLicense(f *testing.F) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC)
	valid, err := Sign(Claims{
		V: 2, ID: "fuzz-license", Customer: "Fuzz", Tier: TierEnterprise,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		DeploymentEntitlement: &DeploymentEntitlement{
			ProductionDeploymentID:     "fuzz-prod",
			NonProductionDeploymentIDs: []string{"fuzz-stage"},
			NonProductionAllowance:     BundledNonProductionDeployments,
		},
	}, priv)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"payload":"","signature":""}`))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		claims, err := Verify(raw, [][]byte{pub})
		if err != nil {
			return
		}
		if claims.V != 2 || claims.DeploymentEntitlement == nil {
			t.Fatalf("accepted claims lost the signed v2 entitlement: %+v", claims)
		}
	})
}
