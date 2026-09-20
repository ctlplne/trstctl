// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

func TestAUD56SignerLicenseLoaderCannotBypassDeploymentBinding(t *testing.T) {
	privateKey, publicKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V: 2, ID: "lic-aud56-signer", Customer: "Acme", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		DeploymentEntitlement: &license.DeploymentEntitlement{
			ProductionDeploymentID:     "acme-prod",
			NonProductionDeploymentIDs: []string{"acme-stage"},
			NonProductionAllowance:     license.BundledNonProductionDeployments,
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	manager, err := loadSignerLicense(path, license.DeploymentIdentity{ID: "acme-stage", Environment: license.EnvironmentNonProduction}, [][]byte{publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if got := manager.Info().DeploymentEntitlement; got == nil || got.ProductionUnitsConsumed != 0 {
		t.Fatalf("signer effective entitlement = %+v, want bound non-production with zero units", got)
	}
	if _, err := loadSignerLicense(path, license.DeploymentIdentity{ID: "copied-stage", Environment: license.EnvironmentNonProduction}, [][]byte{publicKey}); err == nil || !strings.Contains(err.Error(), "not licensed as non-production") {
		t.Fatalf("copied signer deployment error = %v", err)
	}
}
