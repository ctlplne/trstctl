// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/license"
)

func TestAUD56LicenseHelperIssuesBoundEnvironmentBundle(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "vendor.key")
	pubPath := filepath.Join(dir, "vendor.pub")
	licensePath := filepath.Join(dir, "license.json")
	if err := run([]string{"gen-key", "--private-key", privPath, "--public-key", pubPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"sign", "--private-key", privPath, "--out", licensePath,
		"--id", "lic-aud56", "--customer", "Acme", "--tier", "enterprise",
		"--production-deployment-id", "acme-prod",
		"--non-production-deployment-ids", "acme-stage,acme-dev",
		"--issued-at", "2026-08-13T00:00:00Z", "--expires-at", "2027-08-13T00:00:00Z",
	}
	if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("sign environment bundle: %v", err)
	}

	raw, err := os.ReadFile(licensePath) // #nosec G304 -- licensePath is created inside this test's TempDir (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	claims, err := inspectClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.V != 2 || claims.DeploymentEntitlement == nil {
		t.Fatalf("signed claims are not a v2 deployment entitlement: %+v", claims)
	}
	if claims.DeploymentEntitlement.ProductionDeploymentID != "acme-prod" ||
		len(claims.DeploymentEntitlement.NonProductionDeploymentIDs) != 2 ||
		claims.DeploymentEntitlement.NonProductionAllowance != license.BundledNonProductionDeployments {
		t.Fatalf("signed deployment entitlement = %+v", claims.DeploymentEntitlement)
	}

	var inspectOut bytes.Buffer
	if err := run([]string{"inspect", "--license", licensePath}, &inspectOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var inspected map[string]any
	if err := json.Unmarshal(inspectOut.Bytes(), &inspected); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"environment_entitlement", "acme-prod", "acme-stage", "non_production_allowance"} {
		if !strings.Contains(inspectOut.String(), want) {
			t.Fatalf("inspect output missing %q: %s", want, inspectOut.String())
		}
	}
}

func TestAUD56LicenseHelperRefusesUnboundAndOverAllocatedV2(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "vendor.key")
	pubPath := filepath.Join(dir, "vendor.pub")
	if err := run([]string{"gen-key", "--private-key", privPath, "--public-key", pubPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"sign", "--private-key", privPath, "--id", "lic-aud56", "--customer", "Acme", "--tier", "enterprise",
		"--issued-at", "2026-08-13T00:00:00Z", "--expires-at", "2027-08-13T00:00:00Z",
	}
	for name, extra := range map[string][]string{
		"missing production deployment": nil,
		"over allocated": {
			"--production-deployment-id", "prod",
			"--non-production-deployment-ids", "dev-1,dev-2,dev-3,dev-4",
		},
		"duplicate deployment": {
			"--production-deployment-id", "prod",
			"--non-production-deployment-ids", "dev,dev",
		},
	} {
		t.Run(name, func(t *testing.T) {
			args := append(append([]string(nil), base...), extra...)
			if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("sign accepted an unbound or over-allocated v2 license")
			}
		})
	}
}
