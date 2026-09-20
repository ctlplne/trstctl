// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
)

func TestAUD56ProductionCompositionBindsConfiguredLicenseEnvironment(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V: 2, ID: "lic-server-aud56", Customer: "Acme", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		DeploymentEntitlement: &license.DeploymentEntitlement{
			ProductionDeploymentID:     "acme-prod",
			NonProductionDeploymentIDs: []string{"acme-stage"},
			NonProductionAllowance:     license.BundledNonProductionDeployments,
		},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.License = config.License{File: path, DeploymentID: "acme-stage", Environment: "non_production"}

	manager, err := loadConfiguredLicense(cfg, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	posture := manager.Info().DeploymentEntitlement
	if posture == nil || posture.Environment != license.EnvironmentNonProduction || posture.ProductionUnitsConsumed != 0 {
		t.Fatalf("production composition served posture = %+v", posture)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, License: manager})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)
	response, err := http.Get(httpServer.URL + "/api/v1/editions") // #nosec G107 -- fixed localhost-only assembled-test server (CWE-918)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close editions response: %v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET editions = %d", response.StatusCode)
	}
	var served struct {
		DeploymentEntitlement *license.DeploymentEntitlementInfo `json:"deployment_entitlement"`
	}
	if err := json.NewDecoder(response.Body).Decode(&served); err != nil {
		t.Fatal(err)
	}
	if served.DeploymentEntitlement == nil || served.DeploymentEntitlement.DeploymentID != "acme-stage" || served.DeploymentEntitlement.ProductionUnitsConsumed != 0 {
		t.Fatalf("assembled editions posture = %+v", served.DeploymentEntitlement)
	}

	cfg.License.DeploymentID = "unlisted-copy"
	if _, err := loadConfiguredLicense(cfg, [][]byte{pub}); err == nil || !strings.Contains(err.Error(), "not licensed as non-production") {
		t.Fatalf("production composition copied-license error = %v", err)
	}
}
