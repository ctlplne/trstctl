package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

type editionsTestResponse struct {
	license.Info
	FIPS struct {
		ModuleActive   bool `json:"module_active"`
		Required       bool `json:"required"`
		SelfTestPassed bool `json:"self_test_passed"`
	} `json:"fips"`
}

func TestEditionsEndpointReturnsCommunityAndFIPSPosture(t *testing.T) {
	var got editionsTestResponse
	getEditions(t, api.New(nil, nil, nil), &got)

	if got.Tier != license.TierCommunity || got.State != license.StateCommunity {
		t.Fatalf("community editions header = tier %s state %s", got.Tier, got.State)
	}
	assertEditionsFeature(t, got.Features, license.FeatureFIPS, license.TierEnterprise, false, license.ModeOff)
	if got.FIPS.ModuleActive != crypto.FIPSEnabled() {
		t.Fatalf("fips.module_active=%t, want crypto.FIPSEnabled()=%t", got.FIPS.ModuleActive, crypto.FIPSEnabled())
	}
	if got.FIPS.Required {
		t.Fatal("editions posture must not turn FIPS into a runtime license requirement")
	}
	if !got.FIPS.SelfTestPassed {
		t.Fatal("editions posture must report the crypto power-on self-test result")
	}
}

func TestEditionsEndpointReturnsLoadedLicense(t *testing.T) {
	mgr := testLicenseManager(t, license.TierEnterprise)
	var got editionsTestResponse
	getEditions(t, api.New(nil, nil, nil, api.WithLicense(mgr)), &got)

	if got.Tier != license.TierEnterprise || got.State != license.StateActive {
		t.Fatalf("licensed editions header = tier %s state %s", got.Tier, got.State)
	}
	if got.Customer != "Acme Robotics" || got.LicenseID != "lic_test_editions" {
		t.Fatalf("licensed identity fields missing: %+v", got.Info)
	}
	assertEditionsFeature(t, got.Features, license.FeatureFIPS, license.TierEnterprise, true, license.ModeEnabled)
}

func getEditions(t *testing.T, h http.Handler, out *editionsTestResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/editions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/editions = %d, body %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode editions response: %v", err)
	}
}

func testLicenseManager(t *testing.T, tier license.Tier) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V:         1,
		ID:        "lic_test_editions",
		Customer:  "Acme Robotics",
		Tier:      tier,
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func assertEditionsFeature(t *testing.T, features []license.FeatureInfo, name license.Feature, tier license.Tier, licensed bool, mode license.Mode) {
	t.Helper()
	for _, f := range features {
		if f.Name == name {
			if f.Tier != tier || f.Licensed != licensed || f.Mode != mode {
				t.Fatalf("feature %s row = %+v, want tier=%s licensed=%t mode=%s", name, f, tier, licensed, mode)
			}
			return
		}
	}
	t.Fatalf("feature %s row missing from %+v", name, features)
}
