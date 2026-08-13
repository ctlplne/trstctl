// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

func TestAUD56ExpiredLicenseKeepsLicensedReadsAndRefusesLicensedMutations(t *testing.T) {
	manager := expiredLicenseManager(t)
	mutationCalls := 0
	served := api.New(nil, nil, nil,
		api.WithLicense(manager),
		api.WithLicensedRoutes(
			api.LicensedRoute{
				Method: http.MethodGet, Path: "/api/v1/aud56/licensed-state",
				OperationID: "getAUD56LicensedState", Summary: "Read licensed state",
				Handler: func(*api.API) http.HandlerFunc {
					return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
				},
				SuccessCode: "204",
			},
			api.LicensedRoute{
				Method: http.MethodPost, Path: "/api/v1/aud56/licensed-state",
				OperationID: "mutateAUD56LicensedState", Summary: "Mutate licensed state",
				Handler: func(*api.API) http.HandlerFunc {
					return func(w http.ResponseWriter, _ *http.Request) {
						mutationCalls++
						w.WriteHeader(http.StatusNoContent)
					}
				},
				SuccessCode: "204", Mutation: true,
			},
		),
	)

	read := httptest.NewRecorder()
	served.ServeHTTP(read, httptest.NewRequest(http.MethodGet, "/api/v1/aud56/licensed-state", nil))
	if read.Code != http.StatusNoContent {
		t.Fatalf("licensed read after grace = %d body=%s, want 204", read.Code, read.Body.String())
	}

	mutation := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/aud56/licensed-state", nil)
	req.Header.Set("Idempotency-Key", "aud56-expired-license")
	served.ServeHTTP(mutation, req)
	if mutation.Code != http.StatusForbidden || !strings.Contains(mutation.Body.String(), "read-only") {
		t.Fatalf("licensed mutation after grace = %d body=%s, want 403 read-only problem", mutation.Code, mutation.Body.String())
	}
	if mutationCalls != 0 {
		t.Fatalf("expired commercial mutation reached its handler %d times, want 0", mutationCalls)
	}
}

func expiredLicenseManager(t *testing.T) *license.Manager {
	t.Helper()
	privateKey, publicKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_aud56_expired", Customer: "Acme Robotics", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-90 * 24 * time.Hour), ExpiresAt: now.Add(-60 * 24 * time.Hour),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := license.Load(path, [][]byte{publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if manager.State() != license.StateReadOnly {
		t.Fatalf("test fixture state = %s, want read_only", manager.State())
	}
	return manager
}
