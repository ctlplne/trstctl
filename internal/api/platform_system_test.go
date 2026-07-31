// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

func getSystemReadout(t *testing.T, handler http.Handler, authenticated bool) (int, api.SystemReadout) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/system", nil)
	if authenticated {
		req.Header.Set("X-Tenant-ID", connectorTenantA)
		req.Header.Set("X-Roles", "admin")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body api.SystemReadout
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, body
}

// B-5: the readout is what an operator reads when something looks wrong, so
// the build stamp, the uptime, the signer topology, and per-dependency
// reachability all have to survive the round trip.
func TestPlatformSystemReadoutReportsBuildAndDependencies(t *testing.T) {
	started := time.Now().UTC().Add(-90 * time.Second)
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSystemReadout(func() api.SystemReadout {
			return api.SystemReadout{
				Version: "v0.9.1", Commit: "abc123def456", BuildDate: "2026-07-26T00:00:00Z",
				StartedAt: started, UptimeSeconds: 90, SignerMode: "child", FIPSModuleActive: true,
				Dependencies: []api.SystemDependency{
					{Name: "db", Ready: true},
					{Name: "nats", Ready: false, Error: "event log unreachable"},
				},
			}
		}),
		api.WithIdempotencyResultProtection(func(_ context.Context, tenantID string) (api.IdempotencyResultProtectionReadout, error) {
			if tenantID != connectorTenantA {
				t.Fatalf("provider tenant = %q, want authenticated tenant", tenantID)
			}
			return api.IdempotencyResultProtectionReadout{
				State: "partial", RawV0Remaining: 2, SealedResults: 7,
				Failure: "Legacy codecs remain.", Recovery: "Restart the upgraded node.",
			}, nil
		}),
	)

	code, body := getSystemReadout(t, handler, true)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body.Version != "v0.9.1" || body.Commit != "abc123def456" {
		t.Fatalf("build stamp = %+v", body)
	}
	if body.SignerMode != "child" || !body.FIPSModuleActive {
		t.Fatalf("signer/FIPS posture = %+v", body)
	}
	if body.UptimeSeconds != 90 || !body.StartedAt.Equal(started) {
		t.Fatalf("uptime = %d startedAt = %s", body.UptimeSeconds, body.StartedAt)
	}
	if len(body.Dependencies) != 2 {
		t.Fatalf("dependencies = %+v", body.Dependencies)
	}
	// A failing dependency must carry its reason, not just a false flag.
	if body.Dependencies[1].Ready || body.Dependencies[1].Error != "event log unreachable" {
		t.Fatalf("failing dependency = %+v", body.Dependencies[1])
	}
	// A healthy one must NOT carry an error string.
	if body.Dependencies[0].Error != "" {
		t.Fatalf("healthy dependency carried an error: %+v", body.Dependencies[0])
	}
	if body.IdempotencyResults.State != "partial" || body.IdempotencyResults.RawV0Remaining != 2 || body.IdempotencyResults.SealedResults != 7 {
		t.Fatalf("idempotency result protection = %+v", body.IdempotencyResults)
	}
}

func TestPlatformSystemReadoutSanitizesProtectionStatusFailure(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithIdempotencyResultProtection(func(context.Context, string) (api.IdempotencyResultProtectionReadout, error) {
			return api.IdempotencyResultProtectionReadout{}, errors.New("postgres://secret-user:secret-password@db.internal")
		}),
	)

	_, body := getSystemReadout(t, handler, true)
	if body.IdempotencyResults.State != "failed" {
		t.Fatalf("protection state = %+v", body.IdempotencyResults)
	}
	encoded, err := json.Marshal(body.IdempotencyResults)
	if err != nil {
		t.Fatalf("marshal protection status: %v", err)
	}
	for _, secretValue := range []string{"secret-user", "secret-password", "db.internal"} {
		if strings.Contains(string(encoded), secretValue) {
			t.Fatalf("status leaked provider error: %s", encoded)
		}
	}
}

// The route fills the Go version even when a provider omits it, so the
// console never renders an empty build row.
func TestPlatformSystemReadoutDefaultsGoVersion(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSystemReadout(func() api.SystemReadout { return api.SystemReadout{Version: "v0.9.1"} }),
	)

	_, body := getSystemReadout(t, handler, true)
	if body.GoVersion != runtime.Version() {
		t.Fatalf("go_version = %q, want the running toolchain", body.GoVersion)
	}
	// Dependencies must serialize as [] rather than null.
	if body.Dependencies == nil {
		t.Fatal("dependencies = null, want an empty list")
	}
}

func TestPlatformSystemReadoutUnwiredStillAnswers(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())

	code, body := getSystemReadout(t, handler, true)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body.GoVersion == "" || len(body.Dependencies) != 0 {
		t.Fatalf("unwired readout = %+v", body)
	}
}

func TestPlatformSystemReadoutRequiresAuthenticatedTenant(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSystemReadout(func() api.SystemReadout { return api.SystemReadout{Version: "v0.9.1"} }),
	)

	code, _ := getSystemReadout(t, handler, false)
	if code == http.StatusOK {
		t.Fatal("unauthenticated caller received the system readout")
	}
}
