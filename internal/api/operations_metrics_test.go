// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
)

type bulkheadStatsBody struct {
	Served bool `json:"served"`
	Pools  []struct {
		Name       string `json:"name"`
		Workers    int    `json:"workers"`
		Capacity   int    `json:"capacity"`
		Queued     int    `json:"queued"`
		Submitted  int64  `json:"submitted"`
		Completed  int64  `json:"completed"`
		Rejected   int64  `json:"rejected"`
		Panicked   int64  `json:"panicked"`
		Saturation int    `json:"saturation_percent"`
	} `json:"pools"`
}

func getBulkheadStats(t *testing.T, handler http.Handler) (int, bulkheadStatsBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations/bulkheads", nil)
	req.Header.Set("X-Tenant-ID", connectorTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body bulkheadStatsBody
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, body
}

// B-1: AN-7 bounded pools were only visible on the metrics endpoint, so an
// operator could not answer "is a queue backing up, and which one" from the
// served API. These pin the served shape, including the saturation the route
// computes so a caller can sort by pressure.
func TestBulkheadStatsReportsPoolPressure(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithBulkheadStats(func() []bulkhead.Stats {
			return []bulkhead.Stats{
				{Name: "api", Workers: 8, Capacity: 100, Queued: 25, Submitted: 400, Completed: 370, Rejected: 5, Panicked: 0},
				{Name: "discovery", Workers: 4, Capacity: 0, Queued: 0, Submitted: 12, Completed: 12},
			}
		}),
	)

	code, body := getBulkheadStats(t, handler)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !body.Served {
		t.Fatal("served = false with a pool provider wired")
	}
	if len(body.Pools) != 2 {
		t.Fatalf("pools = %+v, want both pools", body.Pools)
	}

	api1 := body.Pools[0]
	if api1.Name != "api" || api1.Workers != 8 || api1.Capacity != 100 || api1.Queued != 25 {
		t.Fatalf("api pool = %+v", api1)
	}
	if api1.Rejected != 5 || api1.Submitted != 400 || api1.Completed != 370 {
		t.Fatalf("api counters = %+v", api1)
	}
	// 25 queued of 100 capacity is 25% pressure.
	if api1.Saturation != 25 {
		t.Fatalf("saturation = %d, want 25", api1.Saturation)
	}
	// An unbounded pool must report 0 rather than dividing by zero.
	if body.Pools[1].Saturation != 0 {
		t.Fatalf("unbounded pool saturation = %d, want 0", body.Pools[1].Saturation)
	}
}

// A server assembled without the bulkheaded surfaces answers truthfully rather
// than 404: "nothing is saturated because nothing is wired" is a real answer.
func TestBulkheadStatsUnwiredReportsNotServed(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())

	code, body := getBulkheadStats(t, handler)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body.Served {
		t.Fatal("served = true with no pool provider wired")
	}
	if len(body.Pools) != 0 {
		t.Fatalf("pools = %+v, want empty", body.Pools)
	}
}

// The route is authenticated like every other operational read: an
// unauthenticated caller gets a problem response, not pool telemetry.
func TestBulkheadStatsRequiresAuthenticatedTenant(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithBulkheadStats(func() []bulkhead.Stats { return []bulkhead.Stats{{Name: "api", Capacity: 10}} }),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations/bulkheads", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("unauthenticated caller received pool telemetry: %s", rec.Body.String())
	}
}
