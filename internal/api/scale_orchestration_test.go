package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/perf"
)

func TestServedScaleOrchestrationCAPSCALE01(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scale/orchestration", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scale orchestration status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got perf.ScaleOrchestrationPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode scale orchestration: %v", err)
	}
	if got.Capability != "CAP-SCALE-01" || !got.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SCALE-01/true", got.Capability, got.Served)
	}
	if got.SelectedCapacityTier.ID != "CAP-LARGE" || got.SelectedCapacityTier.ManagedCredentials < 1_000_000 {
		t.Fatalf("selected capacity tier = %+v, want CAP-LARGE for at least 1M credentials", got.SelectedCapacityTier)
	}
	requireScaleBand(t, got.TargetCredentialBands, "SCALE-100K")
	requireScaleBand(t, got.TargetCredentialBands, "SCALE-1M")
	requireScaleLane(t, got.ExecutionLanes, "scale-issue", "AN-2/AN-5/AN-6/AN-7")
	requireScaleLane(t, got.ExecutionLanes, "scale-signer", "AN-3/AN-4/AN-7/AN-8")
	requireScaleLane(t, got.ExecutionLanes, "scale-projections", "AN-2/AN-7")
	requireScaleGate(t, got.ReleaseGates, "perf-live", perf.LiveMeasurementArtifact)
	requireScaleGate(t, got.ReleaseGates, "soak", "soak-trend.json")
	if got.TenantIsolation.StorageEnforcement == "" || got.Datastore.Postgres == "" || got.Signer.ProcessModel == "" {
		t.Fatalf("scale plan missing tenant/datastore/signer posture: %+v", got)
	}
	if got.ProjectionReplay.ReplayFloorEventsPerSecond < 500 || got.ProjectionReplay.MaxLagEvents != 50 {
		t.Fatalf("projection replay posture = %+v, want 500 events/sec floor and 50 event lag ceiling", got.ProjectionReplay)
	}
	if len(got.OperatorActions) == 0 || len(got.Residuals) == 0 || len(got.MeasurementArtifacts) != 3 {
		t.Fatalf("scale plan missing operator actions/residuals/artifacts: %+v", got)
	}
}

func TestServedActiveActiveIssuanceCAPSCALE02(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scale/ha-issuance", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HA issuance status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got perf.ActiveActiveIssuancePlan
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode HA issuance: %v", err)
	}
	if got.Capability != "CAP-SCALE-02" || !got.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SCALE-02/true", got.Capability, got.Served)
	}
	if len(got.Regions) < 2 || len(got.IssuanceLanes) < 2 {
		t.Fatalf("regions/lanes = %d/%d, want multi-region active issuance lanes", len(got.Regions), len(got.IssuanceLanes))
	}
	for _, want := range []string{"idempotency", "event-log", "outbox", "leader-workers", "signer-boundary"} {
		requireWriteFence(t, got.TenantWriteFences, want)
	}
	for _, want := range []string{"regional-smoke", "failover-drill", "architecture-lint"} {
		requireScaleGate(t, got.ReleaseGates, want, "")
	}
	if got.RPOSeconds != 5 || got.RTOSeconds != 30 {
		t.Fatalf("RPO/RTO = %d/%d, want 5/30 seconds", got.RPOSeconds, got.RTOSeconds)
	}
	for _, want := range []string{"AN-2", "AN-4", "AN-5", "AN-6", "AN-7"} {
		if !containsString(got.ArchitectureInvariants, want) {
			t.Fatalf("missing invariant %s in %+v", want, got.ArchitectureInvariants)
		}
	}
	if got.WriteModel == "" || got.Topology == "" || len(got.OperatorActions) == 0 || len(got.Residuals) == 0 {
		t.Fatalf("HA issuance plan missing write model/topology/actions/residuals: %+v", got)
	}
}

func requireScaleBand(t *testing.T, bands []perf.ScaleBand, id string) {
	t.Helper()
	for _, band := range bands {
		if band.ID == id {
			return
		}
	}
	t.Fatalf("missing scale band %s in %+v", id, bands)
}

func requireScaleLane(t *testing.T, lanes []perf.ExecutionLane, id, invariant string) {
	t.Helper()
	for _, lane := range lanes {
		if lane.ID == id {
			if lane.ArchitectureInvariant != invariant {
				t.Fatalf("lane %s invariant = %q, want %q", id, lane.ArchitectureInvariant, invariant)
			}
			if len(lane.BulkheadEnv) == 0 || lane.BackpressureSignal == "" || lane.Measurement == "" {
				t.Fatalf("lane %s missing bulkhead/backpressure/measurement evidence: %+v", id, lane)
			}
			return
		}
	}
	t.Fatalf("missing execution lane %s in %+v", id, lanes)
}

func requireScaleGate(t *testing.T, gates []perf.ScaleReleaseGate, id, artifact string) {
	t.Helper()
	for _, gate := range gates {
		if gate.ID == id {
			if !gate.Required || (artifact != "" && gate.Artifact != artifact) {
				t.Fatalf("gate %s = %+v, want required artifact %s", id, gate, artifact)
			}
			return
		}
	}
	t.Fatalf("missing release gate %s in %+v", id, gates)
}

func requireWriteFence(t *testing.T, fences []perf.TenantWriteFence, id string) {
	t.Helper()
	for _, fence := range fences {
		if fence.ID == id {
			if fence.Mechanism == "" || fence.ConflictOutcome == "" || fence.Evidence == "" {
				t.Fatalf("fence %s missing mechanism/outcome/evidence: %+v", id, fence)
			}
			return
		}
	}
	t.Fatalf("missing write fence %s in %+v", id, fences)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
