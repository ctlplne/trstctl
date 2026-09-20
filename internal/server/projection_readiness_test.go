// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// TestProjectionTailFailureDegradesServedReadinessUntilCheckpointCoversIt is
// the AUD-103 served regression. PostgreSQL, JetStream, and the HTTP process can
// all be reachable while the read model is stuck behind one poison event. That
// state must remove this replica from readiness and appear in the authenticated
// system readout without copying the raw projection/database error to either
// response. Once the durable cursor covers the failed event, this SAME server
// becomes ready even though one ordinary event of transient lag remains.
func TestProjectionTailFailureDegradesServedReadinessUntilCheckpointCoversIt(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real PostgreSQL and file-backed JetStream")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "projection-health"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	srv, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	poison, err := log.Append(ctx, events.Event{
		Type: "aud103.projection.poison", TenantID: tenantID,
		Data: []byte(`{"safe":"event metadata"}`),
	})
	if err != nil {
		t.Fatalf("append poison event: %v", err)
	}
	later, err := log.Append(ctx, events.Event{
		Type: "aud103.projection.later", TenantID: tenantID,
		Data: []byte(`{"safe":"waiting behind poison"}`),
	})
	if err != nil {
		t.Fatalf("append later event: %v", err)
	}
	// Cleanup also protects the shared server-test PostgreSQL process when an
	// assertion below fails before the explicit recovery step.
	t.Cleanup(func() { _ = st.AdvanceProjectionCheckpoint(context.Background(), later.Sequence) })

	const rawFailure = "duplicate key postgres://secret-user:secret-password@db.internal lifecycle payload"
	if err := st.RecordProjectionTailFailure(ctx, poison.Sequence, errors.New(rawFailure)); err != nil {
		t.Fatalf("persist projection failure: %v", err)
	}
	health, err := st.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatalf("read projection health: %v", err)
	}
	if health.FailedSequence != poison.Sequence || health.LastError != rawFailure {
		t.Fatalf("test did not persist the raw projection failure: %+v", health)
	}
	wantLag := later.Sequence - health.AppliedSequence

	readyCode, readyChecks := projectionReadiness(t, srv.Handler())
	if readyCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503; checks=%v", readyCode, readyChecks)
	}
	diagnostic := readyChecks["projection"]
	for _, want := range []string{
		fmt.Sprintf("applied_sequence=%d", health.AppliedSequence),
		fmt.Sprintf("failed_sequence=%d", poison.Sequence),
		fmt.Sprintf("lag=%d", wantLag),
	} {
		if !strings.Contains(diagnostic, want) {
			t.Fatalf("projection readiness diagnostic %q does not contain %q", diagnostic, want)
		}
	}
	if strings.Contains(diagnostic, rawFailure) || strings.Contains(diagnostic, "secret-password") || strings.Contains(diagnostic, "db.internal") {
		t.Fatalf("/readyz exposed the persisted projection error: %q", diagnostic)
	}

	token := seedScopedToken(t, st, tenantID, string(authz.AccessRead))
	readout := projectionSystemReadout(t, srv.Handler(), token, tenantID)
	wantNames := []string{"db", "nats", "projection"}
	if len(readout.Dependencies) != len(wantNames) {
		t.Fatalf("system dependencies = %+v, want stable order %v", readout.Dependencies, wantNames)
	}
	for i, want := range wantNames {
		if readout.Dependencies[i].Name != want {
			t.Fatalf("system dependency[%d] = %q, want %q; all=%+v", i, readout.Dependencies[i].Name, want, readout.Dependencies)
		}
	}
	projection := readout.Dependencies[2]
	if projection.Ready || projection.Error != diagnostic {
		t.Fatalf("system projection dependency = %+v, want same failed diagnostic as /readyz %q", projection, diagnostic)
	}
	if strings.Contains(projection.Error, rawFailure) {
		t.Fatalf("system readout exposed the persisted projection error: %q", projection.Error)
	}

	// Covering only the failed event atomically clears the durable marker. The
	// second event still makes lag positive, proving catch-up lag alone does not
	// flap readiness during normal operation.
	if err := st.AdvanceProjectionCheckpoint(ctx, poison.Sequence); err != nil {
		t.Fatalf("advance checkpoint through failed sequence: %v", err)
	}
	recoveredHealth, err := st.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatalf("read recovered projection health: %v", err)
	}
	if recoveredHealth.FailedSequence != 0 || recoveredHealth.LastError != "" || recoveredHealth.AppliedSequence != poison.Sequence {
		t.Fatalf("projection health did not recover in place: %+v", recoveredHealth)
	}
	if later.Sequence-recoveredHealth.AppliedSequence == 0 {
		t.Fatal("test precondition lost: recovery must retain ordinary positive lag")
	}

	readyCode, readyChecks = projectionReadiness(t, srv.Handler())
	if readyCode != http.StatusOK || readyChecks["projection"] != "ok" {
		t.Fatalf("recovered /readyz = %d checks=%v, want 200 with projection=ok", readyCode, readyChecks)
	}
	readout = projectionSystemReadout(t, srv.Handler(), token, tenantID)
	if got := readout.Dependencies[2]; !got.Ready || got.Error != "" {
		t.Fatalf("recovered system projection dependency = %+v, want ready without error", got)
	}
}

func projectionReadiness(t *testing.T, handler http.Handler) (int, map[string]string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body struct {
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode /readyz: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, body.Checks
}

func projectionSystemReadout(t *testing.T, handler http.Handler, token, tenantID string) api.SystemReadout {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/system", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", tenantID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/platform/system = %d body=%s", rec.Code, rec.Body.String())
	}
	var body api.SystemReadout
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode platform system readout: %v body=%s", err, rec.Body.String())
	}
	return body
}
