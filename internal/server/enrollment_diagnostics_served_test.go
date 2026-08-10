// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const servedDiagnosticTenantB = "22222222-2222-2222-2222-222222222222"

// This is the AUD-48 wire proof. One failure enters through the actual ACME
// refusal choke point while another tenant reports through that protocol
// callback's production API seam. Authenticated API reads, event envelopes, and
// a clean replay must all preserve the same boundary.
func TestServedEnrollmentDiagnosticsAreTenantScopedEvents(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: servedDiagnosticTenantB, Name: "diagnostic tenant B"}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	tokenA := seedScopedToken(t, h.store, h.tenant, "certs:read")
	tokenB := seedScopedToken(t, h.store, servedDiagnosticTenantB, "certs:read")

	start := make(chan struct{})
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errCh <- causeServedACMERefusal(h)
	}()
	go func() {
		defer wg.Done()
		<-start
		errCh <- h.srv.api.RecordEnrollmentDiagnosis(ctx, servedDiagnosticTenantB,
			enrollmentdiag.Diagnose(enrollmentdiag.ProtocolACME, enrollmentdiag.StepValidation, enrollmentdiag.CauseChallengeNotVisible))
	}()
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A second refusal of the same class must change only tenant A's count.
	if err := causeServedACMERefusal(h); err != nil {
		t.Fatal(err)
	}

	wantA := assertServedDiagnosticTenant(t, h, tokenA, "unknown", 2)
	wantB := assertServedDiagnosticTenant(t, h, tokenB, string(enrollmentdiag.CauseChallengeNotVisible), 1)
	if wantA.Items[0].Summary == wantB.Items[0].Summary {
		t.Fatalf("test setup did not produce distinguishable tenant rows: A=%+v B=%+v", wantA, wantB)
	}

	eventCounts := map[string]int{}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventEnrollmentDiagnosticObserved {
			eventCounts[event.TenantID]++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay diagnostic evidence: %v", err)
	}
	if eventCounts[h.tenant] != 2 || eventCounts[servedDiagnosticTenantB] != 1 {
		t.Fatalf("diagnostic event envelopes = %+v, want tenant A=2 tenant B=1", eventCounts)
	}

	// Delete both derived tables and replay only their immutable source events.
	// API tokens remain in their independent table, so the same authenticated
	// callers can verify the rebuilt projection over the same served route.
	if _, err := h.store.SystemPool().Exec(ctx,
		"TRUNCATE enrollment_diagnostic_observations, enrollment_diagnostics"); err != nil {
		t.Fatalf("truncate diagnostic projection: %v", err)
	}
	projector := projections.New(h.store)
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventEnrollmentDiagnosticObserved {
			return nil
		}
		return projector.Apply(ctx, event)
	}); err != nil {
		t.Fatalf("rebuild diagnostic projection: %v", err)
	}
	assertServedDiagnosticTenant(t, h, tokenA, "unknown", 2)
	assertServedDiagnosticTenant(t, h, tokenB, string(enrollmentdiag.CauseChallengeNotVisible), 1)
}

func causeServedACMERefusal(h *servedHarness) error {
	response, err := h.ts.Client().Get(h.ts.URL + "/directory")
	if err != nil {
		return fmt.Errorf("read served ACME directory: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	var directory struct {
		NewAccount string `json:"newAccount"`
	}
	if err := json.NewDecoder(response.Body).Decode(&directory); err != nil {
		return fmt.Errorf("decode served ACME directory: %w", err)
	}
	request, err := http.NewRequest(http.MethodPost, directory.NewAccount, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/jose+json")
	refusal, err := h.ts.Client().Do(request)
	if err != nil {
		return fmt.Errorf("cause served ACME refusal: %w", err)
	}
	defer func() { _ = refusal.Body.Close() }()
	_, _ = io.Copy(io.Discard, refusal.Body)
	if refusal.StatusCode < 400 {
		return fmt.Errorf("malformed ACME new-account returned %d, want a refusal", refusal.StatusCode)
	}
	return nil
}

func assertServedDiagnosticTenant(t *testing.T, h *servedHarness, token, wantCause string, wantCount int64) api.EnrollmentDiagnosticList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/enrollment/diagnostics", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list enrollment diagnostics: status=%d body=%s", status, body)
	}
	var got api.EnrollmentDiagnosticList
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode enrollment diagnostics: %v body=%s", err, body)
	}
	if len(got.Items) != 1 || got.Items[0].Cause != wantCause || got.Items[0].Count != wantCount {
		t.Fatalf("tenant diagnostics = %+v, want one %s row with count %d", got, wantCause, wantCount)
	}
	if got.Items[0].ObservedAt == "" || !strings.Contains(got.Guidance, "durable tenant-scoped events") {
		t.Fatalf("tenant diagnostics omit durable timestamp/guidance: %+v", got)
	}
	return got
}
