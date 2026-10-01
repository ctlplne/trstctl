// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedRenewalMakesOldRelayCheckNotCheckedForCurrentIdentity(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	ctx := t.Context()
	const endpoint = "04570000-0000-4000-8000-000000000001"
	address := "127.0.0.1:18443"
	oldFingerprint, replacement := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, observation := range []projections.EndpointVerificationObserved{
		{EndpointID: endpoint, Address: address, Vantage: "local", Reached: true, ExpectedFingerprint: oldFingerprint, ObservedFingerprint: oldFingerprint},
		{EndpointID: endpoint, Address: address, Vantage: "relay", Reached: true, ExpectedFingerprint: oldFingerprint, ObservedFingerprint: oldFingerprint},
		{EndpointID: endpoint, Address: address, Vantage: "local", Reached: true, ExpectedFingerprint: replacement, ObservedFingerprint: replacement},
	} {
		observation.ObservedAt = time.Now().UTC()
		if err := h.srv.orch.RecordEndpointVerification(ctx, h.tenant, observation); err != nil {
			t.Fatal(err)
		}
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/endpoints/verifications", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list verification status=%d body=%s", status, body)
	}
	var list struct {
		Items []struct {
			EndpointID string `json:"endpoint_id"`
			Vantage    string `json:"vantage"`
			Status     string `json:"status"`
			Detail     string `json:"detail"`
		} `json:"items"`
		Summary struct {
			Verified   int `json:"verified"`
			Diverged   int `json:"diverged"`
			NotChecked int `json:"not_checked"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Summary.Verified != 0 || list.Summary.Diverged != 0 || list.Summary.NotChecked != 1 {
		t.Fatalf("mixed-generation endpoint earned a current verdict: %+v", list.Summary)
	}
	var relayItem *struct {
		EndpointID string `json:"endpoint_id"`
		Vantage    string `json:"vantage"`
		Status     string `json:"status"`
		Detail     string `json:"detail"`
	}
	for i := range list.Items {
		if list.Items[i].EndpointID == endpoint && list.Items[i].Vantage == "relay" {
			relayItem = &list.Items[i]
		}
	}
	if relayItem == nil || relayItem.Status != "not_checked" || !strings.Contains(relayItem.Detail, "superseded") {
		t.Fatalf("old relay result still claimed current verification: %+v", relayItem)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/endpoints/verifications/"+endpoint, token, nil)
	if status != http.StatusOK || !jsonContains(t, body, "not_checked") || !jsonContains(t, body, "superseded") {
		t.Fatalf("exact relay read disagrees with list: status=%d body=%s", status, body)
	}
}

// A relay can return an hourly sweep after renewal has changed the identity
// expected by the host. Its signed measurement is historical evidence, but
// comparing it with the old expectation cannot describe the current endpoint.
func TestServedStaleRelaySweepRetainsEvidenceWithoutFalseDivergence(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	ctx := t.Context()
	const endpoint = "stale-renewal-apache"
	address := "127.0.0.1:18443"
	oldFingerprint, replacement := strings.Repeat("a", 64), strings.Repeat("b", 64)
	observedAt := time.Now().UTC().Truncate(time.Second)
	if err := h.srv.orch.RecordEndpointVerification(ctx, h.tenant, projections.EndpointVerificationObserved{
		EndpointID: endpoint, Address: address, Vantage: "local", Reached: true,
		ExpectedFingerprint: oldFingerprint, ObservedFingerprint: oldFingerprint,
		ObservedAt: observedAt.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	want := relay.EndpointExpectation{EndpointID: endpoint, Address: address, Fingerprint: oldFingerprint}
	payload, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{want}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,$2,$3,$4)`, h.tenant, relay.KindEndpointVerify, payload, "stale-renewal-sweep")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: response=%v error=%v", claimed, err)
	}
	if err := h.srv.orch.RecordEndpointVerification(ctx, h.tenant, projections.EndpointVerificationObserved{
		EndpointID: endpoint, Address: address, Vantage: "local", Reached: true,
		ExpectedFingerprint: replacement, ObservedFingerprint: replacement,
		ObservedAt: observedAt,
	}); err != nil {
		t.Fatal(err)
	}
	tr := transport.ProbeTranscript{
		Address: address, Vantage: transport.VantageRelay, Reached: true,
		ExpectedFingerprint: oldFingerprint, ObservedFingerprint: replacement,
		Mismatch: certinfo.MismatchFingerprint, ObservedAtUnix: observedAt.Unix(),
		NotBeforeUnix: observedAt.Add(-time.Hour).Unix(), NotAfterUnix: observedAt.Add(time.Hour).Unix(),
	}
	detail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: endpoint, Transcript: tr}}})
	if err != nil {
		t.Fatal(err)
	}
	job := claimed.Jobs[0]
	accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(detail), transport.SweepDigest(append(tr.Canonical(), '\n'))))
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatalf("signed historical report rejected: response=%v error=%v", accepted, err)
	}
	if _, err := h.store.GetEndpointVerification(ctx, h.tenant, endpoint, "relay"); !store.IsNotFound(err) {
		t.Fatalf("stale mismatch became current relay state: %v", err)
	}
	var alerts int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='notification.verification'`, h.tenant).Scan(&alerts)
	}); err != nil || alerts != 0 {
		t.Fatalf("stale mismatch raised an alert: alerts=%d error=%v", alerts, err)
	}
	var retained events.Event
	if err := h.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID == h.tenant && ev.Type == projections.EventEndpointVerified {
			retained = ev
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var history projections.EndpointVerificationObservedWithAlert
	if err := json.Unmarshal(retained.Data, &history); err != nil {
		t.Fatal(err)
	}
	if history.EvidenceDigest != tr.Digest() || !history.SupersededExpectation || history.AlertRequired {
		t.Fatalf("historical observation lacks superseded decision: %+v", history)
	}

	// The safeguard must not hide real drift against the current deployment.
	current := relay.EndpointExpectation{EndpointID: endpoint, Address: address, Fingerprint: replacement}
	payload, err = json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{current}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,$2,$3,$4)`, h.tenant, relay.KindEndpointVerify, payload, "current-renewal-sweep")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err = h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim current sweep: response=%v error=%v", claimed, err)
	}
	tr.ExpectedFingerprint, tr.ObservedFingerprint = replacement, strings.Repeat("c", 64)
	tr.ObservedAtUnix = observedAt.Add(time.Second).Unix()
	detail, err = json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: endpoint, Transcript: tr}}})
	if err != nil {
		t.Fatal(err)
	}
	job = claimed.Jobs[0]
	accepted, err = h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(detail), transport.SweepDigest(append(tr.Canonical(), '\n'))))
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatalf("current signed drift report rejected: response=%v error=%v", accepted, err)
	}
	actual, err := h.store.GetEndpointVerification(ctx, h.tenant, endpoint, "relay")
	if err != nil || actual.Mismatch != string(certinfo.MismatchFingerprint) || actual.ExpectedFingerprint != replacement {
		t.Fatalf("current divergence was hidden: row=%+v error=%v", actual, err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='notification.verification'`, h.tenant).Scan(&alerts)
	}); err != nil || alerts != 1 {
		t.Fatalf("current divergence did not alert: alerts=%d error=%v", alerts, err)
	}
}
