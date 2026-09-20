// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedEndpointAlertFailureKeepsObservationAndClaimRetryable(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	h := &agentChannelHarness{servedHarness: roles.servedHarness, client: roles.client, agent: roles.identity}
	ctx := t.Context()
	want := relay.EndpointExpectation{EndpointID: "alert-intent-sql-lost", Address: "127.0.0.1:5432", Fingerprint: strings.Repeat("a", 64)}
	payload, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{want}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,$2,$3,$4)`, h.tenant, relay.KindEndpointVerify, payload, "alert-recovery")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 1})
	if err != nil || claimed == nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: response=%v error=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	tr := transport.ProbeTranscript{Address: want.Address, Vantage: transport.VantageRelay, ExpectedFingerprint: want.Fingerprint, Error: "controlled refusal", ObservedAtUnix: time.Now().Unix()}
	detail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: want.EndpointID, Transcript: tr, Detail: "controlled refusal"}}})
	if err != nil {
		t.Fatal(err)
	}
	request := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(detail), transport.SweepDigest(append(tr.Canonical(), '\n')))
	// Inject failure while recording the notification intent, after the real NATS append.
	// The owned ephemeral fixture is the only database changed by this trigger.
	_, err = h.store.SystemPool().Exec(ctx, `CREATE FUNCTION qa_endpoint_alert_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.destination='notification.verification' THEN RAISE EXCEPTION 'controlled verification alert failure'; END IF; RETURN NEW; END $$;
	CREATE TRIGGER qa_endpoint_alert_fail BEFORE INSERT OR UPDATE ON outbox FOR EACH ROW EXECUTE FUNCTION qa_endpoint_alert_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := h.store.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS qa_endpoint_alert_fail ON outbox; DROP FUNCTION IF EXISTS qa_endpoint_alert_fail()`); err != nil {
			t.Error(err)
		}
	}
	defer cleanup()
	before := eventCount(t, h.log, h.tenant, projections.EventEndpointVerified)
	accepted, err := h.client.ReportJobResult(ctx, request)
	if err == nil && accepted != nil && accepted.Accepted {
		t.Error("failed alert intent was silently acknowledged and completed its claim")
	}
	assertJobNotCompleted(t, ctx, h, job.JobID)
	if after := eventCount(t, h.log, h.tenant, projections.EventEndpointVerified); after != before+1 {
		t.Fatalf("failure did not retain exactly one NATS observation: before=%d after=%d", before, after)
	}
	if _, err := h.store.GetEndpointVerification(ctx, h.tenant, want.EndpointID, string(tr.Vantage)); !store.IsNotFound(err) {
		t.Fatalf("observation committed without its required alert intent: %v", err)
	}
	if t.Failed() {
		return
	}
	cleanup()
	// A different signed observation on the same attempt must not replace the
	// already retained evidence, even though its projection is still missing.
	changed := tr
	changed.Error = "different observation"
	changedDetail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: want.EndpointID, Transcript: changed, Detail: "different observation"}}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err = h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(changedDetail), transport.SweepDigest(append(changed.Canonical(), '\n'))))
	if err == nil && accepted != nil && accepted.Accepted {
		t.Fatal("changed evidence replaced the retained observation")
	}
	assertJobNotCompleted(t, ctx, h, job.JobID)
	accepted, err = h.client.ReportJobResult(ctx, request)
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatalf("same retained observation could not recover: response=%v error=%v", accepted, err)
	}
	observed, err := h.store.GetEndpointVerification(ctx, h.tenant, want.EndpointID, string(tr.Vantage))
	if err != nil || observed.EvidenceDigest != tr.Digest() || observed.ExpectedFingerprint != want.Fingerprint || observed.Reached {
		t.Fatalf("recovered observation differs: %+v error=%v", observed, err)
	}
	if after := eventCount(t, h.log, h.tenant, projections.EventEndpointVerified); after != before+1 {
		t.Fatalf("retry duplicated the observation: before=%d after=%d", before, after)
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
	var alertCount int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='notification.verification'`, h.tenant).Scan(&alertCount)
	}); err != nil || alertCount != 1 {
		t.Fatalf("recovery must retain exactly one alert intent: count=%d err=%v", alertCount, err)
	}
	if retained.Sequence != observed.EventSequence {
		t.Fatalf("projection sequence %d differs from retained event %d", observed.EventSequence, retained.Sequence)
	}
}
