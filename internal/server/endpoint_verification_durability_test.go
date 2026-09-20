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
)

func TestServedEndpointObservationCancellationKeepsTheClaimRetryable(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	h := &agentChannelHarness{servedHarness: roles.servedHarness, client: roles.client, agent: roles.identity}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	want := relay.EndpointExpectation{EndpointID: "cancelled-observation", Address: "127.0.0.1:5432", Fingerprint: strings.Repeat("a", 64)}
	payload, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{want}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,$2,$3,$4)`, h.tenant, relay.KindEndpointVerify, payload, "cancelled-observation")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim verification: response=%v error=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	tr := transport.ProbeTranscript{Address: want.Address, Vantage: transport.VantageRelay,
		ExpectedFingerprint: want.Fingerprint, Reached: false, Error: "controlled connection refusal", ObservedAtUnix: time.Now().Unix()}
	detail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: want.EndpointID, Transcript: tr, Detail: "controlled connection refusal"}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := transport.SweepDigest(append(tr.Canonical(), '\n'))
	locked, release, lockDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		lockDone <- h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			if err := h.store.LockCertificateMetadataOrderTx(ctx, tx, h.tenant); err != nil {
				return err
			}
			close(locked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	defer close(release)
	select {
	case <-locked:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	done := make(chan error, 1)
	request := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(detail), digest)
	go func() {
		_, err := h.client.ReportJobResult(requestCtx, request)
		done <- err
	}()
	// Wait for the real PostgreSQL admission lock, not an assumed scheduling
	// delay. At that point an observation cannot yet have been appended.
	for {
		var waiting bool
		err := h.store.SystemPool().QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a ON a.pid=l.pid
			WHERE l.locktype='advisory' AND NOT l.granted AND a.datname=current_database())`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("report returned before entering observation admission: %v", err)
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	cancelRequest()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled recording returned success")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertJobNotCompleted(t, ctx, h, job.JobID)
	if t.Failed() {
		return
	}
	release <- struct{}{}
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(detail), digest))
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatalf("retry original observation on original claim: response=%v error=%v", accepted, err)
	}
	observed, err := h.store.GetEndpointVerification(ctx, h.tenant, want.EndpointID, string(transport.VantageRelay))
	if err != nil || observed.Reached || observed.ExpectedFingerprint != want.Fingerprint || observed.EvidenceDigest != tr.Digest() {
		t.Fatalf("retried observation not queryable: %+v error=%v", observed, err)
	}
}
