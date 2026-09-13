// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestEndpointVerificationCannotAppendAheadOfCertificateMetadata(t *testing.T) {
	st := newServerTestStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "events")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	// The served suite shares PostgreSQL. Keep this observation outside the
	// scheduler fixture's tenant, which counts all of its endpoint rows.
	const tenant = "04550000-0000-4000-8000-000000000001"
	payload, err := json.Marshal(map[string]string{"name": "endpoint ordering"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := log.Append(ctx, events.Event{TenantID: tenant, Type: projections.EventTenantRegistered, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	if err := projector.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, log: log, orch: orchestrator.NewOrchestrator(log, st, nil)}
	transcript := transport.ProbeTranscript{
		Address: "mail.example.test:465", Vantage: transport.VantageLocal,
		Reached: true, ExpectedFingerprint: strings.Repeat("a", 64), ObservedFingerprint: strings.Repeat("a", 64),
		ObservedAtUnix: time.Now().Unix(),
	}
	locked, release, lockDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		lockDone <- st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := st.LockCertificateMetadataOrderTx(ctx, tx, tenant); err != nil {
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
	done := make(chan error, 1)
	go func() {
		done <- srv.appendEndpointVerification(ctx, tenant, "mail-host", "mail-target", transcript, "")
	}()
	select {
	case err := <-done:
		t.Fatalf("endpoint observation returned before the earlier metadata holder released admission: %v", err)
	case <-time.After(time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Cancellation while waiting must not leave a retained observation for
	// the tail to apply later, after the caller has already reported failure.
	waitCtx, waitCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	err = srv.appendEndpointVerification(waitCtx, tenant, "mail-host", "cancelled-target", transcript, "")
	waitCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled metadata admission returned %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != registered.Sequence {
		t.Fatalf("endpoint source append overtook metadata admission: head=%d err=%v", head, err)
	}
	release <- struct{}{}
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	check := func() {
		t.Helper()
		rows, err := st.ListEndpointVerifications(ctx, tenant)
		if err != nil || len(rows) != 1 || rows[0].ObservedFingerprint != transcript.ObservedFingerprint || rows[0].EvidenceDigest != transcript.Digest() {
			t.Fatalf("exact endpoint observation unavailable: rows=%+v err=%v", rows, err)
		}
	}
	// Returning from ingestion means the observation is queryable, without
	// requiring the asynchronous tail to win a race against the next issuance.
	check()
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check()
}
