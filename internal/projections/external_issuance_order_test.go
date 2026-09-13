// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

type observedIssuingCA struct {
	ca.CA
	issued chan struct{}
}

func (c observedIssuingCA) Issue(ctx context.Context, request ca.IssueRequest) (ca.Certificate, error) {
	result, err := c.CA.Issue(ctx, request)
	close(c.issued)
	return result, err
}

func TestExternalIssuanceCannotAppendAheadOfCertificateMetadataFence(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	event, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("external-order")})
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(s)
	if err := projector.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	builtin, err := ca.NewBuiltin("ordered-external-ca")
	if err != nil {
		t.Fatal(err)
	}
	issued := make(chan struct{})
	service := ca.NewIssuanceService(observedIssuingCA{builtin, issued}, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s,
		ca.WithAuditLog(log), ca.WithOutboxIssueWorker("ordered-external-ca", nil))
	const key = "external-metadata-order"
	payload, err := json.Marshal(ca.ExternalIssuePayload{AuthorityID: "ordered-external-ca", TenantID: tenantA, CSR: issuanceCSR(t),
		TTLNanos: int64(time.Hour), ProviderIdempotencyKey: ca.ProviderIdempotencyKey(key), RequestBinding: "order-test"})
	if err != nil {
		t.Fatal(err)
	}
	locked, release, lockDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		lockDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantA); err != nil {
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
		done <- service.DeliverExternalIssue(ctx, orchestrator.Message{TenantID: tenantA,
			Destination: ca.DestinationExternalCAIssue, IdempotencyKey: key, Payload: payload})
	}()
	select {
	case <-issued:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// The real CA already returned a certificate. The earlier metadata holder
	// still owns admission, so this issuer must not have a source sequence yet.
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantA+"\x00certificate.recorded\x00"+key)).String()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if _, found, err := log.EventByID(ctx, id); err != nil || found {
				t.Fatalf("external source append overtook the metadata holder: found=%t err=%v", found, err)
			}
		case <-deadline.C:
			// Send instead of close: deferred close remains safe on all exits.
			release <- struct{}{}
			if err := <-lockDone; err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := projector.ProjectCatchUp(ctx, log); err != nil {
				t.Fatal(err)
			}
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			rows, err := s.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantA, key)
			if err != nil || len(rows) != 1 {
				t.Fatalf("ordered replay lost or duplicated issuance: rows=%d err=%v", len(rows), err)
			}
			return
		}
	}
}
