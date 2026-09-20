// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func preparedRecoveryRequest(t *testing.T, h *issuanceDispatcherHarness) (context.Context, store.IssuanceRequest, store.Identity, orchestrator.Message) {
	t.Helper()
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "original-issuer@example.test"})
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "recovery-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: serverTestCSR(t, "request-recovery.example.test", nil)})
	request, err := h.orch.OpenIssuanceRequest(ctx, h.tenant, projections.IssuanceRequestOpened{
		Subject: "request-recovery.example.test", OwnerID: owner.ID, CSRPEM: string(csr),
		Requester: "requester@example.test", Justification: "Recover the recorded first issuance", Origin: "console",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.orch.DecideIssuanceRequest(ctx, h.tenant, request.ID, issuancerequest.StateApproved, "reviewer@example.test", "approved", ""); err != nil {
		t.Fatal(err)
	}
	request, identity, err := h.orch.PrepareIssuanceRequest(ctx, h.tenant, request.ID, "original-issuer@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.orch.CompleteIssuanceRequest(ctx, h.tenant, request.ID); !errors.Is(err, orchestrator.ErrIssuanceRequestNotReady) {
		t.Fatalf("completion without signing evidence: %v", err)
	}
	key := orchestrator.IssuanceRequestIssueIdempotencyKey(request.ID)
	if err = h.orch.TransitionWithSubjectCSR(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "fulfill approved request", key, string(csr)); err != nil {
		t.Fatal(err)
	}
	row := pendingOutboxByDestination(t, h, "ca.issue")
	return ctx, request, identity, orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey, Attempts: 1}
}

func TestIssuanceRequestCompletesWithoutBrowserCallback(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx, request, identity, message := preparedRecoveryRequest(t, h)
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	stored, err := h.store.GetIssuanceRequest(ctx, h.tenant, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != issuancerequest.StateIssued || stored.IdentityID != identity.ID || stored.IssuedBy != "original-issuer@example.test" || stored.IssuedAt == nil {
		t.Fatalf("signing completed but request did not complete without a browser callback: %+v", stored)
	}
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("retry minted %d certificates", len(certs))
	}
	count := 0
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == projections.EventIssuanceRequestIssued {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("completion events=%d, want1", count)
	}
}

func TestIssuanceRequestLateCompletionPreservesTerminalCertificate(t *testing.T) {
	for _, terminal := range []orchestrator.State{orchestrator.StateRevoked, orchestrator.StateRetired} {
		t.Run(string(terminal), func(t *testing.T) {
			h := newIssuanceDispatcherHarness(t)
			ctx, request, identity, message := preparedRecoveryRequest(t, h)
			interrupted := errors.New("interrupted after signing and recording")
			h.handler.afterIssueSideEffects = func(context.Context) error { return interrupted }
			if err := h.handler.Deliver(ctx, message); !errors.Is(err, interrupted) {
				t.Fatalf("injected interruption: %v", err)
			}
			certs := dispatcherCertificates(t, h)
			if len(certs) != 1 {
				t.Fatalf("recorded certificates=%d", len(certs))
			}
			certificate := certs[0]
			if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRevoked, "retire after compromise"); err != nil {
				t.Fatal(err)
			}
			if err := h.orch.RevokeCertificate(ctx, h.tenant, certificate.Fingerprint, certificate.Serial, "keyCompromise", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if terminal == orchestrator.StateRetired {
				if err := h.orch.Transition(ctx, h.tenant, identity.ID, terminal, "retained historical proof"); err != nil {
					t.Fatal(err)
				}
			}
			before, err := h.store.GetCertificate(ctx, h.tenant, certificate.ID)
			if err != nil {
				t.Fatal(err)
			}
			completed, err := h.orch.CompleteIssuanceRequest(events.ContextWithActor(ctx, events.Actor{Subject: "recovery-operator@example.test"}), h.tenant, request.ID)
			if err != nil {
				t.Fatalf("historical issuance cannot be recovered after %s: %v", terminal, err)
			}
			if completed.Status != issuancerequest.StateIssued || completed.IdentityID != identity.ID || completed.IssuedBy != "original-issuer@example.test" || completed.IssuedAt == nil || !completed.IssuedAt.Equal(certificate.CreatedAt) {
				t.Fatalf("completion: %+v", completed)
			}
			after, err := h.store.GetCertificate(ctx, h.tenant, certificate.ID)
			if err != nil {
				t.Fatal(err)
			}
			current, err := h.store.GetIdentity(ctx, h.tenant, identity.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Status != string(terminal) || after.Status != "revoked" || after.Fingerprint != before.Fingerprint || after.RevokedAt == nil || !after.RevokedAt.Equal(*before.RevokedAt) {
				t.Fatalf("completion changed terminal identity/certificate: %+v %+v", current, after)
			}
			if len(dispatcherCertificates(t, h)) != 1 {
				t.Fatal("completion minted another certificate")
			}
		})
	}
}

func TestIssuanceRequestWorkerRecoversRecordedResultAfterRetirement(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx, request, identity, message := preparedRecoveryRequest(t, h)
	interrupted := errors.New("interrupted after signing before request completion")
	h.handler.afterIssueSideEffects = func(context.Context) error { return interrupted }
	if err := h.handler.Deliver(ctx, message); !errors.Is(err, interrupted) {
		t.Fatalf("injected interruption: %v", err)
	}
	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("recorded certificates=%d", len(certs))
	}
	certificate := certs[0]
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRevoked, "revoke before worker resumes"); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.RevokeCertificate(ctx, h.tenant, certificate.Fingerprint, certificate.Serial, "keyCompromise", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRetired, "retire before worker resumes"); err != nil {
		t.Fatal(err)
	}
	// If recovery reaches a signing side effect, fail before any second mint.
	h.handler.afterIssueSideEffects = nil
	h.handler.issue = func(context.Context, []byte, time.Duration, crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		t.Error("recovery attempted another signature")
		return crypto.IssuedLeaf{}, errors.New("must not sign")
	}
	message.Attempts = 2
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatalf("worker cannot recover the exact recorded result: %v", err)
	}
	completed, err := h.store.GetIssuanceRequest(ctx, h.tenant, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != issuancerequest.StateIssued || completed.IssuedBy != "original-issuer@example.test" {
		t.Fatalf("request remains unresolved: %+v", completed)
	}
	current, err := h.store.GetIdentity(ctx, h.tenant, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != "retired" || len(dispatcherCertificates(t, h)) != 1 {
		t.Fatal("worker changed terminal identity or signed another certificate")
	}
}

func TestIssuanceRequestPrefixDoesNotReserveOrdinaryIdempotencyKeys(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "ordinary-key-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "ordinary-key.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.orch.TransitionWithIdempotency(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "ordinary operator issuance", "issuance-request-issue:operator-workflow"); err != nil {
		t.Fatal(err)
	}
	row := pendingOutboxByDestination(t, h, "ca.issue")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey, Attempts: 1}
	if err = h.handler.Deliver(ctx, message); err != nil {
		t.Fatalf("ordinary key mistaken for a first-class request: %v", err)
	}
	if err = h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	if len(dispatcherCertificates(t, h)) != 1 {
		t.Fatal("ordinary retry did not retain exactly one certificate")
	}
	if err = h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == projections.EventIssuanceRequestIssued {
			t.Error("ordinary issuance fabricated a request completion")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
