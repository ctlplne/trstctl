// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func rollbackRevocationFixture(t *testing.T) (*roleHarness, store.Certificate, orchestrator.ConnectorRollbackRequest) {
	t.Helper()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "connector.rollback")
	svc := app.New(h.log, h.store, nil)
	t.Cleanup(svc.Close)
	if err := svc.RegisterTenant(t.Context(), h.tenant, "rollback-guard", "rollback-guard-bootstrap"); err != nil {
		t.Fatal(err)
	}
	issued, err := testExternalCACertificate(ca.IssueRequest{CSR: serverTestCSR(t, "rollback-guard.test", nil), DNSNames: []string{"rollback-guard.test"}}, "Rollback test CA")
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certinfo.LeafDER(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
		Fingerprint: info.SHA256Fingerprint, Serial: info.SerialNumber, Source: "import",
		Subject: info.Subject, Issuer: info.Issuer, SANs: info.DNSNames,
		CertificateDER: der, CertificatePEM: issued.CertificatePEM,
		NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, cert, orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "owned-test-target", PredecessorFingerprint: cert.Fingerprint, PredecessorSerial: cert.Serial}
}

func revokeRollbackPredecessor(t *testing.T, h *roleHarness, cert store.Certificate) {
	t.Helper()
	if err := h.srv.orch.RevokeCertificate(t.Context(), h.tenant, cert.Fingerprint, cert.Serial, "keyCompromise", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackCannotQueueARevokedPredecessor(t *testing.T) {
	h, cert, request := rollbackRevocationFixture(t)
	revokeRollbackPredecessor(t, h, cert)
	if queued, err := h.srv.orch.RequestConnectorRollback(t.Context(), h.tenant, request); err == nil || queued.Queued {
		t.Fatalf("revoked predecessor queued: queued=%t error=%v", queued.Queued, err)
	}
	rows, err := h.srv.outbox.Pending(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Destination == orchestrator.DestinationConnectorRollback {
			t.Fatal("unsafe request left an executable rollback intent")
		}
	}
}

func TestQueuedRollbackIsRefusedIfPredecessorRevokedBeforeClaim(t *testing.T) {
	h, cert, request := rollbackRevocationFixture(t)
	queued, err := h.srv.orch.RequestConnectorRollback(t.Context(), h.tenant, request)
	if err != nil {
		t.Fatal(err)
	}
	revokeRollbackPredecessor(t, h, cert)
	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{"connector.rollback"}, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed.Jobs) != 0 {
		t.Fatal("a queued rollback handed a revoked predecessor to the agent")
	}
	job, err := h.store.GetHostRotationJob(t.Context(), h.tenant, queued.OutboxID)
	if err != nil || job.Status != "failed" {
		t.Fatalf("unsafe work should stop retrying: status=%s error=%v", job.Status, err)
	}
	var receipt store.ConnectorDeliveryReceipt
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		var err error
		receipt, err = h.store.GetConnectorDeliveryReceiptForOutboxTx(t.Context(), tx, h.tenant, queued.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "rollback_refused" || receipt.Reason != "rollback_refused_by_control_plane" {
		t.Fatalf("withheld work has no truthful refusal receipt: %+v", receipt)
	}
}

func TestRollbackRefusesUnknownPredecessorAndRevokedIdentity(t *testing.T) {
	h, _, request := rollbackRevocationFixture(t)
	unknown := request
	unknown.PredecessorFingerprint = "not-in-this-tenant"
	if _, err := h.srv.orch.RequestConnectorRollback(t.Context(), h.tenant, unknown); !errors.Is(err, store.ErrUnsafeRollback) {
		t.Fatalf("unknown predecessor was not refused: %v", err)
	}
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "service", "revoked identity owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "rollback-guard.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateIssued, "fixture issued"); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateRevoked, "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	request.IdentityID = identity.ID
	// The CA worker has not run: the certificate is still active, but an
	// accepted identity revocation already forbids restoring its key material.
	if _, err := h.srv.orch.RequestConnectorRollback(t.Context(), h.tenant, request); !errors.Is(err, store.ErrUnsafeRollback) {
		t.Fatalf("revoked identity with active certificate was not refused: %v", err)
	}
	if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateRetired, "finished containment"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RequestConnectorRollback(t.Context(), h.tenant, request); !errors.Is(err, store.ErrUnsafeRollback) {
		t.Fatalf("retired identity was not refused: %v", err)
	}
}

func TestClaimedRollbackNeedsCurrentRevocationAndAttemptCheck(t *testing.T) {
	h, cert, request := rollbackRevocationFixture(t)
	if _, err := h.srv.orch.RequestConnectorRollback(t.Context(), h.tenant, request); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{"connector.rollback"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: response=%v error=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	check := func(ctx context.Context, attempt int) bool {
		resp, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: attempt, Outcome: transport.JobOutcomeAuthorizeRollback})
		return err == nil && resp.Accepted
	}
	if !check(t.Context(), job.Attempt) {
		t.Fatal("valid rollback was not confirmed")
	}
	if check(t.Context(), job.Attempt+1) {
		t.Error("wrong claim generation authorized rollback")
	}
	revokeRollbackPredecessor(t, h, cert)
	if check(t.Context(), job.Attempt) {
		t.Error("already claimed work stayed authorized after predecessor revocation")
	}
}
