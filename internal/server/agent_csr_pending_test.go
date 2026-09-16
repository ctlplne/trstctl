// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A queued issuance that has not reached its worker is pending, not a terminal
// signing failure. Keep the real request and claim, then recover its one result.
// This tests the served RPC with real PostgreSQL, NATS and signer; the external
// authority is an explicit deterministic test adapter, not vendor qualification.
func TestServedAgentCSRPendingKeepsExactRequestRecoverable(t *testing.T) {
	ctx := context.Background()
	const authority = "pending-agent-csr"
	upstream := &returnedResultTestCA{name: authority, minted: make(chan ca.Certificate, 1)}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: authority, Type: "non-replayable-test", CA: upstream}}
	})
	seedRenewalJob(t, ctx, h, "renew:pending-exact-csr", []string{"pending-agent.example.test"})
	// Configure this test's unclaimed queue fixture before its first lease.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, "renew:pending-exact-csr").Scan(&raw); err != nil {
			return err
		}
		var intent RelayDeployIntent
		if err := json.Unmarshal(raw, &intent); err != nil {
			return err
		}
		intent.IssuingAuthoritySource, intent.IssuingAuthorityID = "external", authority
		payload, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND idempotency_key=$2 AND claim_attempts=0`, h.tenant, "renew:pending-exact-csr", payload)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{agentJobKindEndpointRenew}, Limit: 1, LeaseSeconds: 10,
	})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim short-lived job: %v", err)
	}
	job := claimed.Jobs[0]
	// The original ten-second claim cannot survive the thirty-second result
	// wait. Extend over the served channel while issuance holds its identity
	// fence; an extension accidentally sharing that fence would deadlock here.
	leaseCtx, stopLease := context.WithCancel(ctx)
	leaseDone := make(chan error, 1)
	var extensions atomic.Int64
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				leaseDone <- nil
				return
			case <-ticker.C:
				callCtx, cancel := context.WithTimeout(leaseCtx, 2*time.Second)
				resp, err := h.client.ReportJobResult(callCtx, &transport.ReportJobResultRequest{
					JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeExtend, LeaseSeconds: 10,
				})
				cancel()
				if err != nil || !resp.Accepted || resp.LeaseExpiresUnix <= time.Now().Unix() {
					if leaseCtx.Err() != nil {
						leaseDone <- nil
					} else {
						leaseDone <- fmt.Errorf("claim extension unavailable or refused: %v", err)
					}
					return
				}
				extensions.Add(1)
			}
		}
	}()
	defer func() {
		stopLease()
		if err := <-leaseDone; err != nil {
			t.Error(err)
		}
	}()
	key, err := crypto.GenerateHostSubjectKey("pending-agent.example.test", []string{"pending-agent.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	request := &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER}
	start := time.Now()
	response, pendingErr := h.client.SignJobCSR(ctx, request)
	t.Logf("first signing response: code=%s elapsed=%s", status.Code(pendingErr), time.Since(start))
	if response != nil || pendingErr == nil || upstream.calls.Load() != 0 {
		t.Fatal("unstarted external worker produced a certificate or provider call")
	}
	issueKey := fmt.Sprintf("agentcsr:%d:%d:%s:external-ca:%s", job.JobID, job.Attempt, crypto.SHA256Hex(key.CSRDER)[:16], authority)
	intentID := externalCAIntentOutboxID(t, h.servedHarness, issueKey)
	queued, err := h.srv.outbox.Get(ctx, h.tenant, intentID)
	if err != nil || queued.Status != "pending" || queued.Attempts != 0 {
		t.Fatalf("pending request lost its durable queue intent: status=%s attempts=%d err=%v", queued.Status, queued.Attempts, err)
	}
	if _, held, err := h.store.GetAgentJobForRedemption(ctx, h.tenant, agentRowID(h.tenant, h.agent), job.JobID, time.Now().UTC()); err != nil || !held {
		t.Fatalf("claim was lost before the pending response: held=%t err=%v", held, err)
	}
	startServedExternalCADispatcher(t, h.servedHarness)
	// Deterministically place the external result in its durable read model
	// before the same CSR retries; a fast RPC must not hide this race.
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows, err := h.store.ListCertificatesByIssuanceIdempotencyKey(ctx, h.tenant, issueKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			break
		}
		if len(rows) > 1 || time.Now().After(deadline) {
			t.Fatalf("external result was not recorded once before retry: rows=%d", len(rows))
		}
		time.Sleep(20 * time.Millisecond)
	}
	recovered, err := h.client.SignJobCSR(ctx, request)
	if err != nil || recovered == nil || len(recovered.CertificatePEM) == 0 || recovered.Fingerprint == "" {
		t.Fatalf("same CSR/claim did not recover: %v", err)
	}
	select {
	case issued := <-upstream.minted:
		if !bytes.Equal(recovered.CertificatePEM, issued.CertificatePEM) {
			t.Fatal("retry did not recover the exact externally issued public certificate")
		}
	default:
		t.Fatal("external authority did not retain the original public result")
	}
	otherKey, err := crypto.GenerateHostSubjectKey("pending-agent.example.test", []string{"pending-agent.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer otherKey.Destroy()
	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: otherKey.CSRDER}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("different CSR on the same claim was not refused: %v", err)
	}
	if upstream.calls.Load() != 1 {
		t.Fatalf("provider calls=%d, want exactly one", upstream.calls.Load())
	}
	if extensions.Load() < 3 {
		t.Fatalf("pending signing did not retain a short claim through the served extension RPC: extensions=%d", extensions.Load())
	}
	if status.Code(pendingErr) != codes.Unavailable {
		t.Fatalf("pending request reported %s; want retryable Unavailable while preserving the same CSR and lease", status.Code(pendingErr))
	}
	if delay, pending := transport.CSRPendingRetryDelay(pendingErr); !pending || delay <= 0 || delay > 5*time.Second {
		t.Fatal("pending response omitted its typed marker and bounded retry delay")
	}
}
