// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestAgentReceiptConflictingFirstReportsKeepOneObservation(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	const contenders = 8
	start := make(chan struct{})
	type result struct {
		receipt store.AgentJobReceipt
		err     error
	}
	results := make(chan result, contenders)
	var audits atomic.Int32
	audit := func(context.Context) error { audits.Add(1); return nil }
	for i := 0; i < contenders; i++ {
		go func(i int) {
			r := store.AgentJobReceipt{JobID: 42, Attempt: 1, Agent: "original-agent", Kind: "endpoint.verify",
				Outcome: "failed", State: store.AgentJobReceiptVerified, Signature: "original-signature", SignerFingerprint: "original-certificate",
				Statement: fmt.Sprintf("trstctl-agent-job-receipt/v1\ntenant=%s\nagent=original-agent\njob=42\nattempt=1\noutcome=failed\nevidence=%d\ndetail=original\nissued_at=100\n", tenantA, i)}
			<-start
			results <- result{r, s.RecordAgentJobReceiptWithAudit(ctx, tenantA, r, audit)}
		}(i)
	}
	close(start)
	var winner store.AgentJobReceipt
	var accepted, refused int
	for range contenders {
		r := <-results
		switch {
		case r.err == nil:
			accepted++
			winner = r.receipt
		case errors.Is(r.err, store.ErrAgentJobReceiptConflict):
			refused++
		default:
			t.Errorf("unexpected receipt failure: %v", r.err)
		}
	}
	if accepted != 1 || refused != contenders-1 || audits.Load() != 1 {
		t.Fatalf("conflicting observations entered audit: accepted=%d refused=%d audits=%d", accepted, refused, audits.Load())
	}
	// The same facts can be freshly attested after an outage and certificate
	// renewal. The served mTLS test separately establishes signature validity.
	retry := winner
	retry.Statement = strings.Replace(winner.Statement, "issued_at=100\n", "issued_at=200\n", 1)
	retry.Signature, retry.SignerFingerprint = "fresh-signature", "renewed-certificate"
	if err := s.RecordAgentJobReceiptWithAudit(ctx, tenantA, retry, audit); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*store.AgentJobReceipt){
		func(r *store.AgentJobReceipt) { r.Agent = "another-agent" },
		func(r *store.AgentJobReceipt) { r.Outcome = "executed" },
		func(r *store.AgentJobReceipt) {
			r.Statement = strings.Replace(r.Statement, "detail=original", "detail=changed", 1)
		},
	} {
		changed := retry
		mutate(&changed)
		if err := s.RecordAgentJobReceiptWithAudit(ctx, tenantA, changed, audit); !errors.Is(err, store.ErrAgentJobReceiptConflict) {
			t.Errorf("changed observation: %v", err)
		}
	}
	if audits.Load() != 2 {
		t.Fatalf("refused observation reached audit: %d", audits.Load())
	}
	var statement, signature, fingerprint string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT statement,signature,signer_fingerprint FROM agent_job_receipts WHERE tenant_id=$1 AND job_id=42 AND attempt=1 AND state='verified'`, tenantA).Scan(&statement, &signature, &fingerprint)
	}); err != nil {
		t.Fatal(err)
	}
	if statement != retry.Statement || signature != retry.Signature || fingerprint != retry.SignerFingerprint {
		t.Fatal("original facts or renewed attestation lost")
	}
	// A failed append cannot leave a receipt that the agent could acknowledge.
	retry.Attempt = 2
	failure := errors.New("owned audit outage")
	if err := s.RecordAgentJobReceiptWithAudit(ctx, tenantA, retry, func(context.Context) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	var count int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM agent_job_receipts WHERE tenant_id=$1 AND job_id=42 AND attempt=2`, tenantA).Scan(&count)
	}); err != nil || count != 0 {
		t.Fatalf("failed audit recorded a receipt: %d %v", count, err)
	}
}
