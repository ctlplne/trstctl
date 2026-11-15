// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
)

// TestLateHostReceiptKeepsTheRetainedKeyForTheReofferedAttemptB4O1: a host
// renewal's terminal report that reaches the control plane after its claim
// lapsed is recorded (a late receipt), not accepted, and the job is offered
// again as a new attempt, which reuses the key and certificate the first
// attempt retained. The agent read the recorded receipt as acceptance and
// cleared that key, so the re-offered attempt failed for good
// (host_key_not_retained). The late receipt now settles the durable report,
// so claiming resumes, and reads not accepted; the key and certificate stay
// until the re-offered attempt's report is accepted.
func TestLateHostReceiptKeepsTheRetainedKeyForTheReofferedAttemptB4O1(t *testing.T) {
	const tenant = "receipt-retry-tenant"
	const connector, target = "apache", "target-a"
	const jobID int64 = 91
	binding := strings.Repeat("b", 64)
	fingerprint := strings.Repeat("a", 64)
	rollback, err := relay.NewHostRollbackStore(t.TempDir(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := rollback.RecordHostRenewKey(connector, target, jobID, binding, []byte("csr"), []byte("private-key")); err != nil {
		t.Fatal(err)
	}
	if err := rollback.RecordHostRenewCertificate(connector, target, jobID, binding, []byte("certificate"), nil, fingerprint); err != nil {
		t.Fatal(err)
	}
	var claims atomic.Int32
	ch := newReceiptRetryChannel(t, func(_ context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		if req.JobID != jobID || req.CredentialFingerprint != fingerprint {
			t.Error("the report lost its job or certificate identity")
		}
		if req.Attempt == 1 {
			// The first attempt's claim lapsed and the job was re-offered:
			// its report is kept as a late receipt.
			return &transport.ReportJobResultResponse{ReceiptRecorded: true}, nil
		}
		return &transport.ReportJobResultResponse{Accepted: true}, nil
	}, func(s *receiptRetryChannelServer) {
		s.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
			claims.Add(1)
			return &transport.ClaimJobsResponse{}, nil
		}
	})
	ch.hostRollback = rollback
	pending, err := reportstate.Open(t.TempDir(), "original-identity")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pending.Close() }()
	ch.pending = pending
	record := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable}

	accepted, err := ch.ReportHostRenewResultWithCustody(t.Context(), jobID, 1, transport.JobOutcomeVerified,
		"installed and verified", "", fingerprint, record, connector, target, binding)
	if err != nil {
		t.Fatal(err)
	}
	if accepted {
		t.Error("a late receipt read as accepted: the relay would release what the re-offered attempt needs")
	}
	if value, err := pending.Pending(); err != nil || value != nil {
		t.Fatalf("the recorded late receipt left its durable report pending: %v", err)
	}
	if _, err := ch.ClaimJobs(t.Context(), []string{"endpoint.renew"}, 1, 60); err != nil || claims.Load() != 1 {
		t.Fatalf("claiming did not resume after the late receipt: %v", err)
	}
	kept, err := rollback.LoadHostRenewPending(connector, target, jobID, binding)
	if err != nil || kept == nil {
		t.Fatalf("the late receipt released the retained key and certificate: present=%v err=%v", kept != nil, err)
	}
	if !bytes.Equal(kept.KeyPEM, []byte("private-key")) || !bytes.Equal(kept.CertPEM, []byte("certificate")) || kept.Fingerprint != fingerprint {
		t.Fatal("the retained key or certificate changed")
	}
	secret.Wipe(kept.KeyPEM)

	// The re-offered attempt reuses them; its accepted report releases them.
	accepted, err = ch.ReportHostRenewResultWithCustody(t.Context(), jobID, 2, transport.JobOutcomeVerified,
		"installed and verified", "", fingerprint, record, connector, target, binding)
	if err != nil || !accepted {
		t.Fatalf("the re-offered attempt's report: accepted=%v %v", accepted, err)
	}
	if value, err := rollback.LoadHostRenewPending(connector, target, jobID, binding); err != nil || value != nil {
		t.Fatalf("the accepted re-offered attempt left the retained key: %v", err)
	}
}
