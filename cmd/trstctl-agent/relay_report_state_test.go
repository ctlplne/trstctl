// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
)

func TestDurableReportRefusalBlocksClaimsAndLaterAttestsOriginal(t *testing.T) {
	testDurableReportAcknowledgement(t, false)
}

func TestDurableReportReceiptOnlyAcknowledgementClearsOriginal(t *testing.T) {
	testDurableReportAcknowledgement(t, true)
}

func testDurableReportAcknowledgement(t *testing.T, receiptOnly bool) {
	t.Helper()
	for _, withCustody := range []bool{false, true} {
		name := "ordinary"
		if withCustody {
			name = "custody"
		}
		t.Run(name, func(t *testing.T) {
			var permit atomic.Bool
			var claims atomic.Int32
			var signedAt atomic.Int64
			signedAt.Store(time.Now().Add(-time.Hour).Unix())
			ch := newReceiptRetryChannel(t, func(_ context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
				if req.JobID != 91 || req.Attempt != 4 || req.Detail != "original detail" || req.IssuedAtUnix != signedAt.Load() || len(req.Signature) == 0 {
					t.Error("original report facts or current attestation missing")
				}
				if withCustody && (req.Custody == nil || req.Custody.GeneratedBy != "receipt-retry-agent" || req.CredentialFingerprint != strings.Repeat("a", 64)) {
					t.Error("original custody lost")
				}
				return &transport.ReportJobResultResponse{Accepted: permit.Load() && !receiptOnly, ReceiptRecorded: permit.Load() && receiptOnly}, nil
			}, func(s *receiptRetryChannelServer) {
				s.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
					claims.Add(1)
					return &transport.ClaimJobsResponse{}, nil
				}
			})
			ch.now = func() time.Time { return time.Unix(signedAt.Load(), 0) }
			dir := t.TempDir()
			pending, err := reportstate.Open(dir, "original-identity")
			if err != nil {
				t.Fatal(err)
			}
			ch.pending = pending
			var accepted bool
			if withCustody {
				accepted, err = ch.ReportJobResultWithCustody(t.Context(), 91, 4, transport.JobOutcomeVerified, "original detail", "", strings.Repeat("a", 64), custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable})
			} else {
				accepted, err = ch.ReportJobResult(t.Context(), 91, 4, transport.JobOutcomeFailed, "original detail", "")
			}
			if err != nil || accepted {
				t.Fatalf("expected unacknowledged result: %v, %v", accepted, err)
			}
			if _, err := ch.ClaimJobs(t.Context(), []string{"unused"}, 1, 60); err == nil || claims.Load() != 0 {
				t.Fatal("new claim allowed with refused report")
			}
			if err := pending.Close(); err != nil {
				t.Fatal(err)
			}
			pending, err = reportstate.Open(dir, "original-identity")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = pending.Close() }()
			ch.pending = pending
			signedAt.Store(time.Now().Unix())
			permit.Store(true)
			if _, err := ch.ClaimJobs(t.Context(), []string{"unused"}, 1, 60); err != nil || claims.Load() != 1 {
				t.Fatalf("recovered result did not release claiming: %v", err)
			}
			if p, err := pending.Pending(); err != nil || p != nil {
				t.Fatalf("accepted result retained: %v", err)
			}
		})
	}
}

func TestReportIdentityBindingSurvivesRenewalButNotAuthorityChange(t *testing.T) {
	ca, err := mtls.NewCA("binding-ca")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("binding-agent")
	if err != nil {
		t.Fatal(err)
	}
	defer id.Destroy()
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	const registration = "https://trstctl.com/agent/tenant-registration/v1/binding-tenant/original"
	issue := func(uris ...string) {
		t.Helper()
		chain, err := ca.SignClientCSRWithTenant(csr, "binding-tenant", []string{mtls.AgentRoleHost}, time.Hour, uris...)
		if err != nil {
			t.Fatal(err)
		}
		if err := id.UseCertificate(chain); err != nil {
			t.Fatal(err)
		}
	}
	binding := func(caPEM []byte, name string) string {
		t.Helper()
		b, err := reportIdentityBinding(id, caPEM, name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	issue(registration)
	original := binding(ca.BundlePEM(), "server")
	issue(registration)
	if binding(ca.BundlePEM(), "server") != original {
		t.Fatal("renewal changed stable registration identity")
	}
	if binding(ca.BundlePEM(), "other-server") == original || binding([]byte("different trust"), "server") == original {
		t.Fatal("server authority change kept original binding")
	}
	issue(registration + "-new")
	if binding(ca.BundlePEM(), "server") == original {
		t.Fatal("new registration kept original binding")
	}
	issue()
	legacy := binding(ca.BundlePEM(), "server")
	issue()
	if binding(ca.BundlePEM(), "server") == legacy {
		t.Fatal("unbound legacy certificate silently crossed renewal")
	}
}
