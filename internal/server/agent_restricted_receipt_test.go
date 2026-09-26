// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

func TestRestrictedTenantAcceptsOnlyOriginalTerminalReceipt(t *testing.T) {
	for _, restriction := range []string{"suspended", "offboarded"} {
		for _, outcome := range []string{transport.JobOutcomeFailed, transport.JobOutcomeExecuted} {
			t.Run(restriction+"/"+outcome, func(t *testing.T) {
				h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "endpoint.verify")
				ctx := t.Context()
				seedRoleJob(t, ctx, h, "endpoint.verify", "restricted-completion")
				claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
				if err != nil || len(claimed.Jobs) != 1 {
					t.Fatalf("active claim=%+v err=%v", claimed, err)
				}
				job := claimed.Jobs[0]
				// Reproduce a legacy restriction accepted while a remote executor
				// was still outstanding. Current lifecycle admission refuses this.
				if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `INSERT INTO provider_tenants
					 (tenant_id,slug,name,status,created_at,updated_at) VALUES ($1,'restricted','Restricted customer',$2,now(),now())`, h.tenant, restriction)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				queueState := func() string {
					t.Helper()
					var result string
					if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
						return tx.QueryRow(ctx, `SELECT to_jsonb(o)::text FROM outbox o WHERE tenant_id=$1 AND id=$2`, h.tenant, job.JobID).Scan(&result)
					}); err != nil {
						t.Fatal(err)
					}
					return result
				}
				before := queueState()
				for name, call := range map[string]func() error{
					"claim":     func() error { _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{}); return err },
					"heartbeat": func() error { _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{}); return err },
					"redeem": func() error {
						_, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
						return err
					},
					"sign": func() error {
						_, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt})
						return err
					},
					"extend": func() error {
						_, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeExtend, LeaseSeconds: 60})
						return err
					},
					"rollback": func() error {
						_, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeAuthorizeRollback})
						return err
					},
				} {
					if err := call(); status.Code(err) != codes.PermissionDenied {
						t.Errorf("restricted %s was not refused: %v", name, err)
					}
				}
				if _, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: job.Attempt, Outcome: outcome}); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("unsigned restricted receipt: %v", err)
				}
				if err := h.store.RequireTenantAgentWorkQuiescent(ctx, h.tenant); !errors.Is(err, store.ErrTenantServiceBusy) {
					t.Fatalf("unverified reports cleared remote executor: %v", err)
				}
				request := h.report(t, job.JobID, job.Attempt, outcome, "original executor has stopped", "")
				unknown := h.report(t, job.JobID, job.Attempt+1, outcome, "unissued attempt", "")
				if result, err := h.client.ReportJobResult(ctx, unknown); err != nil || result.Accepted || result.ReceiptRecorded {
					t.Fatalf("unissued restricted attempt accepted: %+v %v", result, err)
				}
				if result, err := h.client.ReportJobResult(ctx, request); err != nil || result.Accepted || !result.ReceiptRecorded || result.LeaseExpiresUnix != 0 {
					t.Fatalf("restricted original completion cannot recover: %+v %v", result, err)
				}
				if queueState() != before {
					t.Fatal("receipt recovery changed a restricted tenant's queue or claim")
				}
				if err := h.store.RequireTenantAgentWorkQuiescent(ctx, h.tenant); err != nil {
					t.Fatalf("verified completion did not clear remote executor: %v", err)
				}
				if _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1}); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("accepted receipt restored permission to claim work: %v", err)
				}
				if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error {
					_, err := h.client.ReportJobResult(ctx, request)
					if status.Code(err) != codes.Unavailable {
						t.Errorf("receipt crossed exclusive lifecycle barrier: %v", err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				// Revocation remains authoritative even for observation-only recovery.
				if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					return h.store.ApplyAgentCertRevokedTx(ctx, tx, store.AgentCertRevocation{TenantID: h.tenant, AgentID: agentRowID(h.tenant, h.agent), SelectorType: "serial", Selector: h.identity.CertificateSerial(), RevokedAt: time.Now()})
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := h.client.ReportJobResult(ctx, request); status.Code(err) != codes.PermissionDenied {
					t.Errorf("revoked certificate could report: %v", err)
				}
				offboardServedTestTenant(t, h.servedHarness)
				if _, err := h.client.ReportJobResult(ctx, request); status.Code(err) != codes.PermissionDenied {
					t.Errorf("deleted tenant could report: %v", err)
				}
			})
		}
	}
}

func TestReceiptRecoveryDoesNotBypassUnavailableServiceAuthority(t *testing.T) {
	var unavailable atomic.Bool
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"endpoint.verify"}, func(d *Deps) {
		d.TenantServiceCheck = func(context.Context, string) error {
			if unavailable.Load() {
				return errors.New("owned service registry outage")
			}
			return nil
		}
	})
	ctx := t.Context()
	seedRoleJob(t, ctx, h, "endpoint.verify", "receipt-authority-outage")
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	request := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "executor stopped", "")
	unavailable.Store(true)
	if _, err := h.client.ReportJobResult(ctx, request); status.Code(err) != codes.Unavailable {
		t.Fatalf("authority outage did not refuse the receipt: %v", err)
	}
	if err := h.store.RequireTenantAgentWorkQuiescent(ctx, h.tenant); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("authority outage released remote completion: %v", err)
	}
	unavailable.Store(false)
	if result, err := h.client.ReportJobResult(ctx, request); err != nil || !result.Accepted {
		t.Fatalf("same report failed after authority recovery: %+v %v", result, err)
	}
}
