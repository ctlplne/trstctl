// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

func TestAgentAuditAppendFailureLogsRoutingMetadataWithoutPayload(t *testing.T) {
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	var output bytes.Buffer
	service := &agentService{log: log, logger: slog.New(slog.NewJSONHandler(&output, nil))}
	const canary = "private-payload-must-not-be-logged"
	service.recordAgentJobEvent(ctx, "tenant-1", "agent.jobs.claimed", map[string]any{
		"agent": canary, "count": 1, "kinds": []string{"connector.deploy"}, "undeclared": canary,
	})
	var diagnostic map[string]any
	if err := json.Unmarshal(output.Bytes(), &diagnostic); err != nil {
		t.Fatalf("missing structured audit failure diagnostic: %v", err)
	}
	if diagnostic["level"] != "ERROR" || diagnostic["tenant_id"] != "tenant-1" || diagnostic["event_type"] != "agent.jobs.claimed" {
		t.Errorf("audit failure missing routing metadata: %v", diagnostic)
	}
	if strings.Contains(output.String(), canary) || strings.Contains(output.String(), "undeclared") {
		t.Error("audit failure diagnostic exposed event payload or validation detail")
	}
	retained := 0
	if err := log.Replay(ctx, 0, func(events.Event) error { retained++; return nil }); err != nil {
		t.Fatal(err)
	}
	if retained != 0 {
		t.Fatalf("malformed audit event bypassed the production guard: %d retained", retained)
	}
}

func TestAgentProductionPrivacyGuardRetainsClaimAndTerminalAudit(t *testing.T) {
	for _, outcome := range []string{transport.JobOutcomeExecuted, transport.JobOutcomeFailed} {
		t.Run(outcome, func(t *testing.T) {
			h := newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"},
				[]events.OpenOption{events.WithRequiredPrivacyEventPolicies()})
			ctx := t.Context()
			seedRoleJob(t, ctx, h, "connector.deploy", "production-audit")
			claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
			if err != nil || len(claimed.Jobs) != 1 {
				t.Fatalf("claim: %+v %v", claimed, err)
			}
			job := claimed.Jobs[0]
			if _, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: job.Attempt, Outcome: outcome}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("unsigned result was not refused: %v", err)
			}
			request := h.report(t, job.JobID, job.Attempt, outcome, "owned terminal observation", "owned-evidence")
			if accepted, err := h.client.ReportJobResult(ctx, request); err != nil || !accepted.Accepted {
				t.Fatalf("signed result: %+v %v", accepted, err)
			}
			terminal := "agent.job.executed"
			if outcome == transport.JobOutcomeFailed {
				terminal = "agent.job.failed"
			}
			counts := map[string]int{}
			if err := h.log.Replay(ctx, 0, func(e events.Event) error {
				if e.TenantID != h.tenant {
					return nil
				}
				switch e.Type {
				case "agent.jobs.claimed", "agent.job.receipt.rejected", terminal:
				default:
					return nil
				}
				counts[e.Type]++
				if e.Type == terminal {
					var payload struct {
						Statement string `json:"receipt_statement"`
						Signature string `json:"receipt_signature"`
					}
					if err := json.Unmarshal(e.Data, &payload); err != nil {
						return err
					}
					sig, err := base64.StdEncoding.DecodeString(payload.Signature)
					if err != nil {
						return err
					}
					if err := mtls.VerifyStatement(h.identity.Identity().CertificateDER(), []byte(payload.Statement), sig); err != nil {
						t.Errorf("retained terminal signature invalid: %v", err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"agent.jobs.claimed", "agent.job.receipt.rejected", terminal} {
				if counts[kind] != 1 {
					t.Errorf("successful production flow retained %d %s events, want 1", counts[kind], kind)
				}
			}
		})
	}
}
