// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// recordDiscoveryScan ingests the detail covered by a verified relay receipt.
// ReportJobResult invokes it while the exact lease is still held; any error
// leaves that claim open so the signed report can be retried.
func (s *Server) recordDiscoveryScan(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	if s.orch == nil || s.store == nil {
		return errors.New("discovery relay receiver is not configured")
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return errors.New("discovery relay report exceeds the receiver bound")
	}
	var intent segmentscan.Intent
	if err := decodeStrictJSON(jobPayload, &intent); err != nil {
		return fmt.Errorf("decode discovery relay command: %w", err)
	}
	agentID := agentRowID(tenantID, agentName)
	if intent.RequiredAgentID != "" && intent.RequiredAgentID != agentID {
		return errors.New("discovery relay receipt does not match the selected agent")
	}
	var report segmentscan.Report
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil {
		return fmt.Errorf("decode discovery relay report: %w", err)
	}
	if err := segmentscan.ValidateReport(intent, report); err != nil {
		return err
	}

	run, err := s.store.GetDiscoveryRun(ctx, tenantID, intent.ID)
	if err != nil {
		return err
	}
	if run.SourceID != intent.SourceID || run.Execution != segmentscan.ExecutionRelay ||
		run.Segment != intent.Segment || run.RequiredAgentRole != intent.RequiredAgentRole ||
		run.RequiredAgentID != intent.RequiredAgentID {
		return errors.New("discovery relay command does not match its projected run")
	}
	if discoveryRunTerminal(run.Status) {
		if run.ExecutedByAgentID == agentID {
			return nil
		}
		return errors.New("discovery relay run is already terminal under another executor")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return errors.New("discovery relay claim has no durable idempotency key")
	}
	if run.Status == "queued" {
		if err := s.orch.StartDiscoveryRunWithEventID(ctx, tenantID, intent.ID,
			orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "run-started")); err != nil {
			return err
		}
	}

	if !intent.DryRun {
		for _, finding := range report.Findings {
			if err := s.recordRelayDiscoveryFinding(ctx, tenantID, agentID, idempotencyKey, intent, finding); err != nil {
				return err
			}
		}
	}
	status, reason := segmentscan.Status(report)
	if err := s.orch.CompleteDiscoveryRunWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "run-completed"), store.DiscoveryRun{
			ID: intent.ID, Status: status, Targets: report.Targets, Discovered: report.Discovered,
			Failed: report.Failed, Rejected: report.Rejected, Blocked: report.Blocked, Error: reason,
			Segment: intent.Segment, ExecutedByAgentID: agentID,
			TargetResults: relayTargetResults(report),
		}); err != nil {
		return err
	}
	return nil
}

func (s *Server) recordRelayDiscoveryFinding(ctx context.Context, tenantID, agentID, idempotencyKey string, intent segmentscan.Intent, finding segmentscan.Finding) error {
	metadata := map[string]any{
		"location": finding.Address, "segment": intent.Segment,
		"executed_by_agent_id": agentID, "key_material_present": false,
	}
	kind := "x509_certificate"
	provenance := "network-relay:" + intent.Segment + ":" + finding.Address
	riskScore := 50
	if intent.Mode == segmentscan.ModeTLS {
		notBefore, err := relayFindingTime(finding.NotBefore)
		if err != nil {
			return err
		}
		notAfter, err := relayFindingTime(finding.NotAfter)
		if err != nil {
			return err
		}
		metadata["subject"] = finding.Subject
		metadata["issuer"] = finding.Issuer
		metadata["serial"] = finding.Serial
		metadata["sans"] = finding.SANs
		metadata["not_before"] = notBefore
		metadata["not_after"] = notAfter
		metadata["key_algorithm"] = finding.KeyType
		metadata["public_key_bits"] = finding.PublicKeyBits
		metadata["is_ca"] = finding.IsCA
		riskScore = discoveryRiskScore(notAfter)
		observation := intent.Mode + "\x00" + finding.Address + "\x00" + finding.Fingerprint
		if _, err := s.orch.RecordCertificateWithEventID(ctx, tenantID,
			orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "certificate\x00"+observation), store.Certificate{
				Subject: finding.Subject, SANs: finding.SANs, Issuer: finding.Issuer, Serial: finding.Serial,
				Fingerprint: finding.Fingerprint, KeyAlgorithm: finding.KeyType,
				NotBefore: &notBefore, NotAfter: &notAfter, DeploymentLocation: finding.Address,
				Source: "discovery:network",
			}); err != nil {
			return err
		}
	} else {
		kind = "ssh_key"
		provenance = "ssh:ssh-host-probe:" + finding.Address
		metadata["source"] = "ssh-host-probe"
		metadata["key_type"] = finding.KeyType
		metadata["standing_access"] = false
		metadata["orphaned"] = false
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	observation := intent.Mode + "\x00" + finding.Address + "\x00" + finding.Fingerprint
	_, err = s.orch.RecordDiscoveryFindingWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "finding\x00"+observation), store.DiscoveryFinding{
			RunID: intent.ID, SourceID: intent.SourceID, Kind: kind, Ref: finding.Address,
			Provenance: provenance, Fingerprint: finding.Fingerprint, RiskScore: riskScore,
			Metadata: encoded,
		})
	return err
}

func relayFindingTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New("discovery relay report contains an invalid timestamp")
	}
	return parsed.UTC(), nil
}

func decodeStrictJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON value has trailing content")
	}
	return nil
}

// relayTargetResults carries the relay's per-target outcomes into the completion
// event under the kind of probe the mode ran.
func relayTargetResults(report segmentscan.Report) []store.DiscoveryTargetResult {
	if len(report.TargetResults) == 0 {
		return nil
	}
	kind := "network"
	if report.Mode == segmentscan.ModeSSH {
		kind = "ssh"
	}
	out := make([]store.DiscoveryTargetResult, 0, len(report.TargetResults))
	for _, result := range report.TargetResults {
		out = append(out, store.DiscoveryTargetResult{Kind: kind, Target: result.Target, Status: result.Status, Error: result.Error})
	}
	return out
}
