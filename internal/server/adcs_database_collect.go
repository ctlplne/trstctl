// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/projections"
)

var adcsDatabaseReportNamespace = uuid.MustParse("8e2b6f41-3c7d-4a95-b0e8-6f1d2c9a7b35")

// recordADCSDatabase records a relay's CA database counts (A162) after checking
// them against the queued read: the exact relay it was queued for, the same CA,
// and counts that add up. The event id comes from the job, so a retried report
// records once.
func (s *Server) recordADCSDatabase(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	var intent relay.ADCSDatabaseIntent
	if err := decodeStrictJSON(jobPayload, &intent); err != nil {
		return fmt.Errorf("server: decode durable CA database intent: %w", err)
	}
	agentID := agentRowID(tenantID, agentName)
	if intent.RequiredAgentID == "" || intent.RequiredAgentID != agentID {
		return errors.New("server: a CA database result requires the exact selected relay")
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: CA database report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report relay.ADCSDatabaseReport
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil {
		return fmt.Errorf("server: decode CA database report: %w", err)
	}
	if err := relay.ValidateADCSDatabaseReport(intent, report); err != nil {
		return err
	}
	if s.orch == nil {
		return errors.New("server: CA database reports need the orchestrator")
	}
	sum := report.Summary
	eventID := uuid.NewSHA1(adcsDatabaseReportNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
	return s.orch.RecordADCSDatabaseCollected(ctx, tenantID, eventID, projections.ADCSDatabaseIngested{
		CAConfig: intent.CAConfig,
		Issued:   sum.Issued, Pending: sum.Pending, Revoked: sum.Revoked,
		Denied: sum.Denied, Failed: sum.Failed, Unknown: sum.Unknown,
		Unparsed: sum.Unparsed, Total: sum.Total,
		RowsRead: report.RowsRead, RowsRejected: report.RowsRejected,
		Source: "relay:" + agentID,
	})
}
