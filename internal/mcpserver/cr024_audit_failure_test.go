// SPDX-License-Identifier: BUSL-1.1

package mcpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestCR024ToolWithholdsEvidenceWhenCallAuditFails(t *testing.T) {
	appendErr := errors.New("injected tool-call audit append failure")
	var gatherRecorded bool
	auditor := auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
		if eventType == "rca.evidence.gathered" {
			gatherRecorded = true
			return nil
		}
		if eventType == "mcp.tool.call" {
			return appendErr
		}
		return nil
	})
	s := newServer(t, auditor, NewRateLimiter(100, time.Minute))
	result, err := s.Call(t.Context(), "agent-1", "t1", "explain_incident", "cert-123")
	if !gatherRecorded || !errors.Is(err, appendErr) || result.Text != "" || len(result.Citations) != 0 {
		t.Fatalf("tool result escaped without call audit: gather_recorded=%t text_present=%t citations=%d err=%v", gatherRecorded, result.Text != "", len(result.Citations), err)
	}
}
