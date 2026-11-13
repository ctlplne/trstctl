// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// The PSA tickets a customer's alerts open, update and close under its
// company in a Provider PSA target (MSP-3): an operation is requested (open
// with a summary and the first alert's note, update with a later alert's
// note, close with the reason the condition cleared) and its outcome is
// recorded (the PSA's ticket ID on open). The tenant is the customer.
const (
	EventPSATicketRequested = "provider.psa_ticket.requested"
	EventPSATicketRecorded  = "provider.psa_ticket.recorded"
)

// PSATicketEvent is the payload of both provider.psa_ticket.* events.
type PSATicketEvent struct {
	TargetID          string `json:"target_id"`
	AlertKey          string `json:"alert_key"`
	Generation        int    `json:"generation"`
	Op                string `json:"op"`
	Kind              string `json:"kind,omitempty"`
	ExternalCompanyID string `json:"external_company_id,omitempty"`
	ExternalTicketID  string `json:"external_ticket_id,omitempty"`
	Summary           string `json:"summary,omitempty"`
	Note              string `json:"note,omitempty"`
	AlertRef          string `json:"alert_ref,omitempty"`
	OK                bool   `json:"ok,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// PSA ticket text bounds.
const (
	PSATicketSummaryMax = 200
	PSATicketNoteMax    = 4000
)

// ValidatePSATicketEvent checks a provider.psa_ticket.* payload.
func ValidatePSATicketEvent(eventType string, p PSATicketEvent) error {
	if !billingTargetIDPattern.MatchString(p.TargetID) {
		return fmt.Errorf("a PSA ticket names a valid target, not %q", p.TargetID)
	}
	if kind, subject, ok := strings.Cut(p.AlertKey, ":"); !ok || kind == "" || subject == "" || len(p.AlertKey) > 400 {
		return fmt.Errorf("a PSA ticket names its alert subject as kind:subject")
	}
	if p.Generation < 1 {
		return fmt.Errorf("a PSA ticket names its generation")
	}
	if len(p.Kind) > 64 || len(p.ExternalCompanyID) > 128 || len(p.ExternalTicketID) > 128 || len(p.Summary) > PSATicketSummaryMax ||
		len(p.Note) > PSATicketNoteMax || len(p.AlertRef) > 300 || len(p.Reason) > 2000 {
		return fmt.Errorf("a PSA ticket field is too long")
	}
	switch p.Op {
	case store.PSATicketOpOpen, store.PSATicketOpUpdate, store.PSATicketOpClose:
	default:
		return fmt.Errorf("unknown PSA ticket operation %q", p.Op)
	}
	switch eventType {
	case EventPSATicketRequested:
		switch {
		case p.Op == store.PSATicketOpOpen && (p.Kind == "" || strings.TrimSpace(p.ExternalCompanyID) == "" || strings.TrimSpace(p.Summary) == ""):
			return fmt.Errorf("an opened PSA ticket names its kind, company and summary")
		case p.Op == store.PSATicketOpUpdate && strings.TrimSpace(p.Note) == "":
			return fmt.Errorf("a PSA ticket update carries its note")
		case p.Op == store.PSATicketOpClose && strings.TrimSpace(p.Reason) == "":
			return fmt.Errorf("a closed PSA ticket says why its condition cleared")
		}
	case EventPSATicketRecorded:
		if p.OK && p.Op == store.PSATicketOpOpen && strings.TrimSpace(p.ExternalTicketID) == "" {
			return fmt.Errorf("an opened PSA ticket records the system's ticket ID")
		}
		if !p.OK && strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("a failed PSA ticket operation says why")
		}
	default:
		return fmt.Errorf("unknown PSA ticket event %q", eventType)
	}
	return nil
}

func (p *Projector) applyPSATicketTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventPSATicketRequested && e.Type != EventPSATicketRecorded {
		return false, nil
	}
	var d PSATicketEvent
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := ValidatePSATicketEvent(e.Type, d); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyPSATicketTx(ctx, tx, store.PSATicketChange{
		TenantID: e.TenantID, TargetID: d.TargetID, AlertKey: d.AlertKey, Generation: d.Generation, Op: d.Op,
		Recorded: e.Type == EventPSATicketRecorded, OK: d.OK, Kind: d.Kind, ExternalCompanyID: d.ExternalCompanyID,
		ExternalTicketID: d.ExternalTicketID, Summary: d.Summary, Reason: d.Reason, AlertRef: d.AlertRef, At: e.Time,
	}, e.Sequence)
}
