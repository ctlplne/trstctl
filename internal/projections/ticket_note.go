// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ticketintake"
)

// queueTicketNoteTx writes a decision on a request ServiceNow intake opened
// back to its ticket as a work note (P13-L1): approved, denied, canceled,
// expired and issued each queue one note, through the enabled intake schedule
// for the ticket's table, in the decision's own projection transaction.
// Requests from elsewhere, and tickets whose table no enabled schedule reads,
// queue nothing.
func (p *Projector) queueTicketNoteTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, decision string) error {
	req, found, err := p.store.IssuanceRequestTx(ctx, tx, tenantID, requestID)
	if err != nil || !found || req.Origin != ticketintake.SystemServiceNow {
		return err
	}
	table, sysID, ok := strings.Cut(req.TicketRef, ":")
	if !ok || table == "" || sysID == "" {
		return nil
	}
	sched, found, err := p.store.ServiceNowIntakeScheduleForTableTx(ctx, tx, tenantID, table)
	if err != nil || !found {
		return err
	}
	intent := ticketintake.NoteIntent{Schedule: sched.Name, NoteID: ticketintake.NoteID(tenantID, req.ID, decision),
		InstanceURL: sched.InstanceURL, TokenRef: sched.TokenRef, SNTable: table, SourceRef: sysID,
		Text: ticketNoteText(req.ID, req.Subject, decision, req.DecidedBy, req.DecisionReason)}
	if ticketintake.ValidateNoteIntent(intent) != nil {
		// A ticket ref or schedule that cannot carry a note gets none.
		return nil
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return p.store.QueueTicketNoteTx(ctx, tx, tenantID, intent.NoteID, payload)
}

// ticketNoteText is a decision as the ticket's work note says it.
func ticketNoteText(requestID, subject, decision, decidedBy, reason string) string {
	text := ""
	switch decision {
	case "approved":
		text = fmt.Sprintf("trstctl approved certificate request %s for %s (by %s).", requestID, subject, decidedBy)
	case "denied":
		text = fmt.Sprintf("trstctl denied certificate request %s for %s (by %s).", requestID, subject, decidedBy)
	case "cancelled":
		text = fmt.Sprintf("Certificate request %s for %s was canceled in trstctl by its requester.", requestID, subject)
	case "expired":
		text = fmt.Sprintf("Certificate request %s for %s expired in trstctl without a decision.", requestID, subject)
	case "issued":
		return fmt.Sprintf("trstctl issued the certificate for request %s (%s).", requestID, subject)
	default:
		text = fmt.Sprintf("Certificate request %s for %s is now %s in trstctl.", requestID, subject, decision)
	}
	if reason = strings.TrimSpace(reason); reason != "" && decision != "expired" {
		if len(reason) > 500 {
			reason = reason[:500]
		}
		text += " Reason: " + reason
	}
	return text
}
