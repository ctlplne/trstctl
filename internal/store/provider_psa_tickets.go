// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PSA ticket states (MSP-3).
const (
	PSATicketOpening = "opening"
	PSATicketOpen    = "open"
	PSATicketClosing = "closing"
	PSATicketClosed  = "closed"
	PSATicketFailed  = "failed"
)

// PSA ticket operations.
const (
	PSATicketOpOpen   = "open"
	PSATicketOpUpdate = "update"
	PSATicketOpClose  = "close"
)

// PSATicket is the service ticket one alert subject of a customer has in a
// PSA target: opened by its first alert, noted by later ones, closed when
// its condition clears. Generation counts the tickets the subject has had.
type PSATicket struct {
	TenantID          string
	TargetID          string
	AlertKey          string
	Generation        int
	Kind              string
	Status            string
	ExternalCompanyID string
	ExternalTicketID  string
	Summary           string
	Notes             int
	Reason            string
	LastAlertRef      string
	OpenedAt          *time.Time
	ClosedAt          *time.Time
	EventSequence     uint64
	UpdatedAt         time.Time
}

// PSATicketChange is one projected ticket event: an operation requested
// (open, update with a note, close) or its recorded outcome.
type PSATicketChange struct {
	TenantID          string
	TargetID          string
	AlertKey          string
	Generation        int
	Op                string
	Recorded          bool
	OK                bool
	Kind              string
	ExternalCompanyID string
	ExternalTicketID  string
	Summary           string
	Reason            string
	AlertRef          string
	At                time.Time
}

// ApplyPSATicketTx projects one ticket event. An open request starts a new
// generation on a subject with no ticket or a closed or failed one; an
// update or close request applies only to the open generation it names; an
// outcome applies only to the operation in flight. Anything else leaves the
// row as it is, so a replay or an out-of-order event converges.
func (s *Store) ApplyPSATicketTx(ctx context.Context, tx pgx.Tx, c PSATicketChange, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: PSA ticket event sequence is out of range")
	}
	seq := int64(sequence) // #nosec G115 -- bounded by the check above (CWE-190)
	at := c.At.UTC()
	cur, found, err := psaTicketForUpdateTx(ctx, tx, c.TenantID, c.TargetID, c.AlertKey)
	if err != nil {
		return err
	}
	if found && cur.EventSequence >= sequence {
		return nil
	}
	if !c.Recorded && c.Op == PSATicketOpOpen {
		if found && cur.Status != PSATicketClosed && cur.Status != PSATicketFailed && cur.ExternalCompanyID == c.ExternalCompanyID {
			return nil
		}
		if found && c.Generation <= cur.Generation {
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO provider_psa_tickets
			  (tenant_id, target_id, alert_key, generation, kind, status, external_company_id, external_ticket_id, summary,
			   notes, reason, last_alert_ref, opened_at, closed_at, event_sequence, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'opening', $6, '', $7, 0, '', $8, NULL, NULL, $9, $10)
			ON CONFLICT (tenant_id, target_id, alert_key) DO UPDATE SET
			  generation = EXCLUDED.generation, kind = EXCLUDED.kind, status = 'opening',
			  external_company_id = EXCLUDED.external_company_id, external_ticket_id = '', summary = EXCLUDED.summary,
			  notes = 0, reason = '', last_alert_ref = EXCLUDED.last_alert_ref, opened_at = NULL, closed_at = NULL,
			  event_sequence = EXCLUDED.event_sequence, updated_at = EXCLUDED.updated_at`,
			c.TenantID, c.TargetID, c.AlertKey, c.Generation, c.Kind, c.ExternalCompanyID, c.Summary, c.AlertRef, seq, at)
		return err
	}
	if !found || cur.Generation != c.Generation {
		return nil
	}
	status, ticketID, notes, reason, lastRef := cur.Status, cur.ExternalTicketID, cur.Notes, cur.Reason, cur.LastAlertRef
	openedAt, closedAt := cur.OpenedAt, cur.ClosedAt
	switch {
	case !c.Recorded && c.Op == PSATicketOpUpdate:
		if status != PSATicketOpening && status != PSATicketOpen {
			return nil
		}
		notes++
		lastRef = c.AlertRef
	case !c.Recorded && c.Op == PSATicketOpClose:
		if status != PSATicketOpening && status != PSATicketOpen {
			return nil
		}
		status, reason = PSATicketClosing, c.Reason
	case c.Recorded && c.Op == PSATicketOpOpen:
		if status != PSATicketOpening {
			return nil
		}
		if c.OK {
			status, ticketID, openedAt = PSATicketOpen, c.ExternalTicketID, &at
		} else {
			status, reason = PSATicketFailed, c.Reason
		}
	case c.Recorded && c.Op == PSATicketOpUpdate:
		if !c.OK {
			reason = c.Reason
		}
	case c.Recorded && c.Op == PSATicketOpClose:
		if status != PSATicketClosing {
			return nil
		}
		if c.OK {
			status, closedAt = PSATicketClosed, &at
		} else {
			status, reason = PSATicketFailed, c.Reason
		}
	default:
		return fmt.Errorf("store: unknown PSA ticket change %q (recorded=%v)", c.Op, c.Recorded)
	}
	_, err = tx.Exec(ctx, `UPDATE provider_psa_tickets SET status = $4, external_ticket_id = $5, notes = $6, reason = $7,
		last_alert_ref = $8, opened_at = $9, closed_at = $10, event_sequence = $11, updated_at = $12
		WHERE tenant_id = $1 AND target_id = $2 AND alert_key = $3`,
		c.TenantID, c.TargetID, c.AlertKey, status, ticketID, notes, reason, lastRef, openedAt, closedAt, seq, at)
	return err
}

const psaTicketColumns = `tenant_id::text, target_id, alert_key, generation, kind, status, external_company_id, external_ticket_id,
	summary, notes, reason, last_alert_ref, opened_at, closed_at, event_sequence, updated_at`

type psaTicketScanner interface {
	Scan(dest ...any) error
}

func scanPSATicket(row psaTicketScanner) (PSATicket, error) {
	var t PSATicket
	var seq int64
	if err := row.Scan(&t.TenantID, &t.TargetID, &t.AlertKey, &t.Generation, &t.Kind, &t.Status, &t.ExternalCompanyID,
		&t.ExternalTicketID, &t.Summary, &t.Notes, &t.Reason, &t.LastAlertRef, &t.OpenedAt, &t.ClosedAt, &seq, &t.UpdatedAt); err != nil {
		return PSATicket{}, err
	}
	if seq > 0 {
		t.EventSequence = uint64(seq)
	}
	t.UpdatedAt = t.UpdatedAt.UTC()
	return t, nil
}

func psaTicketForUpdateTx(ctx context.Context, tx pgx.Tx, tenantID, targetID, alertKey string) (PSATicket, bool, error) {
	t, err := scanPSATicket(tx.QueryRow(ctx, `SELECT `+psaTicketColumns+` FROM provider_psa_tickets
		WHERE tenant_id = $1 AND target_id = $2 AND alert_key = $3 FOR UPDATE`, tenantID, targetID, alertKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return PSATicket{}, false, nil
	}
	return t, err == nil, err
}

// PSATicketForTx reads one subject's ticket inside a command's tenant
// transaction, locking the row.
func PSATicketForTx(ctx context.Context, tx pgx.Tx, tenantID, targetID, alertKey string) (PSATicket, bool, error) {
	return psaTicketForUpdateTx(ctx, tx, tenantID, targetID, alertKey)
}

// PSATicketFor reads one subject's ticket under the customer's tenant.
func (s *Store) PSATicketFor(ctx context.Context, tenantID, targetID, alertKey string) (PSATicket, bool, error) {
	var out PSATicket
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		t, err := scanPSATicket(tx.QueryRow(ctx, `SELECT `+psaTicketColumns+` FROM provider_psa_tickets
			WHERE tenant_id = $1 AND target_id = $2 AND alert_key = $3`, tenantID, targetID, alertKey))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out, found = t, true
		return nil
	})
	return out, found, err
}

// PSATickets lists a customer's tickets, most recently changed first.
func (s *Store) PSATickets(ctx context.Context, tenantID string, limit int) ([]PSATicket, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []PSATicket
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+psaTicketColumns+` FROM provider_psa_tickets WHERE tenant_id = $1
			ORDER BY updated_at DESC, target_id, alert_key LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanPSATicket(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// OpenPSATickets lists a customer's tickets in a target that are open (or
// still opening), for the close sweep.
func (s *Store) OpenPSATickets(ctx context.Context, tenantID, targetID string) ([]PSATicket, error) {
	var out []PSATicket
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+psaTicketColumns+` FROM provider_psa_tickets
			WHERE tenant_id = $1 AND target_id = $2 AND status IN ('opening', 'open') ORDER BY alert_key LIMIT 500`, tenantID, targetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanPSATicket(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// PSATicketConditionCleared reports whether the condition an alert subject
// stands for is gone, and why, read under the customer's tenant:
//   - certificate.expiry:<certificate>: the certificate is no longer active
//     (renewed, revoked or removed);
//   - identity.renewal_failed:<identity>: the identity is deployed or issued
//     again, or gone;
//   - revocation.health:<certificate>|<endpoint>: every observation of that
//     endpoint for the certificate is fresh again, or there is none;
//   - credential.drift:<path>: no untriaged drift finding for the path in its
//     source's latest completed run.
func (s *Store) PSATicketConditionCleared(ctx context.Context, tenantID, alertKey string) (bool, string, error) {
	kind, subject, ok := strings.Cut(alertKey, ":")
	if !ok || subject == "" {
		return false, "", fmt.Errorf("store: PSA ticket alert key %q names no subject", alertKey)
	}
	var cleared bool
	var reason string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		switch kind {
		case "certificate.expiry":
			var active bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificates WHERE tenant_id = $1 AND id::text = $2 AND status = 'active')`,
				tenantID, subject).Scan(&active); err != nil {
				return err
			}
			cleared, reason = !active, "the certificate is no longer active: it was renewed, revoked or removed"
		case "identity.renewal_failed":
			var status string
			err := tx.QueryRow(ctx, `SELECT status FROM identities WHERE tenant_id = $1 AND id::text = $2`, tenantID, subject).Scan(&status)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				cleared, reason = true, "the identity no longer exists"
			case err != nil:
				return err
			default:
				cleared, reason = status == "deployed" || status == "issued", "a renewal succeeded: the identity is "+status+" again"
			}
		case "revocation.health":
			certificate, endpoint, ok := strings.Cut(subject, "|")
			if !ok {
				return fmt.Errorf("store: revocation alert key %q names no endpoint", alertKey)
			}
			var failing bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM revocation_endpoint_health
				WHERE tenant_id = $1 AND certificate_id::text = $2 AND endpoint = $3 AND status <> 'fresh')`,
				tenantID, certificate, endpoint).Scan(&failing); err != nil {
				return err
			}
			cleared, reason = !failing, "the revocation endpoint answers fresh again"
		case "credential.drift":
			var drifting bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM discovery_findings f
				 WHERE f.tenant_id = $1 AND f.kind = 'credential_drift' AND f.ref = $2
				   AND f.triage_status NOT IN ('remediated', 'dismissed')
				   AND f.run_id = (SELECT r.id FROM discovery_runs r
				                    WHERE r.tenant_id = f.tenant_id AND r.source_id = f.source_id AND r.status = 'succeeded'
				                    ORDER BY r.created_at DESC, r.id DESC LIMIT 1))`, tenantID, subject).Scan(&drifting); err != nil {
				return err
			}
			cleared, reason = !drifting, "the latest scan no longer reports the drift, or it was remediated or dismissed"
		default:
			return fmt.Errorf("store: PSA ticket alert kind %q has no closing condition", kind)
		}
		return nil
	})
	return cleared, reason, err
}
