// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/store"
)

// M2-L3: a misuse finding opens an incident for its API token, so the
// deviation is worked to a close rather than only alerted. A token has at
// most one open incident; later findings for it attach to that one (they are
// the token's findings since the incident opened). An operator closes it
// with a resolution: the token was revoked, the use was expected, or other.

const (
	EventIncidentOpened = "misuse.incident.opened"
	EventIncidentClosed = "misuse.incident.closed"
)

// Incident resolutions.
const (
	ResolutionTokenRevoked = "token_revoked"
	ResolutionExpectedUse  = "expected_use"
	ResolutionOther        = "other"
)

// IncidentOpened is the payload of misuse.incident.opened. IncidentID is the
// finding that opened it.
type IncidentOpened struct {
	IncidentID   string `json:"incident_id"`
	CredentialID string `json:"credential_id"`
	Principal    string `json:"principal"`
	FindingID    string `json:"finding_id"`
}

// IncidentClosed is the payload of misuse.incident.closed.
type IncidentClosed struct {
	IncidentID string `json:"incident_id"`
	Resolution string `json:"resolution"`
	Note       string `json:"note,omitempty"`
}

// ErrIncidentNotOpen is a close of an incident that is not open.
var ErrIncidentNotOpen = errors.New("misuse: the incident is not open")

// ErrIncidentNotFound is an incident this tenant does not have.
var ErrIncidentNotFound = errors.New("misuse: no such incident")

const maxIncidentNote = 500

// openIncidentTx opens an incident for the finding's token when the token has
// none open, in the caller's tenant transaction.
func (d *Detector) openIncidentTx(ctx context.Context, tx pgx.Tx, tenantID string, c candidate) error {
	var open bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM misuse_incidents WHERE tenant_id = $1 AND credential_id = $2 AND status = 'open')`,
		tenantID, c.finding.CredentialID).Scan(&open); err != nil {
		return err
	}
	if open {
		return nil
	}
	payload, err := json.Marshal(IncidentOpened{IncidentID: c.id, CredentialID: c.finding.CredentialID, Principal: c.finding.Principal, FindingID: c.id})
	if err != nil {
		return err
	}
	ev, err := d.log.Append(ctx, events.Event{ID: incidentEventID(c.id), Type: EventIncidentOpened, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	return d.proj.applyIncidentTx(ctx, tx, ev)
}

// incidentEventID derives the opening event's id from the finding's, so a
// retried record converges on one incident.
func incidentEventID(findingID string) string {
	return uuid.NewSHA1(findingNamespace, []byte("incident\x00"+findingID)).String()
}

// applyIncidentTx projects the incident events; a replay changes nothing.
func (p *Projection) applyIncidentTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return fmt.Errorf("misuse: %s has no sequence", ev.Type)
	}
	if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
		return err
	}
	seq := int64(ev.Sequence) // #nosec G115 -- bounded by MaxInt64 above.
	switch ev.Type {
	case EventIncidentOpened:
		var o IncidentOpened
		if err := json.Unmarshal(ev.Data, &o); err != nil || o.IncidentID == "" || o.CredentialID == "" {
			return fmt.Errorf("misuse: %s payload is incomplete", ev.Type)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO misuse_incidents (tenant_id, incident_id, credential_id, principal, opened_by_finding, status, opened_at, event_sequence)
			VALUES ($1, $2, $3, $4, $5, 'open', $6, $7)
			ON CONFLICT DO NOTHING`, ev.TenantID, o.IncidentID, o.CredentialID, o.Principal, o.FindingID, ev.Time.UTC(), seq)
		return err
	case EventIncidentClosed:
		var c IncidentClosed
		if err := json.Unmarshal(ev.Data, &c); err != nil || c.IncidentID == "" || !validResolution(c.Resolution) {
			return fmt.Errorf("misuse: %s payload is incomplete", ev.Type)
		}
		closedBy := ""
		if ev.Actor != nil {
			closedBy = ev.Actor.Subject
		}
		_, err := tx.Exec(ctx, `
			UPDATE misuse_incidents SET status = 'closed', closed_at = $3, closed_by = $4, resolution = $5, note = $6, event_sequence = $7
			 WHERE tenant_id = $1 AND incident_id = $2 AND status = 'open' AND event_sequence < $7`,
			ev.TenantID, c.IncidentID, ev.Time.UTC(), closedBy, c.Resolution, c.Note, seq)
		return err
	}
	return nil
}

func validResolution(r string) bool {
	return r == ResolutionTokenRevoked || r == ResolutionExpectedUse || r == ResolutionOther
}

// Incident is one served misuse incident. Findings counts the token's
// findings from the one that opened it to its close (or now), in event order.
type Incident struct {
	ID           string     `json:"id"`
	CredentialID string     `json:"credential_id"`
	Principal    string     `json:"principal"`
	Status       string     `json:"status"`
	OpenedAt     time.Time  `json:"opened_at"`
	Findings     int        `json:"findings"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	ClosedBy     string     `json:"closed_by,omitempty"`
	Resolution   string     `json:"resolution,omitempty"`
	Note         string     `json:"note,omitempty"`
}

// IncidentStore lists and closes a tenant's misuse incidents.
type IncidentStore struct {
	Store *store.Store
	Log   *events.Log
}

// List returns up to limit incidents, newest first, optionally only open or
// only closed ones.
func (s IncidentStore) List(ctx context.Context, tenantID, status string, limit int) ([]Incident, error) {
	var out []Incident
	err := s.Store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT i.incident_id, i.credential_id, i.principal, i.status, i.opened_at, i.closed_at, i.closed_by, i.resolution, i.note,
			       (SELECT count(*) FROM misuse_findings f WHERE f.tenant_id = i.tenant_id AND f.credential_id = i.credential_id
			           AND f.event_sequence >= coalesce((SELECT o.event_sequence FROM misuse_findings o
			                                              WHERE o.tenant_id = i.tenant_id AND o.finding_id = i.opened_by_finding), 0)
			           AND (i.status = 'open' OR f.event_sequence <= i.event_sequence))
			  FROM misuse_incidents i
			 WHERE i.tenant_id = $1 AND ($2 = '' OR i.status = $2)
			 ORDER BY i.opened_at DESC, i.incident_id DESC LIMIT $3`, tenantID, status, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var in Incident
			if err := rows.Scan(&in.ID, &in.CredentialID, &in.Principal, &in.Status, &in.OpenedAt, &in.ClosedAt, &in.ClosedBy,
				&in.Resolution, &in.Note, &in.Findings); err != nil {
				return err
			}
			out = append(out, in)
		}
		return rows.Err()
	})
	return out, err
}

// Close records an incident's close with its resolution; the caller's actor
// rides in ctx.
func (s IncidentStore) Close(ctx context.Context, tenantID, incidentID, resolution, note string) (Incident, error) {
	note = strings.TrimSpace(note)
	if !validResolution(resolution) {
		return Incident{}, errors.New("resolution must be token_revoked, expected_use or other")
	}
	if len(note) > maxIncidentNote {
		return Incident{}, fmt.Errorf("note must be at most %d characters", maxIncidentNote)
	}
	payload, err := json.Marshal(IncidentClosed{IncidentID: incidentID, Resolution: resolution, Note: note})
	if err != nil {
		return Incident{}, err
	}
	proj := NewProjection(s.Store)
	err = s.Store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM misuse_incidents WHERE tenant_id = $1 AND incident_id = $2 FOR UPDATE`,
			tenantID, incidentID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIncidentNotFound
		}
		if err != nil {
			return err
		}
		if status != "open" {
			return ErrIncidentNotOpen
		}
		ev, err := s.Log.Append(ctx, events.Event{Type: EventIncidentClosed, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		return proj.applyIncidentTx(ctx, tx, ev)
	})
	if err != nil {
		return Incident{}, err
	}
	all, err := s.List(ctx, tenantID, "", maxIncidentList)
	if err != nil {
		return Incident{}, err
	}
	for _, in := range all {
		if in.ID == incidentID {
			return in, nil
		}
	}
	return Incident{}, ErrIncidentNotFound
}

const maxIncidentList = 200
