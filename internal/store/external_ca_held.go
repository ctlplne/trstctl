// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// N1-L1: an external CA issuance the CA holds for a manager's approval, by the
// CA's own request id, and how it was resolved once the request was read back.

// ErrExternalCAHeldIssueNotFound means the authority holds no such request for
// this tenant.
var ErrExternalCAHeldIssueNotFound = errors.New("store: held external CA issuance not found")

// Held issuance states.
const (
	ExternalCAHeldIssueHeld   = "held"
	ExternalCAHeldIssueIssued = "issued"
	ExternalCAHeldIssueDenied = "denied"
)

// ExternalCAHeldIssueListMax bounds one listing of an authority's held
// issuances.
const ExternalCAHeldIssueListMax = 500

// ExternalCAHeldIssue is one issuance an external CA holds, or held, for
// approval.
type ExternalCAHeldIssue struct {
	AuthorityID    string
	CARequestID    int
	IssueKey       string
	RequestBinding string
	KeyOrigin      string
	DNSNames       []string
	Status         string
	Serial         string
	HeldAt         time.Time
	ResolvedAt     *time.Time
}

func externalCAHeldSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: held external CA issuance event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplyExternalCAIssueHeldTx records an issuance the CA holds for approval.
// Recording it again changes nothing.
func (s *Store) ApplyExternalCAIssueHeldTx(ctx context.Context, tx pgx.Tx, tenantID string, h ExternalCAHeldIssue, sequence uint64) error {
	seq, err := externalCAHeldSequence(sequence)
	if err != nil {
		return err
	}
	names := h.DNSNames
	if names == nil {
		names = []string{}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO external_ca_held_issues (tenant_id, authority_id, ca_request_id, issue_key, request_binding, key_origin,
		                                     dns_names, held_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT DO NOTHING`,
		tenantID, h.AuthorityID, h.CARequestID, h.IssueKey, h.RequestBinding, h.KeyOrigin, names, h.HeldAt.UTC(), seq)
	return err
}

// ApplyExternalCAIssueResumedTx records how a held issuance was resolved: the
// CA issued it (with the certificate's serial) or refused it. Only a held
// issuance is resolved, once.
func (s *Store) ApplyExternalCAIssueResumedTx(ctx context.Context, tx pgx.Tx, tenantID, authorityID string, requestID int, status, serial string, at time.Time, sequence uint64) error {
	seq, err := externalCAHeldSequence(sequence)
	if err != nil {
		return err
	}
	if status != ExternalCAHeldIssueIssued && status != ExternalCAHeldIssueDenied {
		return fmt.Errorf("store: a held external CA issuance resolves as issued or denied, not %q", status)
	}
	_, err = tx.Exec(ctx, `UPDATE external_ca_held_issues SET status = $4, serial = $5, resolved_at = $6, event_sequence = $7
		WHERE tenant_id = $1 AND authority_id = $2 AND ca_request_id = $3 AND status = 'held'`,
		tenantID, authorityID, requestID, status, serial, at.UTC(), seq)
	return err
}

const externalCAHeldColumns = `authority_id, ca_request_id, issue_key, request_binding, key_origin, dns_names, status, serial,
	held_at, resolved_at`

const prefixedExternalCAHeldColumns = `h.authority_id, h.ca_request_id, h.issue_key, h.request_binding, h.key_origin, h.dns_names, h.status,
	h.serial, h.held_at, h.resolved_at`

func scanExternalCAHeldIssue(row pgx.Row) (ExternalCAHeldIssue, error) {
	var h ExternalCAHeldIssue
	err := row.Scan(&h.AuthorityID, &h.CARequestID, &h.IssueKey, &h.RequestBinding, &h.KeyOrigin, &h.DNSNames, &h.Status, &h.Serial,
		&h.HeldAt, &h.ResolvedAt)
	return h, err
}

// HeldIssueForADCSDecisionTx reads the issuance still held on the request an
// AD CS decision decided, when there is one: the decision's issuer is the
// authority, and its request id the CA's.
func (s *Store) HeldIssueForADCSDecisionTx(ctx context.Context, tx pgx.Tx, tenantID, decisionID string) (ExternalCAHeldIssue, bool, error) {
	h, err := scanExternalCAHeldIssue(tx.QueryRow(ctx, `SELECT `+prefixedExternalCAHeldColumns+`
		FROM adcs_request_decisions d
		JOIN external_ca_held_issues h ON h.tenant_id = d.tenant_id AND h.authority_id = d.issuer_id AND h.ca_request_id = d.request_id
		WHERE d.tenant_id = $1 AND d.id = $2 AND h.status = 'held'`, tenantID, decisionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ExternalCAHeldIssue{}, false, nil
	}
	if err != nil {
		return ExternalCAHeldIssue{}, false, err
	}
	return h, true, nil
}

// GetExternalCAHeldIssue reads one held issuance by the CA's request id.
func (s *Store) GetExternalCAHeldIssue(ctx context.Context, tenantID, authorityID string, requestID int) (ExternalCAHeldIssue, error) {
	var h ExternalCAHeldIssue
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		h, err = scanExternalCAHeldIssue(tx.QueryRow(ctx, `SELECT `+externalCAHeldColumns+` FROM external_ca_held_issues
			WHERE tenant_id = $1 AND authority_id = $2 AND ca_request_id = $3`, tenantID, authorityID, requestID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ExternalCAHeldIssue{}, ErrExternalCAHeldIssueNotFound
	}
	return h, err
}

// ListExternalCAHeldIssues lists an authority's held issuances, newest first.
func (s *Store) ListExternalCAHeldIssues(ctx context.Context, tenantID, authorityID string, limit int) ([]ExternalCAHeldIssue, error) {
	out := []ExternalCAHeldIssue{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+externalCAHeldColumns+` FROM external_ca_held_issues
			WHERE tenant_id = $1 AND authority_id = $2 ORDER BY held_at DESC, ca_request_id DESC LIMIT $3`, tenantID, authorityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			h, err := scanExternalCAHeldIssue(rows)
			if err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return out, err
}
