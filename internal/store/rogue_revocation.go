// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// A163: rogue certificates revoked at the CA that issued them. A projection of
// rogue.certificate.revocation_requested and rogue.certificate.revoked_at_issuer.

// RogueCertificateRevocationCommand is the revocation.publish outbox payload of a
// rogue certificate's revocation at its issuer. RogueEventID names the retained
// request event; the delivery revokes only what that event authorized.
type RogueCertificateRevocationCommand struct {
	RogueEventID string `json:"rogue_event_id"`
	DiscoveryID  string `json:"discovery_id"`
	AuthorityID  string `json:"authority_id"`
	Serial       string `json:"serial"`
	Reason       string `json:"reason"`
}

// RogueCertificateRevocation is one rogue finding's revocation at one
// authority, with the status its queued delivery reached.
type RogueCertificateRevocation struct {
	TenantID       string
	DiscoveryID    string
	AuthorityID    string
	RequestEventID string
	Serial         string
	Reason         string
	// State is queued, revoked or failed (the delivery stopped retrying).
	State       string
	RequestedAt time.Time
	RevokedAt   *time.Time
	Attempts    int
	LastError   string
}

// RogueRevocationDestination and RogueRevocationKey place the delivery beside
// trstctl's other external revocations.
const RogueRevocationDestination = "revocation.publish"

// RogueRevocationKey is the outbox idempotency key of one request.
func RogueRevocationKey(requestEventID string) string { return "rogue-revoke:" + requestEventID }

// ApplyRogueCertificateRevocationRequestedTx records the queued request.
func (s *Store) ApplyRogueCertificateRevocationRequestedTx(ctx context.Context, tx pgx.Tx, r RogueCertificateRevocation, eventSequence uint64) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO rogue_certificate_revocations
		        (tenant_id, discovery_id, authority_id, request_event_id, serial, reason, state, requested_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, $8)
		 ON CONFLICT (tenant_id, discovery_id, authority_id) DO UPDATE
		    SET request_event_id = EXCLUDED.request_event_id, serial = EXCLUDED.serial, reason = EXCLUDED.reason,
		        state = 'queued', requested_at = EXCLUDED.requested_at, revoked_at = NULL,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE rogue_certificate_revocations.event_sequence < EXCLUDED.event_sequence`,
		r.TenantID, r.DiscoveryID, r.AuthorityID, r.RequestEventID, r.Serial, r.Reason, r.RequestedAt.UTC(), eventSequence)
	return err
}

// ApplyRogueCertificateRevokedAtIssuerTx marks the request revoked.
func (s *Store) ApplyRogueCertificateRevokedAtIssuerTx(ctx context.Context, tx pgx.Tx, tenantID, discoveryID, authorityID, requestEventID string, revokedAt time.Time, eventSequence uint64) error {
	_, err := tx.Exec(ctx,
		`UPDATE rogue_certificate_revocations
		    SET state = 'revoked', revoked_at = $5, event_sequence = $6
		  WHERE tenant_id = $1 AND discovery_id = $2 AND authority_id = $3 AND request_event_id = $4
		    AND event_sequence < $6`,
		tenantID, discoveryID, authorityID, requestEventID, revokedAt.UTC(), eventSequence)
	return err
}

const rogueRevocationSelect = `SELECT r.tenant_id::text, r.discovery_id::text, r.authority_id, r.request_event_id, r.serial,
	        r.reason, CASE WHEN r.state = 'revoked' THEN 'revoked'
	                       WHEN o.status = 'failed' THEN 'failed'
	                       ELSE 'queued' END,
	        r.requested_at, r.revoked_at, COALESCE(o.attempts, 0), COALESCE(o.last_error, '')
	   FROM rogue_certificate_revocations r
	   LEFT JOIN outbox o ON o.tenant_id = r.tenant_id AND o.destination = 'revocation.publish'
	                     AND o.idempotency_key = 'rogue-revoke:' || r.request_event_id`

func scanRogueRevocation(row pgx.Row) (RogueCertificateRevocation, error) {
	var r RogueCertificateRevocation
	err := row.Scan(&r.TenantID, &r.DiscoveryID, &r.AuthorityID, &r.RequestEventID, &r.Serial, &r.Reason, &r.State,
		&r.RequestedAt, &r.RevokedAt, &r.Attempts, &r.LastError)
	return r, err
}

// GetRogueCertificateRevocationTx reads one finding's revocation at one
// authority inside the caller's tenant transaction.
func (s *Store) GetRogueCertificateRevocationTx(ctx context.Context, tx pgx.Tx, tenantID, discoveryID, authorityID string) (RogueCertificateRevocation, bool, error) {
	r, err := scanRogueRevocation(tx.QueryRow(ctx, rogueRevocationSelect+`
	  WHERE r.tenant_id = $1 AND r.discovery_id = $2 AND r.authority_id = $3`, tenantID, discoveryID, authorityID))
	if errors.Is(err, pgx.ErrNoRows) {
		return RogueCertificateRevocation{}, false, nil
	}
	return r, err == nil, err
}

// ListRogueCertificateRevocations returns the tenant's rogue revocations,
// newest request first.
func (s *Store) ListRogueCertificateRevocations(ctx context.Context, tenantID string) ([]RogueCertificateRevocation, error) {
	var out []RogueCertificateRevocation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, rogueRevocationSelect+`
		  WHERE r.tenant_id = $1 ORDER BY r.requested_at DESC LIMIT 500`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRogueRevocation(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
