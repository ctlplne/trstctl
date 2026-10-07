// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const ACMEUpstreamARIFetchDestination = "external-ca.ari.fetch"

// ACMEUpstreamARI is the rebuildable observation for one exact external ACME
// leaf. EventID and EventSequence bind one outbox command to one immutable
// event; neither is supplied by a tenant API request.
type ACMEUpstreamARI struct {
	TenantID         string
	CertificateID    string
	AuthorityID      string
	ARICertificateID string
	Fingerprint      string
	Status           string
	WindowStart      *time.Time
	WindowEnd        *time.Time
	UpdatedAt        time.Time
	FetchedAt        *time.Time
	NextPollAt       time.Time
	FailureCount     int
	ErrorClass       string
	EventID          string
	EventSequence    uint64
}

type acmeUpstreamARIFetchPayload struct {
	CertificateID    string `json:"certificate_id"`
	AuthorityID      string `json:"authority_id"`
	ARICertificateID string `json:"ari_certificate_id"`
	Fingerprint      string `json:"fingerprint"`
}

// ACMEUpstreamARICandidate is an active external leaf without an initial ARI
// request. CertificateDER is public evidence; the caller verifies it before
// appending a fetch intent. Selection is keyset-bounded under tenant RLS.
type ACMEUpstreamARICandidate struct {
	CertificateID  string
	AuthorityID    string
	Fingerprint    string
	Serial         string
	CertificateDER []byte
	NotAfter       time.Time
}

// TenantsWithMissingACMEUpstreamARI is only an enumerator. The actual leaves
// are loaded through tenant-scoped RLS in ListMissingACMEUpstreamARI.
func (s *Store) TenantsWithMissingACMEUpstreamARI(ctx context.Context, authorityID, authorityTenant string, now time.Time, limit int) ([]string, error) {
	if authorityID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — leader-only cross-tenant enumeration returns tenant IDs; certificate details are read later under each tenant's RLS context (AN-1).
		`SELECT DISTINCT c.tenant_id::text FROM certificates c
		 LEFT JOIN acme_upstream_ari a ON a.tenant_id=c.tenant_id AND a.certificate_id=c.id
		 WHERE c.issuing_external_ca_id=$1 AND c.status='active'
		   AND c.not_after>$2 AND a.certificate_id IS NULL
		   AND ($3::text='' OR c.tenant_id::text=$3)
		 ORDER BY 1 LIMIT $4`, authorityID, now, authorityTenant, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}

func (s *Store) ListMissingACMEUpstreamARI(ctx context.Context, tenantID, afterID, authorityID string, now time.Time, limit int) ([]ACMEUpstreamARICandidate, error) {
	if authorityID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var candidates []ACMEUpstreamARICandidate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.id::text,c.issuing_external_ca_id,c.fingerprint,c.serial,c.certificate_der,c.not_after
			FROM certificates c
			LEFT JOIN acme_upstream_ari a ON a.tenant_id=$1 AND a.certificate_id=c.id
			WHERE c.tenant_id=$1 AND c.id>$2 AND c.issuing_external_ca_id=$3
			  AND c.status='active' AND c.not_after>$4 AND a.certificate_id IS NULL
			ORDER BY c.id LIMIT $5`, tenantID, afterID, authorityID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var candidate ACMEUpstreamARICandidate
			if err := rows.Scan(&candidate.CertificateID, &candidate.AuthorityID,
				&candidate.Fingerprint, &candidate.Serial, &candidate.CertificateDER,
				&candidate.NotAfter); err != nil {
				return err
			}
			candidates = append(candidates, candidate)
		}
		return rows.Err()
	})
	return candidates, err
}

func validateACMEUpstreamARI(a ACMEUpstreamARI) error {
	if a.TenantID == "" || a.CertificateID == "" || a.AuthorityID == "" ||
		a.ARICertificateID == "" || a.Fingerprint == "" || a.EventID == "" ||
		a.EventSequence == 0 || a.UpdatedAt.IsZero() || !a.NextPollAt.After(a.UpdatedAt) && a.Status != "queued" {
		return errors.New("store: incomplete upstream ARI event")
	}
	if a.Status != "queued" && a.Status != "ready" && a.Status != "error" && a.Status != "unavailable" {
		return errors.New("store: unknown upstream ARI status")
	}
	if a.Status == "ready" && (a.WindowStart == nil || a.WindowEnd == nil || !a.WindowEnd.After(*a.WindowStart)) {
		return errors.New("store: invalid upstream ARI window")
	}
	if (a.WindowStart == nil) != (a.WindowEnd == nil) || a.FailureCount < 0 {
		return errors.New("store: invalid upstream ARI observation")
	}
	if a.Status != "queued" && a.NextPollAt.Sub(a.UpdatedAt) > 24*time.Hour {
		return errors.New("store: upstream ARI poll exceeds one-day bound")
	}
	return nil
}

func exactExternalARICertificateTx(ctx context.Context, tx pgx.Tx, a ACMEUpstreamARI) (string, time.Time, error) {
	var status string
	var notAfter time.Time
	err := tx.QueryRow(ctx, `SELECT status, not_after FROM certificates
		WHERE tenant_id=$1 AND id=$2 AND fingerprint=$3 AND issuing_external_ca_id=$4 AND not_after IS NOT NULL
		FOR UPDATE`, a.TenantID, a.CertificateID, a.Fingerprint, a.AuthorityID).
		Scan(&status, &notAfter)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store: upstream ARI certificate binding: %w", err)
	}
	return status, notAfter, nil
}

func upstreamARIPayload(a ACMEUpstreamARI) ([]byte, error) {
	return json.Marshal(acmeUpstreamARIFetchPayload{
		CertificateID: a.CertificateID, AuthorityID: a.AuthorityID,
		ARICertificateID: a.ARICertificateID, Fingerprint: a.Fingerprint,
	})
}

func enqueueUpstreamARIFetchTx(ctx context.Context, tx pgx.Tx, a ACMEUpstreamARI, due time.Time, suffix string) error {
	payload, err := upstreamARIPayload(a)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox
		(tenant_id, destination, effect_lane, required_agent_role, payload, idempotency_key, next_attempt_at)
		VALUES ($1, $2, $3, 'control_plane', $4, $5, $6) ON CONFLICT DO NOTHING`,
		a.TenantID, ACMEUpstreamARIFetchDestination,
		"external-ca.ari:"+a.AuthorityID, payload, "external-ca.ari.fetch:"+suffix, due)
	return err
}

// ApplyACMEUpstreamARIRequestedTx projects a poll request and its outbox effect
// in the same tenant transaction. A replay of the same or older event does not
// erase an observation or enqueue a second fetch.
func (s *Store) ApplyACMEUpstreamARIRequestedTx(ctx context.Context, tx pgx.Tx, a ACMEUpstreamARI) error {
	a.Status = "queued"
	if err := validateACMEUpstreamARI(a); err != nil {
		return err
	}
	status, notAfter, err := exactExternalARICertificateTx(ctx, tx, a)
	if err != nil {
		return err
	}
	if status != "active" || !notAfter.After(a.UpdatedAt) {
		return nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO acme_upstream_ari
		(tenant_id, certificate_id, authority_id, certificate_id_ari, fingerprint,
		 status, updated_at, next_poll_at, event_sequence)
		VALUES ($1,$2,$3,$4,$5,'queued',$6,$6,$7)
		ON CONFLICT (tenant_id, certificate_id) DO UPDATE SET
		 status='queued', updated_at=EXCLUDED.updated_at,
		 next_poll_at=EXCLUDED.next_poll_at, event_sequence=EXCLUDED.event_sequence
		WHERE acme_upstream_ari.authority_id=EXCLUDED.authority_id
		 AND acme_upstream_ari.fingerprint=EXCLUDED.fingerprint
		 AND acme_upstream_ari.certificate_id_ari=EXCLUDED.certificate_id_ari
		 AND acme_upstream_ari.event_sequence < EXCLUDED.event_sequence`,
		a.TenantID, a.CertificateID, a.AuthorityID, a.ARICertificateID,
		a.Fingerprint, a.UpdatedAt, int64(a.EventSequence)) // #nosec G115 -- JetStream sequence is bounded by PostgreSQL bigint (CWE-190)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return enqueueUpstreamARIFetchTx(ctx, tx, a, a.UpdatedAt, a.EventID)
}

// ApplyACMEUpstreamARIObservedTx records a fetched window or a classified
// failure. An error keeps the last valid window so a temporary outage cannot
// silently delay an already scheduled renewal. The next poll intent is in the
// same transaction as the observation, and inactive leaves get no new poll.
func (s *Store) ApplyACMEUpstreamARIObservedTx(ctx context.Context, tx pgx.Tx, a ACMEUpstreamARI) error {
	if a.Status == "queued" {
		return errors.New("store: queued ARI status is not a fetch result")
	}
	if err := validateACMEUpstreamARI(a); err != nil {
		return err
	}
	status, notAfter, err := exactExternalARICertificateTx(ctx, tx, a)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO acme_upstream_ari
		(tenant_id, certificate_id, authority_id, certificate_id_ari, fingerprint,
		 status, window_start, window_end, updated_at, fetched_at, next_poll_at,
		 failure_count, error_class, event_sequence)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (tenant_id, certificate_id) DO UPDATE SET
		 status=EXCLUDED.status,
		 window_start=CASE WHEN EXCLUDED.status='ready' THEN EXCLUDED.window_start ELSE acme_upstream_ari.window_start END,
		 window_end=CASE WHEN EXCLUDED.status='ready' THEN EXCLUDED.window_end ELSE acme_upstream_ari.window_end END,
		 updated_at=EXCLUDED.updated_at,
		 fetched_at=COALESCE(EXCLUDED.fetched_at, acme_upstream_ari.fetched_at),
		 next_poll_at=EXCLUDED.next_poll_at,
		 failure_count=EXCLUDED.failure_count,
		 error_class=EXCLUDED.error_class,
		 event_sequence=EXCLUDED.event_sequence
		WHERE acme_upstream_ari.authority_id=EXCLUDED.authority_id
		 AND acme_upstream_ari.fingerprint=EXCLUDED.fingerprint
		 AND acme_upstream_ari.certificate_id_ari=EXCLUDED.certificate_id_ari
		 AND acme_upstream_ari.event_sequence < EXCLUDED.event_sequence`,
		a.TenantID, a.CertificateID, a.AuthorityID, a.ARICertificateID,
		a.Fingerprint, a.Status, a.WindowStart, a.WindowEnd, a.UpdatedAt,
		a.FetchedAt, a.NextPollAt, a.FailureCount, a.ErrorClass,
		int64(a.EventSequence)) // #nosec G115 -- JetStream sequence is bounded by PostgreSQL bigint (CWE-190)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 || status != "active" || !notAfter.After(a.NextPollAt) {
		return nil
	}
	return enqueueUpstreamARIFetchTx(ctx, tx, a, a.NextPollAt, a.EventID)
}

// GetACMEUpstreamARI reads the exact certificate's latest observation through
// its tenant RLS context. A missing row is distinct from no ARI advertisement.
func (s *Store) GetACMEUpstreamARI(ctx context.Context, tenantID, certificateID string) (ACMEUpstreamARI, error) {
	var a ACMEUpstreamARI
	var seq int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, certificate_id::text, authority_id,
		 certificate_id_ari, fingerprint, status, window_start, window_end,
		 updated_at, fetched_at, next_poll_at, failure_count, error_class, event_sequence
		 FROM acme_upstream_ari WHERE tenant_id=$1 AND certificate_id=$2`, tenantID, certificateID).
			Scan(&a.TenantID, &a.CertificateID, &a.AuthorityID, &a.ARICertificateID,
				&a.Fingerprint, &a.Status, &a.WindowStart, &a.WindowEnd, &a.UpdatedAt,
				&a.FetchedAt, &a.NextPollAt, &a.FailureCount, &a.ErrorClass, &seq)
	})
	if err != nil {
		return ACMEUpstreamARI{}, err
	}
	a.EventSequence = uint64(seq) // #nosec G115 -- DB CHECK keeps event_sequence positive (CWE-190)
	return a, nil
}

func (a ACMEUpstreamARI) CanSchedule() bool {
	// A queued refresh retains the last accepted CA window until its result
	// arrives. Only the first request has no window and cannot schedule from it.
	return (a.Status == "ready" || a.Status == "error" || a.Status == "queued") &&
		a.WindowStart != nil && a.WindowEnd != nil && a.WindowEnd.After(*a.WindowStart) &&
		strings.TrimSpace(a.AuthorityID) != ""
}
