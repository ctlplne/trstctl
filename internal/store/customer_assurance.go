// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// CustomerAssuranceListLimit bounds each list a customer assurance report
// names. The count beside a list is exact.
const CustomerAssuranceListLimit = 10

// closedIncidentStatuses end an incident run; any other status is open.
var closedIncidentStatuses = []string{"executed", "failed", "rolled_back", "completed"}

// CustomerAssuranceFacts is what one tenant's store holds for its customer
// assurance report (A187): the inventory at At, and what changed in
// [From, Through). Expected ephemeral credentials are left out, as on the
// expiry views. One tenant transaction reads it, so the counts agree.
type CustomerAssuranceFacts struct {
	ActiveCertificates int
	OwnedCertificates  int
	// ExpiredActive are active certificates already past not_after; Expiring
	// expire after At and by At plus the report's window.
	ExpiredActive   int
	Expiring        int
	ExpiringSoonest []AssuranceCertificate
	UnownedSoonest  []AssuranceCertificate

	AddedInPeriod   int
	RenewedInPeriod int
	RevokedInPeriod int

	// FailedRenewals are renewal runs that ended failed in the period;
	// FailedDeliveries are connector deliveries that failed or whose
	// verification failed.
	FailedRenewals   int
	FailedDeliveries int
	Failures         []AssuranceFailure

	// VerifiedDeliveries are connector deliveries verified in the period.
	VerifiedDeliveries int
	// Endpoint observations are the latest per listener and vantage.
	EndpointObservations     int
	EndpointsMatching        int
	EndpointsMismatched      int
	EndpointsUnreachable     int
	EndpointsCheckedInPeriod int

	// Incidents are the runs open at Through or updated in the period,
	// newest first; IncidentsInPeriod counts them all.
	Incidents               []AssuranceIncident
	IncidentsInPeriod       int
	IncidentsOpenedInPeriod int
	IncidentsOpen           int
}

// AssuranceCertificate names one certificate in a report list.
type AssuranceCertificate struct {
	ID       string
	Subject  string
	NotAfter *time.Time
	Owner    string
}

// AssuranceFailure is one failed renewal run or connector delivery.
type AssuranceFailure struct {
	// Kind is "renewal" or "delivery".
	Kind    string
	ID      string
	Subject string
	// Via is the connector of a delivery.
	Via    string
	Status string
	Reason string
	At     time.Time
}

// AssuranceIncident is one incident run and the evidence bundle it recorded.
type AssuranceIncident struct {
	// Kind is "credential_compromise" or "issuer_compromise".
	Kind           string
	ID             string
	Status         string
	Phase          string
	Reason         string
	OpenedAt       time.Time
	UpdatedAt      time.Time
	EvidenceFormat string
	Evidence       string
}

// CustomerAssuranceFacts reads a tenant's report facts.
func (s *Store) CustomerAssuranceFacts(ctx context.Context, tenantID string, at, from, through time.Time, expiringWithin time.Duration) (CustomerAssuranceFacts, error) {
	if !from.Before(through) || expiringWithin <= 0 {
		return CustomerAssuranceFacts{}, errors.New("store: a customer assurance period must be non-empty")
	}
	var f CustomerAssuranceFacts
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FILTER (WHERE status = 'active'),
			        count(*) FILTER (WHERE status = 'active' AND owner_id IS NOT NULL),
			        count(*) FILTER (WHERE status = 'active' AND not_after <= $2),
			        count(*) FILTER (WHERE status = 'active' AND not_after > $2 AND not_after <= $3),
			        count(*) FILTER (WHERE created_at >= $4 AND created_at < $5),
			        count(*) FILTER (WHERE renewed_at >= $4 AND renewed_at < $5),
			        count(*) FILTER (WHERE revoked_at >= $4 AND revoked_at < $5)
			   FROM certificates
			  WHERE tenant_id = $1 AND issuance_idempotency_key NOT LIKE 'ephemeral-issue:%'`,
			tenantID, at, at.Add(expiringWithin), from, through,
		).Scan(&f.ActiveCertificates, &f.OwnedCertificates, &f.ExpiredActive, &f.Expiring,
			&f.AddedInPeriod, &f.RenewedInPeriod, &f.RevokedInPeriod); err != nil {
			return err
		}
		var err error
		if f.ExpiringSoonest, err = assuranceCertificates(ctx, tx, tenantID,
			`c.not_after > $2 AND c.not_after <= $3`, at, at.Add(expiringWithin)); err != nil {
			return err
		}
		if f.UnownedSoonest, err = assuranceCertificates(ctx, tx, tenantID, `c.owner_id IS NULL`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT (SELECT count(*) FROM lifecycle_rotation_runs
			          WHERE tenant_id = $1 AND status = 'failed' AND updated_at >= $2 AND updated_at < $3),
			        (SELECT count(*) FROM connector_delivery_receipts
			          WHERE tenant_id = $1 AND status IN ('failed', 'verify_failed') AND updated_at >= $2 AND updated_at < $3),
			        (SELECT count(*) FROM connector_delivery_receipts
			          WHERE tenant_id = $1 AND status = 'verified' AND updated_at >= $2 AND updated_at < $3)`,
			tenantID, from, through,
		).Scan(&f.FailedRenewals, &f.FailedDeliveries, &f.VerifiedDeliveries); err != nil {
			return err
		}
		if f.Failures, err = assuranceFailures(ctx, tx, tenantID, from, through); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE reached AND mismatch = ''),
			        count(*) FILTER (WHERE reached AND mismatch <> ''),
			        count(*) FILTER (WHERE NOT reached),
			        count(*) FILTER (WHERE last_checked_at >= $2 AND last_checked_at < $3)
			   FROM endpoint_verifications
			  WHERE tenant_id = $1`,
			tenantID, from, through,
		).Scan(&f.EndpointObservations, &f.EndpointsMatching, &f.EndpointsMismatched,
			&f.EndpointsUnreachable, &f.EndpointsCheckedInPeriod); err != nil {
			return err
		}
		return f.readIncidents(ctx, tx, tenantID, from, through)
	})
	if err != nil {
		return CustomerAssuranceFacts{}, err
	}
	return f, nil
}

// assuranceCertificates lists the active certificates matching where, whose
// parameters follow the tenant's, soonest expiry first.
func assuranceCertificates(ctx context.Context, tx pgx.Tx, tenantID, where string, args ...any) ([]AssuranceCertificate, error) {
	// where is one of this file's constant predicates; every value is bound.
	rows, err := tx.Query(ctx,
		`SELECT c.id::text, c.subject, c.not_after, COALESCE(o.name, '')
		   FROM certificates c
		   LEFT JOIN owners o ON o.tenant_id = c.tenant_id AND o.id = c.owner_id
		  WHERE c.tenant_id = $1 AND c.status = 'active'
		    AND c.issuance_idempotency_key NOT LIKE 'ephemeral-issue:%' AND `+where+`
		  ORDER BY c.not_after NULLS LAST, c.id
		  LIMIT `+strconv.Itoa(CustomerAssuranceListLimit), append([]any{tenantID}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssuranceCertificate{}
	for rows.Next() {
		var c AssuranceCertificate
		if err := rows.Scan(&c.ID, &c.Subject, &c.NotAfter, &c.Owner); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func assuranceFailures(ctx context.Context, tx pgx.Tx, tenantID string, from, through time.Time) ([]AssuranceFailure, error) {
	rows, err := tx.Query(ctx,
		`SELECT kind, id, subject, via, status, reason, at FROM (
		     SELECT 'renewal' AS kind, r.id::text AS id, COALESCE(i.name, r.identity_id::text) AS subject,
		            '' AS via, r.status, CASE WHEN r.error <> '' THEN r.error ELSE r.reason END AS reason,
		            r.updated_at AS at
		       FROM lifecycle_rotation_runs r
		       LEFT JOIN identities i ON i.tenant_id = r.tenant_id AND i.id = r.identity_id
		      WHERE r.tenant_id = $1 AND r.status = 'failed' AND r.updated_at >= $2 AND r.updated_at < $3
		     UNION ALL
		     SELECT 'delivery', d.id::text, d.target, d.connector, d.status,
		            CASE WHEN d.reason <> '' THEN d.reason ELSE d.detail END, d.updated_at
		       FROM connector_delivery_receipts d
		      WHERE d.tenant_id = $1 AND d.status IN ('failed', 'verify_failed')
		        AND d.updated_at >= $2 AND d.updated_at < $3
		 ) failures
		 ORDER BY at DESC, id
		 LIMIT $4`, tenantID, from, through, CustomerAssuranceListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssuranceFailure{}
	for rows.Next() {
		var f AssuranceFailure
		if err := rows.Scan(&f.Kind, &f.ID, &f.Subject, &f.Via, &f.Status, &f.Reason, &f.At); err != nil {
			return nil, err
		}
		f.At = f.At.UTC()
		out = append(out, f)
	}
	return out, rows.Err()
}

// readIncidents reads the incident runs created before through that were
// updated in the period or are still open.
func (f *CustomerAssuranceFacts) readIncidents(ctx context.Context, tx pgx.Tx, tenantID string, from, through time.Time) error {
	const runs = `SELECT tenant_id, 'credential_compromise' AS kind, id::text AS id, status, phase, reason,
		        created_at, updated_at, evidence_bundle_format, evidence_bundle
		   FROM incident_executions WHERE tenant_id = $1
		 UNION ALL
		 SELECT tenant_id, 'issuer_compromise', id::text, status, phase, reason,
		        created_at, updated_at, evidence_bundle_format, evidence_bundle
		   FROM incident_fleet_reissuance_runs WHERE tenant_id = $1`
	const inPeriod = `created_at < $3 AND ((updated_at >= $2 AND updated_at < $3) OR NOT (status = ANY($4)))`
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE `+inPeriod+`),
		        count(*) FILTER (WHERE created_at >= $2 AND created_at < $3),
		        count(*) FILTER (WHERE created_at < $3 AND NOT (status = ANY($4)))
		   FROM (`+runs+`) incidents
		  WHERE tenant_id = $1`,
		tenantID, from, through, closedIncidentStatuses,
	).Scan(&f.IncidentsInPeriod, &f.IncidentsOpenedInPeriod, &f.IncidentsOpen); err != nil {
		return err
	}
	rows, err := tx.Query(ctx,
		`SELECT kind, id, status, phase, reason, created_at, updated_at, evidence_bundle_format, evidence_bundle
		   FROM (`+runs+`) incidents
		  WHERE tenant_id = $1 AND `+inPeriod+`
		  ORDER BY updated_at DESC, id
		  LIMIT $5`, tenantID, from, through, closedIncidentStatuses, CustomerAssuranceListLimit)
	if err != nil {
		return err
	}
	defer rows.Close()
	f.Incidents = []AssuranceIncident{}
	for rows.Next() {
		var in AssuranceIncident
		if err := rows.Scan(&in.Kind, &in.ID, &in.Status, &in.Phase, &in.Reason, &in.OpenedAt, &in.UpdatedAt,
			&in.EvidenceFormat, &in.Evidence); err != nil {
			return err
		}
		in.OpenedAt, in.UpdatedAt = in.OpenedAt.UTC(), in.UpdatedAt.UTC()
		f.Incidents = append(f.Incidents, in)
	}
	return rows.Err()
}
