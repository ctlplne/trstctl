// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// The plain causes of a host renewal job that did not complete (A36). They
// are a closed set read from the control plane's own records: the closed
// error class of the job's certificate authority request, or whether a
// certificate was signed for it. Text an agent reported never becomes one.
const (
	RenewalCauseCAValidation     = "The certificate authority could not validate the domain: its order or DNS-01 challenge failed. The renewal retries on its own once validation can succeed."
	RenewalCauseNoDNS01Provider  = "No DNS-01 provider covers this name, so the certificate authority cannot validate it. Add one for its zone, then retry the renewal."
	RenewalCauseCAAccount        = "The ACME account at the certificate authority could not be set up."
	RenewalCauseCAFinalize       = "The certificate authority refused to finalize the new certificate."
	RenewalCauseCAUnconfirmed    = "An earlier attempt left an unconfirmed result at the certificate authority, so this job cannot finish. Retry the renewal to start a new one."
	RenewalCauseCADidNotIssue    = "The certificate authority did not issue the new certificate. The renewal retries on its own while the authority is unavailable."
	RenewalCauseEnded            = "The attempt was ended before the certificate authority answered. Retry the renewal to start a new one."
	RenewalCauseIssuedNotServing = "The new certificate was issued, but the endpoint is not serving it: the host did not install it, or the endpoint did not present it when checked."
	RenewalCauseNotSigned        = "The host's request for the new certificate was not signed."
)

// renewalCauseForCAClass maps a certificate authority request's closed
// last_error class to its plain cause.
func renewalCauseForCAClass(class string) string {
	switch class {
	case "external_ca_order_failed":
		return RenewalCauseCAValidation
	case "external_ca_dns01_unconfigured":
		return RenewalCauseNoDNS01Provider
	case "external_ca_account_failed":
		return RenewalCauseCAAccount
	case "external_ca_finalize_failed":
		return RenewalCauseCAFinalize
	case "external_ca_idempotency_failed":
		return RenewalCauseCAUnconfirmed
	case OutboxLastErrorSupersededByRetry, OutboxLastErrorOperatorCancelled:
		return RenewalCauseEnded
	}
	return RenewalCauseCADidNotIssue
}

// hostRenewalFailureCauseTx is the plain cause of jobID not completing.
func hostRenewalFailureCauseTx(ctx context.Context, tx pgx.Tx, tenantID string, jobID int64) (string, error) {
	job := strconv.FormatInt(jobID, 10)
	var status, class string
	err := tx.QueryRow(ctx,
		`SELECT status, COALESCE(last_error, '') FROM outbox
		  WHERE tenant_id = $1 AND destination = 'external-ca.issue'
		    AND split_part(idempotency_key, ':', 1) = 'agentcsr'
		    AND split_part(idempotency_key, ':', 2) = $2
		  ORDER BY id DESC LIMIT 1`, tenantID, job).Scan(&status, &class)
	switch {
	case err == nil && status == "delivered":
		return RenewalCauseIssuedNotServing, nil
	case err == nil:
		return renewalCauseForCAClass(class), nil
	case !errors.Is(err, pgx.ErrNoRows):
		return "", err
	}
	var signed bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM certificates
		   WHERE tenant_id = $1 AND split_part(issuance_idempotency_key, ':', 1) = 'agentcsr'
		     AND split_part(issuance_idempotency_key, ':', 2) = $2)`, tenantID, job).Scan(&signed); err != nil {
		return "", err
	}
	if signed {
		return RenewalCauseIssuedNotServing, nil
	}
	return RenewalCauseNotSigned, nil
}

// HostRenewalFailure is the newest host renewal attempt of an identity that
// did not complete, with its plain cause.
type HostRenewalFailure struct {
	JobID   int64
	Attempt int
	Cause   string
}

// LatestHostRenewalFailure reads the identity's newest host renewal job that
// was attempted and did not complete. found is false when it has none.
func (s *Store) LatestHostRenewalFailure(ctx context.Context, tenantID, identityID string) (HostRenewalFailure, bool, error) {
	var out HostRenewalFailure
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT id, claim_attempts FROM outbox
			  WHERE tenant_id = $1 AND destination = 'endpoint.renew'
			    AND delivered_at IS NULL AND claim_attempts >= 1 AND attempts >= 1
			    AND convert_from(payload, 'UTF8')::jsonb ->> 'identity_id' = $2
			  ORDER BY id DESC LIMIT 1`, tenantID, identityID).Scan(&out.JobID, &out.Attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.Cause, err = hostRenewalFailureCauseTx(ctx, tx, tenantID, out.JobID)
		found = err == nil
		return err
	})
	return out, found, err
}
