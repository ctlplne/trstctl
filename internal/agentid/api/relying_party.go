// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

// relying_party.go serves what a relying service needs to honor chain-bound agent
// credentials: the tenant's issuing CA to pin, and each credential's current status, so
// a revocation stops further use of a credential before it expires.

// IssuingCAReader reads a tenant's agent issuing CA certificate from the isolated
// signer over its authenticated transport. Only public material crosses.
type IssuingCAReader interface {
	AgentIssuingCA(ctx context.Context, tenantID string) ([]byte, error)
}

// ErrIssuingCAUnavailable means the signer could not publish the tenant's issuing CA.
var ErrIssuingCAUnavailable = errors.New("agentid api: the signer's agent issuing CA is unavailable")

// Credential status values a relying service acts on. Only active is honored.
const (
	CredentialStatusActive  = "active"
	CredentialStatusRevoked = "revoked"
	CredentialStatusExpired = "expired"
	CredentialStatusUnknown = "unknown"
)

// IssuingCAResponse is the tenant's agent issuing CA: the trust root its relying
// services pin to verify the chain-bound credentials agents present. The key behind
// it is stable for the tenant; the certificate is re-issued over the same key before
// it expires, so spki_sha256 is the durable pin.
type IssuingCAResponse struct {
	TenantID       string    `json:"tenant_id"`
	CertificatePEM string    `json:"certificate_pem"`
	CertificateDER []byte    `json:"certificate_der"`
	SPKISHA256     string    `json:"spki_sha256"`
	Subject        string    `json:"subject"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

// CredentialStatusResponse is a credential's status for a relying service. Status is
// revoked once a revocation's cascade has recorded a job against the credential;
// revocation_evidenced reports whether the job's effect has been recorded with signed
// completion evidence. credential_sha256 lets the relying service confirm the status
// is for the exact credential the agent presented.
type CredentialStatusResponse struct {
	CredentialID        string     `json:"credential_id"`
	Found               bool       `json:"found"`
	Status              string     `json:"status"`
	CredentialSHA256    string     `json:"credential_sha256,omitempty"`
	SubjectID           string     `json:"subject_id,omitempty"`
	NotBefore           int64      `json:"not_before,omitempty"`
	NotAfter            int64      `json:"not_after,omitempty"`
	DirectiveID         string     `json:"directive_id,omitempty"`
	RevocationReason    string     `json:"revocation_reason,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevocationEvidenced bool       `json:"revocation_evidenced"`
	CheckedAt           time.Time  `json:"checked_at"`
}

// IssuingCA reads the tenant's issuing CA certificate from the signer and describes it.
func (s *service) IssuingCA(ctx context.Context, tenantID string) (IssuingCAResponse, error) {
	if s.issuingCA == nil {
		return IssuingCAResponse{}, ErrIssuingCAUnavailable
	}
	der, err := s.issuingCA.AgentIssuingCA(ctx, tenantID)
	if err != nil || len(der) == 0 {
		return IssuingCAResponse{}, ErrIssuingCAUnavailable
	}
	facts, err := crypto.CertificateFactsFromDER(der)
	if err != nil {
		return IssuingCAResponse{}, fmt.Errorf("%w: the signer returned an unreadable certificate", ErrIssuingCAUnavailable)
	}
	spki, err := crypto.CertificateSubjectPublicKeyInfo(der)
	if err != nil {
		return IssuingCAResponse{}, fmt.Errorf("%w: the signer returned an unreadable certificate", ErrIssuingCAUnavailable)
	}
	return IssuingCAResponse{
		TenantID:       tenantID,
		CertificatePEM: string(crypto.EncodeCertificatePEM(der)),
		CertificateDER: der,
		SPKISHA256:     crypto.SHA256Hex(spki),
		Subject:        facts.SubjectDN,
		NotBefore:      facts.NotBefore.UTC(),
		NotAfter:       facts.NotAfter.UTC(),
	}, nil
}

// CredentialStatus reads an issued credential's status from the tenant's issuance and
// revocation ledger (RLS-scoped).
func (s *service) CredentialStatus(ctx context.Context, tenantID, credentialID string) (CredentialStatusResponse, error) {
	now := time.Now().UTC()
	resp := CredentialStatusResponse{CredentialID: credentialID, Status: CredentialStatusUnknown, CheckedAt: now}
	if s.store == nil {
		return resp, nil
	}
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var credentialDER []byte
		err := tx.QueryRow(ctx,
			`SELECT subject_id, credential_der, not_before, not_after
			   FROM agent_issuances
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND credential_id = $1`,
			credentialID).Scan(&resp.SubjectID, &credentialDER, &resp.NotBefore, &resp.NotAfter)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("agentid api: read credential: %w", err)
		}
		resp.Found = true
		if len(credentialDER) > 0 {
			resp.CredentialSHA256 = crypto.SHA256Hex(credentialDER)
		}
		// The earliest revocation that reached this credential: a cascade job (the
		// durable decision) or, for a ledger that recorded only the effect, the effect.
		var revokedAt time.Time
		err = tx.QueryRow(ctx,
			`SELECT r.directive_id, r.created_at, COALESCE(d.reason, '')
			   FROM (SELECT directive_id, created_at FROM agent_revocation_jobs
			          WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = $1
			         UNION ALL
			         SELECT directive_id, created_at FROM agent_revocation_effects
			          WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = $1) r
			   LEFT JOIN agent_revocation_directives d
			     ON d.tenant_id = current_setting('trstctl.tenant_id')::uuid AND d.directive_id = r.directive_id
			  ORDER BY r.created_at, r.directive_id
			  LIMIT 1`,
			credentialID).Scan(&resp.DirectiveID, &revokedAt, &resp.RevocationReason)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("agentid api: read credential revocation: %w", err)
		default:
			revokedAt = revokedAt.UTC()
			resp.RevokedAt = &revokedAt
			if err := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM agent_revocation_effects
				  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND credential_id = $1)`,
				credentialID).Scan(&resp.RevocationEvidenced); err != nil {
				return fmt.Errorf("agentid api: read credential revocation evidence: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return CredentialStatusResponse{}, err
	}
	switch {
	case !resp.Found:
		resp.Status = CredentialStatusUnknown
	case resp.RevokedAt != nil:
		resp.Status = CredentialStatusRevoked
	case resp.NotAfter > 0 && now.Unix() >= resp.NotAfter:
		resp.Status = CredentialStatusExpired
	default:
		resp.Status = CredentialStatusActive
	}
	return resp, nil
}

func issuingCAHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		start := time.Now()
		resp, err := svc.IssuingCA(r.Context(), tenantID)
		a.ObserveFeature("agentid", "issuing-ca", start, err)
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "the agent issuing CA is unavailable; retry after the signer recovers")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func credentialStatusHandler(a *api.API, svc Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := a.Tenant(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "missing or invalid tenant")
			return
		}
		credentialID := r.URL.Query().Get("credential_id")
		if credentialID == "" {
			writeProblem(w, http.StatusBadRequest, "credential_id query parameter is required")
			return
		}
		start := time.Now()
		resp, err := svc.CredentialStatus(r.Context(), tenantID, credentialID)
		a.ObserveFeature("agentid", "credential-status", start, err)
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "credential status is unavailable; a relying service must not honor the credential until it reads one")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, resp)
	}
}

func relyingPartySchemas() map[string]*api.Schema {
	return map[string]*api.Schema{
		"AGIDIssuingCA": api.ObjectSchema(map[string]*api.Schema{
			"tenant_id":       api.StringSchema(),
			"certificate_pem": api.StringSchema(),
			"certificate_der": api.StringSchema(), // base64-encoded issuing CA certificate DER
			"spki_sha256":     {Type: "string", Description: "Lowercase hex SHA-256 of the CA's SubjectPublicKeyInfo; stable across certificate re-issues and signer restarts."},
			"subject":         api.StringSchema(),
			"not_before":      api.TimestampSchema(),
			"not_after":       api.TimestampSchema(),
		}, "tenant_id", "certificate_pem", "certificate_der", "spki_sha256", "not_after"),
		"AGIDCredentialStatus": api.ObjectSchema(map[string]*api.Schema{
			"credential_id":        api.StringSchema(),
			"found":                api.BooleanSchema(),
			"status":               {Type: "string", Enum: []string{CredentialStatusActive, CredentialStatusRevoked, CredentialStatusExpired, CredentialStatusUnknown}, Description: "Only active is honored: revoked once a revocation's cascade recorded a job against the credential, expired past not_after, unknown when no credential has this ID in the tenant."},
			"credential_sha256":    {Type: "string", Description: "Lowercase hex SHA-256 of the credential's DER; a relying service compares it with the credential the agent presented."},
			"subject_id":           api.StringSchema(),
			"not_before":           api.IntegerSchema(),
			"not_after":            api.IntegerSchema(),
			"directive_id":         api.StringSchema(),
			"revocation_reason":    api.StringSchema(),
			"revoked_at":           api.TimestampSchema(),
			"revocation_evidenced": api.BooleanSchema(),
			"checked_at":           api.TimestampSchema(),
		}, "credential_id", "found", "status", "revocation_evidenced", "checked_at"),
	}
}
