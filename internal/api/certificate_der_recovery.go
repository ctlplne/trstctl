// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

// ErrCertificateDERRecoveryInvalid: the request names no method this control
// plane runs, or an endpoint egress it cannot honor.
var ErrCertificateDERRecoveryInvalid = errors.New("api: invalid certificate byte recovery")

// CertificateDERRecoveryRequest asks for an inventory row's certificate bytes
// (A215): from a mint of the tenant's own CA that retained them (ca_ledger) or
// from the endpoint the row records (endpoint).
type CertificateDERRecoveryRequest struct {
	Method               string   `json:"method"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

// CertificateDERRecovery is what a recovery found.
type CertificateDERRecovery struct {
	CertificateID string `json:"certificate_id"`
	Fingerprint   string `json:"fingerprint"`
	Method        string `json:"method"`
	// Outcome: recovered | already_held | not_found | mismatch | unreachable.
	Outcome  string `json:"outcome"`
	Evidence string `json:"evidence,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// CertificateDERRecoveryRecord is how a certificate's bytes were recovered,
// on its detail read.
type CertificateDERRecoveryRecord struct {
	Method      string `json:"method"`
	Evidence    string `json:"evidence"`
	RecoveredAt string `json:"recovered_at"`
}

func (a *API) certificateDERRecoveryRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/certificates/{id}/der-recovery", opID: "recoverCertificateDER", summary: "Recover an inventory row's certificate bytes from the tenant's CA mint or the endpoint it records, attached only when they hash to the row's fingerprint", handler: a.recoverCertificateDER, pathParams: idPath, reqSchema: "CertificateDERRecoveryRequest", resSchema: "CertificateDERRecovery", successCode: "200", mutation: true, perm: authz.CertsWrite},
	}
}

//trstctl:mutation
func (a *API) recoverCertificateDER(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pkiSecretLeafRecovery == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "certificate byte recovery is not available on this control plane")
		}
		var req CertificateDERRecoveryRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Method = strings.TrimSpace(req.Method)
		if req.AllowPrivateEndpoint {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
			req.PrivateEgressCIDRs = cleanAPIStringList(req.PrivateEgressCIDRs)
			if len(req.PrivateEgressCIDRs) == 0 {
				return 0, nil, errStatus(http.StatusBadRequest, "private_egress_cidrs is required when allow_private_endpoint is true")
			}
			if err := validatePrivateEgressCIDRs(req.PrivateEgressCIDRs); err != nil {
				return 0, nil, err
			}
		}
		out, err := a.pkiSecretLeafRecovery.RecoverCertificateDER(ctx, tenantID, id, req)
		if errors.Is(err, ErrCertificateDERRecoveryInvalid) {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

// certificateDERRecovery is how a certificate's bytes were recovered, for its
// detail read.
func (a *API) certificateDERRecovery(ctx context.Context, tenantID, fingerprint string) (*CertificateDERRecoveryRecord, error) {
	rec, found, err := a.store.CertificateDERRecoveryFor(ctx, tenantID, fingerprint)
	if err != nil || !found {
		return nil, err
	}
	return &CertificateDERRecoveryRecord{Method: rec.Method, Evidence: rec.Evidence,
		RecoveredAt: rec.RecoveredAt.UTC().Format(time.RFC3339)}, nil
}
