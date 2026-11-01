// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
)

// One-call revoke of an AI agent's broker identity (Q4). It is the exact
// certificate revocation the revocation center runs, narrowed to one broker
// certificate: the issuing CA's ledger records it, the signed CRL and OCSP
// answer revoked, and the agent key set drops the key, so a relying party
// refuses the agent's next use. A retry with the same key replays the result
// and revokes nothing twice; the revocation event names who revoked.

type brokerAgentIdentityRevokeRequest struct {
	Reason string `json:"reason"`
}

func (a *API) brokerRevokeRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/broker/agent-identities/{id}/revoke", opID: "revokeBrokerAgentIdentity",
			summary: "Revoke one AI agent's broker identity in one call; relying parties refuse its next use",
			handler: a.revokeBrokerAgentIdentity, pathParams: []param{pathUUID("id")},
			reqSchema: "BrokerAgentIdentityRevokeRequest", resSchema: "BulkRevokeResult", successCode: "200",
			mutation: true, perm: authz.CertsIssue},
	}
}

//trstctl:mutation
func (a *API) revokeBrokerAgentIdentity(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.store == nil || a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "agent identity revocation is not configured")
		}
		id, err := googleuuid.Parse(r.PathValue("id"))
		if err != nil {
			return 0, nil, errStatus(http.StatusNotFound, "no broker certificate found")
		}
		if _, err := a.store.GetBrokerCertificate(ctx, tenantID, id.String(), time.Now().UTC()); errors.Is(err, pgx.ErrNoRows) {
			// Only an agent broker identity is revocable here; any other
			// certificate goes through the revocation center.
			return 0, nil, errStatus(http.StatusNotFound, "no broker certificate found")
		} else if err != nil {
			return 0, nil, err
		}
		var req brokerAgentIdentityRevokeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		reason := strings.TrimSpace(req.Reason)
		if !crypto.IsValidRevocationReason(reason) {
			return 0, nil, errStatus(http.StatusBadRequest, "a revocation reason is required: use an RFC 5280 reason such as keyCompromise or cessationOfOperation")
		}
		principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
		return a.revokeSelectedCertificates(w, ctx, tenantID, idempotencyKey, r.URL.EscapedPath(), principal,
			bulkRevokeRequest{CertificateIDs: []string{id.String()}, Reason: reason})
	})
}
