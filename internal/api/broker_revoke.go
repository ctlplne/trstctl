// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// One-call revoke of an AI agent's broker identity (Q4). It is the exact
// certificate revocation the revocation center runs, narrowed to one broker
// certificate: the issuing CA's ledger records it, the signed CRL and OCSP
// answer revoked, and the agent key set drops the key, so a relying party
// refuses the agent's next use. A retry with the same key replays the result
// and revokes nothing twice; the revocation event names who revoked.
//
// The same call ends what acts as the agent here (A257): the access bundle
// runs minted for its agent ID are revoked, so the control plane refuses
// their next request, and every live privileged session the agent opened,
// itself or through such a run, is revoked as an operator's revocation is
// (a gateway session's connections close). Ending what the identity opened
// is part of revoking it, so certs:issue is all the call needs.

type brokerAgentIdentityRevokeRequest struct {
	Reason string `json:"reason"`
}

// brokerAgentIdentityRevoked is the certificate revocation's result with the
// runs and sessions the call ended.
type brokerAgentIdentityRevoked struct {
	orchestrator.BulkRevokeResult
	Runs     []string                  `json:"runs"`
	Sessions []brokerAgentSessionEnded `json:"sessions"`
}

type brokerAgentSessionEnded struct {
	ID         string `json:"id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Role       string `json:"role"`
	Status     string `json:"status"`
}

func (a *API) brokerRevokeRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/broker/agent-identities/{id}/revoke", opID: "revokeBrokerAgentIdentity",
			summary: "Revoke one AI agent's broker identity in one call; relying parties refuse its next use, and the access runs and privileged sessions acting as the agent end",
			handler: a.revokeBrokerAgentIdentity, pathParams: []param{pathUUID("id")},
			reqSchema: "BrokerAgentIdentityRevokeRequest", resSchema: "BrokerAgentIdentityRevokeResult", successCode: "200",
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
		cert, err := a.store.GetBrokerCertificate(ctx, tenantID, id.String(), time.Now().UTC())
		if errors.Is(err, pgx.ErrNoRows) {
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
		status, body, err := a.revokeSelectedCertificates(w, ctx, tenantID, idempotencyKey, r.URL.EscapedPath(), principal,
			bulkRevokeRequest{CertificateIDs: []string{id.String()}, Reason: reason})
		if err != nil || status != http.StatusOK {
			return status, body, err
		}
		result, _ := body.(orchestrator.BulkRevokeResult)
		out := brokerAgentIdentityRevoked{BulkRevokeResult: result, Runs: []string{}, Sessions: []brokerAgentSessionEnded{}}
		if cert.Issuance == nil || cert.Issuance.AgentID == "" {
			return status, out, nil
		}
		if out.Runs, out.Sessions, err = a.endAgentAccess(ctx, tenantID, cert.Issuance.AgentID, principal.Subject, reason, idempotencyKey); err != nil {
			return 0, nil, err
		}
		return status, out, nil
	})
}

// endAgentAccess revokes the access bundle runs minted for the agent first, so
// it cannot open another session, then the live sessions it opened. A retried
// call finds only what is still live.
func (a *API) endAgentAccess(ctx context.Context, tenantID, agent, actor, reason, idempotencyKey string) ([]string, []brokerAgentSessionEnded, error) {
	runs := []string{}
	for pass := 0; ; pass++ {
		live, err := a.store.ListLiveAccessBundleRuns(ctx, tenantID, agent, time.Now(), 100)
		if err != nil {
			return nil, nil, err
		}
		if len(live) == 0 {
			break
		}
		if pass == agentRevokePages {
			return nil, nil, errStatus(http.StatusServiceUnavailable, "the agent has more live access runs than one call revokes; retry with the same Idempotency-Key")
		}
		for _, run := range live {
			if err := a.orch.RevokeAccessBundleRun(ctx, tenantID, run.ID, actor); err != nil {
				return nil, nil, fmt.Errorf("revoke access run %s: %w", run.ID, err)
			}
			runs = append(runs, run.ID)
		}
	}
	sessions := []brokerAgentSessionEnded{}
	revoker, ok := a.pam.(PAMAgentSessionRevoker)
	if !ok {
		return runs, sessions, nil
	}
	ended, err := revoker.RevokeAgentPAMSessions(ctx, tenantID, agent, actor, "agent identity revoked: "+reason, idempotencyKey)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range ended {
		sessions = append(sessions, brokerAgentSessionEnded{ID: s.ID, TargetType: s.TargetType, TargetID: s.TargetID, Role: s.Role, Status: s.Status})
	}
	return runs, sessions, nil
}

// agentRevokePages bounds one call's passes over an agent's live runs; each
// pass revokes up to 100.
const agentRevokePages = 10
