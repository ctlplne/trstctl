// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

type FirstIssuanceRetryReadiness struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type FirstIssuanceRetryService interface {
	RetryFirstIssuance(context.Context, string, string, string, string, string) (store.FirstIssuanceRetryReceipt, error)
	FirstIssuanceRetryReadiness(context.Context, string, string, string) (FirstIssuanceRetryReadiness, error)
}

func WithFirstIssuanceRetry(service FirstIssuanceRetryService) Option {
	return func(c *config) { c.firstIssuanceRetry = service }
}

type firstIssuanceRetryRequest struct {
	RequestKey string `json:"request_key"`
	Reason     string `json:"reason"`
}

type firstIssuanceRetryResponse struct {
	IdentityID   string `json:"identity_id"`
	RequestKey   string `json:"request_key"`
	RetryEventID string `json:"retry_event_id"`
	State        string `json:"state"`
	Attempts     int    `json:"attempts"`
	AttemptGrant int    `json:"attempt_grant"`
}

//trstctl:mutation
func (a *API) retryFirstIssuance(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	var req firstIssuanceRetryRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.RequestKey, req.Reason = strings.TrimSpace(req.RequestKey), strings.TrimSpace(req.Reason)
	if req.RequestKey == "" || len(req.RequestKey) > 256 || req.Reason == "" || len(req.Reason) > 1024 {
		a.writeError(w, errStatus(http.StatusBadRequest, "request_key (at most 256 bytes) and reason (at most 1024 bytes) are required"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	canonical, err := json.Marshal(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := mutationRequestRouteBinding(principal, r.Method, r.URL.EscapedPath(), r.URL.RawQuery, crypto.SHA256Hex(canonical))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.firstIssuanceRetry == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "issuance recovery is not configured")
		}
		receipt, err := a.firstIssuanceRetry.RetryFirstIssuance(ctx, tenantID, r.PathValue("id"), req.RequestKey, idempotencyKey, req.Reason)
		if errors.Is(err, store.ErrIssuanceRetryUnavailable) {
			return 0, nil, errStatus(http.StatusConflict, err.Error())
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, firstIssuanceRetryResponse{
			IdentityID: receipt.IdentityID, RequestKey: receipt.RequestKey, RetryEventID: receipt.EventID,
			State: "pending", Attempts: receipt.Attempts, AttemptGrant: 1,
		}, nil
	})
}
