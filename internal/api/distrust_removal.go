// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// DistrustedRootRemovalRequest names, as the operator reviewed it, the anchor
// to take out of a host trust store: the finding's certificate fingerprint and
// file path must still match when the removal is queued.
type DistrustedRootRemovalRequest struct {
	Fingerprint string `json:"fingerprint"`
	AnchorPath  string `json:"anchor_path"`
	Reason      string `json:"reason,omitempty"`
}

// distrustRemovalRoutes is the eMudhra Part 4 removal of a distrusted root an
// agent found in a host trust store, through the host's trust-distribution
// executor. It is a host mutation, so it takes connectors:write like the
// other host-side removals.
func (a *API) distrustRemovalRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/discovery/findings/{id}/remove-distrusted-root", opID: "removeDistrustedRoot",
			summary: "Queue removal of a distrusted root from the host trust store an agent found it in, through the host's trust-distribution executor",
			handler: a.removeDistrustedRoot, pathParams: idPath, reqSchema: "DistrustedRootRemovalRequest", resSchema: "ConnectorDelivery",
			successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
	}
}

//trstctl:mutation
func (a *API) removeDistrustedRoot(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	findingID := r.PathValue("id")
	var request DistrustedRootRemovalRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	request.Fingerprint = strings.ToLower(strings.TrimSpace(request.Fingerprint))
	request.AnchorPath = strings.TrimSpace(request.AnchorPath)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Fingerprint == "" || request.AnchorPath == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "removal needs the finding's fingerprint and anchor_path, as reviewed"))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	binding, err := json.Marshal(struct {
		Domain    string                       `json:"domain"`
		Actor     string                       `json:"actor"`
		FindingID string                       `json:"finding_id"`
		Request   DistrustedRootRemovalRequest `json:"request"`
	}{"trstctl.distrusted-root-removal.v1", principal.Subject, findingID, request})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, crypto.SHA256Hex(binding),
		func(ctx context.Context, tenantID string) (int, any, error) {
			if a.orch == nil {
				return 0, nil, errors.New("distrusted root removal orchestrator is unavailable")
			}
			finding, err := a.store.GetDiscoveryFinding(ctx, tenantID, findingID)
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, nil, errStatus(http.StatusNotFound, "no such discovery finding")
			}
			if err != nil {
				return 0, nil, err
			}
			target, err := orchestrator.DistrustedRootRemovalTarget(finding)
			if errors.Is(err, orchestrator.ErrDistrustRemovalIneligible) {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), orchestrator.ErrDistrustRemovalIneligible.Error()+": "))
			}
			if err != nil {
				return 0, nil, err
			}
			if target.Fingerprint != request.Fingerprint || target.AnchorPath != request.AnchorPath {
				return 0, nil, errStatus(http.StatusConflict, "the finding's fingerprint or path differs from the reviewed request; read the finding again")
			}
			receipt, err := a.orch.RequestDistrustedRootRemoval(ctx, tenantID, orchestrator.DistrustedRootRemovalRequest{
				FindingID: finding.ID, Fingerprint: target.Fingerprint, AnchorPath: target.AnchorPath,
				Reason: request.Reason, RequestedBy: principal.Subject, IdempotencyKey: idempotencyKey,
			})
			if errors.Is(err, store.ErrIdempotencyConflict) {
				return 0, nil, errStatus(http.StatusConflict, "the finding changed after review; read it again")
			}
			if err != nil {
				return 0, nil, err
			}
			return http.StatusAccepted, toConnectorDeliveryResponse(receipt), nil
		})
}
