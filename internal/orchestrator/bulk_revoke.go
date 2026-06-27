package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// ErrBulkRevokeEmptyCriteria is returned when a bulk revoke request names neither
// explicit identities nor narrowing criteria.
var ErrBulkRevokeEmptyCriteria = errors.New("orchestrator: bulk revoke requires at least one identity id or criterion")

// BulkRevokeRequest selects tenant-local identities to revoke.
type BulkRevokeRequest struct {
	IDs      []string `json:"ids,omitempty"`
	OwnerID  string   `json:"owner_id,omitempty"`
	IssuerID string   `json:"issuer_id,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Status   string   `json:"status,omitempty"`
	Reason   string   `json:"reason"`
}

// BulkRevokeResult summarizes a bulk revocation.
type BulkRevokeResult struct {
	TotalMatched int              `json:"total_matched"`
	TotalRevoked int              `json:"total_revoked"`
	TotalSkipped int              `json:"total_skipped"`
	TotalFailed  int              `json:"total_failed"`
	Items        []BulkRevokeItem `json:"items"`
}

// BulkRevokeItem reports the per-identity outcome inside a bulk revocation.
type BulkRevokeItem struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// BulkRevoke revokes every tenant-local identity selected by req. Each successful
// item is the normal lifecycle transition, so it appends the existing immutable
// event and enqueues the existing revocation outbox intent (AN-2/AN-6).
func (o *Orchestrator) BulkRevoke(ctx context.Context, tenantID string, req BulkRevokeRequest) (BulkRevokeResult, error) {
	if !req.hasSelectors() {
		return BulkRevokeResult{}, ErrBulkRevokeEmptyCriteria
	}
	reason := req.Reason
	if reason == "" {
		reason = string(crypto.RevocationReasonUnspecified)
	}
	if !crypto.IsValidRevocationReason(reason) {
		return BulkRevokeResult{}, fmt.Errorf("orchestrator: invalid revocation reason %q", reason)
	}
	idents, result, err := o.resolveBulkRevokeIdentities(ctx, tenantID, req)
	if err != nil {
		return BulkRevokeResult{}, err
	}
	for _, ident := range idents {
		result.TotalMatched++
		switch {
		case State(ident.Status) == StateRevoked:
			result.TotalSkipped++
			result.Items = append(result.Items, BulkRevokeItem{ID: ident.ID, Status: "skipped", Error: "already revoked"})
		case !CanTransition(State(ident.Status), StateRevoked):
			result.TotalFailed++
			result.Items = append(result.Items, BulkRevokeItem{ID: ident.ID, Status: "failed", Error: "invalid transition from " + ident.Status + " to revoked"})
		default:
			if err := o.Transition(ctx, tenantID, ident.ID, StateRevoked, reason); err != nil {
				result.TotalFailed++
				result.Items = append(result.Items, BulkRevokeItem{ID: ident.ID, Status: "failed", Error: err.Error()})
				continue
			}
			result.TotalRevoked++
			result.Items = append(result.Items, BulkRevokeItem{ID: ident.ID, Status: "revoked"})
		}
	}
	return result, nil
}

func (r BulkRevokeRequest) hasSelectors() bool {
	return len(r.IDs) > 0 || r.OwnerID != "" || r.IssuerID != "" || r.Kind != "" || r.Status != ""
}

func (o *Orchestrator) resolveBulkRevokeIdentities(ctx context.Context, tenantID string, req BulkRevokeRequest) ([]store.Identity, BulkRevokeResult, error) {
	hasIDs := len(req.IDs) > 0
	hasCriteria := req.OwnerID != "" || req.IssuerID != "" || req.Kind != "" || req.Status != ""
	if hasIDs && !hasCriteria {
		result := BulkRevokeResult{Items: make([]BulkRevokeItem, 0, len(req.IDs))}
		var out []store.Identity
		seen := map[string]bool{}
		for _, id := range req.IDs {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ident, err := o.store.GetIdentity(ctx, tenantID, id)
			if err != nil {
				result.TotalFailed++
				result.Items = append(result.Items, BulkRevokeItem{ID: id, Status: "failed", Error: "not found"})
				continue
			}
			out = append(out, ident)
		}
		return out, result, nil
	}

	idents, err := o.store.ListIdentities(ctx, tenantID)
	if err != nil {
		return nil, BulkRevokeResult{}, err
	}
	idSet := map[string]bool{}
	if hasIDs {
		for _, id := range req.IDs {
			idSet[id] = true
		}
	}
	out := make([]store.Identity, 0, len(idents))
	for _, ident := range idents {
		if hasIDs && !idSet[ident.ID] {
			continue
		}
		if !bulkRevokeMatchesCriteria(ident, req) {
			continue
		}
		out = append(out, ident)
	}
	return out, BulkRevokeResult{Items: make([]BulkRevokeItem, 0, len(out))}, nil
}

func bulkRevokeMatchesCriteria(ident store.Identity, req BulkRevokeRequest) bool {
	if req.OwnerID != "" && ident.OwnerID != req.OwnerID {
		return false
	}
	if req.IssuerID != "" {
		if ident.IssuerID == nil || *ident.IssuerID != req.IssuerID {
			return false
		}
	}
	if req.Kind != "" && string(ident.Kind) != req.Kind {
		return false
	}
	if req.Status != "" && ident.Status != req.Status {
		return false
	}
	return true
}
