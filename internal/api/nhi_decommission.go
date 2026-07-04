// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

var nhiDecommissionCoverage = []string{"departure", "vendor_term", "inactivity", "revoke", "retire", "event_sourced"}

type nhiDecommissionRequest struct {
	Reason           string                  `json:"reason"`
	RevocationReason string                  `json:"revocation_reason,omitempty"`
	Signals          []nhiDecommissionSignal `json:"signals"`
}

type nhiDecommissionSignal struct {
	Type           string     `json:"type"`
	Subject        string     `json:"subject,omitempty"`
	OwnerID        string     `json:"owner_id,omitempty"`
	OwnerName      string     `json:"owner_name,omitempty"`
	VendorName     string     `json:"vendor_name,omitempty"`
	IdentityID     string     `json:"identity_id,omitempty"`
	InactiveBefore *time.Time `json:"inactive_before,omitempty"`
	EvidenceRefs   []string   `json:"evidence_refs,omitempty"`
}

type nhiDecommissionResponse struct {
	Capability string                 `json:"capability"`
	Coverage   []string               `json:"coverage"`
	Reason     string                 `json:"reason"`
	Summary    nhiDecommissionSummary `json:"summary"`
	Items      []nhiDecommissionItem  `json:"items"`
}

type nhiDecommissionSummary struct {
	TotalMatched int `json:"total_matched"`
	Revoked      int `json:"revoked"`
	Retired      int `json:"retired"`
	Skipped      int `json:"skipped"`
	Failed       int `json:"failed"`
}

type nhiDecommissionItem struct {
	IdentityID   string   `json:"identity_id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	OwnerID      string   `json:"owner_id"`
	SignalType   string   `json:"signal_type"`
	Action       string   `json:"action"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type nhiDecommissionOwnerIndex struct {
	byID    map[string]store.Owner
	byName  map[string][]store.Owner
	byEmail map[string][]store.Owner
}

type nhiDecommissionMatch struct {
	signalType string
	evidence   []string
}

//trstctl:mutation
func (a *API) decommissionNHI(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req nhiDecommissionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		resp, err := a.runNHIDecommission(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, resp, nil
	})
}

func (a *API) runNHIDecommission(ctx context.Context, tenantID string, req nhiDecommissionRequest) (nhiDecommissionResponse, error) {
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		req.Reason = "NHI decommission requested"
	}
	revocationReason := strings.TrimSpace(req.RevocationReason)
	if revocationReason == "" {
		revocationReason = string(crypto.RevocationReasonCessationOfOperation)
	}
	if !crypto.IsValidRevocationReason(revocationReason) {
		return nhiDecommissionResponse{}, errStatus(http.StatusBadRequest, "invalid revocation_reason: use an RFC 5280 reason such as cessationOfOperation or privilegeWithdrawn")
	}
	if len(req.Signals) == 0 {
		return nhiDecommissionResponse{}, errStatus(http.StatusBadRequest, "at least one decommission signal is required")
	}
	for i := range req.Signals {
		req.Signals[i].Type = strings.TrimSpace(req.Signals[i].Type)
		if err := validateNHIDecommissionSignal(req.Signals[i]); err != nil {
			return nhiDecommissionResponse{}, err
		}
	}

	owners, err := a.store.ListOwners(ctx, tenantID)
	if err != nil {
		return nhiDecommissionResponse{}, err
	}
	idents, err := a.store.ListIdentities(ctx, tenantID)
	if err != nil {
		return nhiDecommissionResponse{}, err
	}
	idx := newNHIDecommissionOwnerIndex(owners)
	resp := nhiDecommissionResponse{
		Capability: "CAP-GOV-04",
		Coverage:   append([]string(nil), nhiDecommissionCoverage...),
		Reason:     req.Reason,
		Items:      make([]nhiDecommissionItem, 0, len(idents)),
	}
	seen := map[string]bool{}
	for _, sig := range req.Signals {
		for _, ident := range idents {
			if seen[ident.ID] {
				continue
			}
			match, ok := matchNHIDecommissionSignal(ident, idx, sig)
			if !ok {
				continue
			}
			seen[ident.ID] = true
			item := a.applyNHIDecommissionAction(ctx, tenantID, ident, match, req.Reason, revocationReason)
			resp.Items = append(resp.Items, item)
			resp.Summary.TotalMatched++
			switch item.Action {
			case "revoked":
				resp.Summary.Revoked++
			case "retired":
				resp.Summary.Retired++
			case "skipped":
				resp.Summary.Skipped++
			case "failed":
				resp.Summary.Failed++
			}
		}
	}
	return resp, nil
}

func validateNHIDecommissionSignal(sig nhiDecommissionSignal) error {
	switch sig.Type {
	case "departure":
		if allBlank(sig.Subject, sig.OwnerID, sig.OwnerName, sig.IdentityID) {
			return errStatus(http.StatusBadRequest, "departure signals require subject, owner_id, owner_name, or identity_id")
		}
	case "vendor_term":
		if allBlank(sig.VendorName, sig.OwnerID, sig.OwnerName, sig.IdentityID) {
			return errStatus(http.StatusBadRequest, "vendor_term signals require vendor_name, owner_id, owner_name, or identity_id")
		}
	case "inactivity":
		if sig.InactiveBefore == nil && allBlank(sig.IdentityID, sig.OwnerID, sig.OwnerName) {
			return errStatus(http.StatusBadRequest, "inactivity signals require inactive_before, identity_id, owner_id, or owner_name")
		}
	default:
		return errStatus(http.StatusBadRequest, "signal type must be departure, vendor_term, or inactivity")
	}
	return nil
}

func allBlank(vals ...string) bool {
	for _, val := range vals {
		if strings.TrimSpace(val) != "" {
			return false
		}
	}
	return true
}

func newNHIDecommissionOwnerIndex(owners []store.Owner) nhiDecommissionOwnerIndex {
	idx := nhiDecommissionOwnerIndex{
		byID:    make(map[string]store.Owner, len(owners)),
		byName:  map[string][]store.Owner{},
		byEmail: map[string][]store.Owner{},
	}
	for _, owner := range owners {
		idx.byID[owner.ID] = owner
		if key := normalizeNHIMatch(owner.Name); key != "" {
			idx.byName[key] = append(idx.byName[key], owner)
		}
		if key := normalizeNHIMatch(owner.Email); key != "" {
			idx.byEmail[key] = append(idx.byEmail[key], owner)
		}
	}
	return idx
}

func matchNHIDecommissionSignal(ident store.Identity, idx nhiDecommissionOwnerIndex, sig nhiDecommissionSignal) (nhiDecommissionMatch, bool) {
	evidence := append([]string(nil), sig.EvidenceRefs...)
	if strings.TrimSpace(sig.IdentityID) != "" {
		if strings.TrimSpace(sig.IdentityID) != ident.ID {
			return nhiDecommissionMatch{}, false
		}
		return nhiDecommissionMatch{signalType: sig.Type, evidence: append(evidence, "identity_id:"+ident.ID)}, true
	}
	attrs := decodeNHIAttrStrings(ident.Attributes)
	owner := idx.byID[ident.OwnerID]
	switch sig.Type {
	case "departure":
		if matchOwnerSignal(ident, owner, idx, sig.OwnerID, sig.OwnerName, sig.Subject, attrs, "human_owner", "owner", "owner_name", "owner_email", "subject", "employee_subject") {
			return nhiDecommissionMatch{signalType: sig.Type, evidence: append(evidence, "departure:"+firstNonBlank(sig.Subject, sig.OwnerName, sig.OwnerID))}, true
		}
	case "vendor_term":
		if matchOwnerSignal(ident, owner, idx, sig.OwnerID, firstNonBlank(sig.VendorName, sig.OwnerName), sig.VendorName, attrs, "vendor", "vendor_name", "provider") {
			return nhiDecommissionMatch{signalType: sig.Type, evidence: append(evidence, "vendor_term:"+firstNonBlank(sig.VendorName, sig.OwnerName, sig.OwnerID))}, true
		}
	case "inactivity":
		if !matchOwnerSignal(ident, owner, idx, sig.OwnerID, sig.OwnerName, "", attrs) {
			if strings.TrimSpace(sig.OwnerID) != "" || strings.TrimSpace(sig.OwnerName) != "" {
				return nhiDecommissionMatch{}, false
			}
		}
		if sig.InactiveBefore == nil {
			return nhiDecommissionMatch{signalType: sig.Type, evidence: append(evidence, "inactivity:selector")}, true
		}
		if lastSeen, ok := identityLastActivity(attrs); ok && lastSeen.Before(sig.InactiveBefore.UTC()) {
			return nhiDecommissionMatch{signalType: sig.Type, evidence: append(evidence, "last_activity_before:"+sig.InactiveBefore.UTC().Format(time.RFC3339))}, true
		}
	}
	return nhiDecommissionMatch{}, false
}

func matchOwnerSignal(ident store.Identity, owner store.Owner, idx nhiDecommissionOwnerIndex, ownerID, ownerName, subject string, attrs map[string]string, attrFields ...string) bool {
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" && ident.OwnerID == ownerID {
		return true
	}
	for _, raw := range []string{ownerName, subject} {
		key := normalizeNHIMatch(raw)
		if key == "" {
			continue
		}
		if normalizeNHIMatch(owner.Name) == key || normalizeNHIMatch(owner.Email) == key {
			return true
		}
		for _, candidate := range idx.byName[key] {
			if candidate.ID == ident.OwnerID {
				return true
			}
		}
		for _, candidate := range idx.byEmail[key] {
			if candidate.ID == ident.OwnerID {
				return true
			}
		}
		for _, field := range attrFields {
			if normalizeNHIMatch(attrs[field]) == key {
				return true
			}
		}
	}
	return len(attrFields) == 0 && strings.TrimSpace(ownerID) == "" && strings.TrimSpace(ownerName) == "" && strings.TrimSpace(subject) == ""
}

func (a *API) applyNHIDecommissionAction(ctx context.Context, tenantID string, ident store.Identity, match nhiDecommissionMatch, reason, revocationReason string) nhiDecommissionItem {
	from := orchestrator.State(ident.Status)
	item := nhiDecommissionItem{
		IdentityID: ident.ID, Name: ident.Name, Kind: string(ident.Kind), OwnerID: ident.OwnerID,
		SignalType: match.signalType, From: string(from), EvidenceRefs: append([]string(nil), match.evidence...),
	}
	switch {
	case from == orchestrator.StateRetired:
		item.Action = "skipped"
		item.To = string(from)
		item.Error = "already retired"
	case from == orchestrator.StateRevoked && orchestrator.CanTransition(from, orchestrator.StateRetired):
		if err := a.orch.Transition(ctx, tenantID, ident.ID, orchestrator.StateRetired, reason); err != nil {
			item.Action = "failed"
			item.To = string(from)
			item.Error = err.Error()
			return item
		}
		item.Action = "retired"
		item.To = string(orchestrator.StateRetired)
	case orchestrator.CanTransition(from, orchestrator.StateRevoked):
		if err := a.orch.Transition(ctx, tenantID, ident.ID, orchestrator.StateRevoked, revocationReason); err != nil {
			item.Action = "failed"
			item.To = string(from)
			item.Error = err.Error()
			return item
		}
		item.Action = "revoked"
		item.To = string(orchestrator.StateRevoked)
	default:
		item.Action = "skipped"
		item.To = string(from)
		item.Error = "state " + string(from) + " cannot be decommissioned automatically"
	}
	return item
}

func decodeNHIAttrStrings(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return out
	}
	for key, val := range attrs {
		if typed, ok := val.(string); ok {
			out[key] = typed
		}
	}
	return out
}

func identityLastActivity(attrs map[string]string) (time.Time, bool) {
	for _, field := range []string{"last_seen_at", "last_used_at", "last_activity_at", "last_seen", "last_used"} {
		if raw := strings.TrimSpace(attrs[field]); raw != "" {
			if t, err := time.Parse(time.RFC3339, raw); err == nil {
				return t.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func normalizeNHIMatch(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func firstNonBlank(vals ...string) string {
	for _, val := range vals {
		if strings.TrimSpace(val) != "" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}
