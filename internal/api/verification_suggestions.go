// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// VerificationSuggestions answers where discovery saw the leaves trstctl
// delivered to a target (A214), so an operator can confirm one as the
// target's verification address. Nothing here changes the target.
type VerificationSuggestions struct {
	TargetID         string                   `json:"target_id"`
	TargetRevision   string                   `json:"target_revision"`
	VerifyAddress    string                   `json:"verify_address,omitempty"`
	VerifyServerName string                   `json:"verify_server_name,omitempty"`
	Suggestions      []VerificationSuggestion `json:"suggestions"`
	Note             string                   `json:"note"`
}

// VerificationSuggestion is one address and the findings that saw a delivered
// leaf there.
type VerificationSuggestion struct {
	Address  string                           `json:"address"`
	LastSeen string                           `json:"last_seen"`
	Evidence []VerificationSuggestionEvidence `json:"evidence"`
}

// VerificationSuggestionEvidence is one discovery finding behind a suggestion.
type VerificationSuggestionEvidence struct {
	FindingID    string `json:"finding_id"`
	RunID        string `json:"run_id"`
	SourceID     string `json:"source_id"`
	Fingerprint  string `json:"fingerprint"`
	DiscoveredAt string `json:"discovered_at"`
}

// VerificationAddressConfirmation confirms a suggested address for a target.
type VerificationAddressConfirmation struct {
	Address        string `json:"address"`
	ServerName     string `json:"server_name,omitempty"`
	TargetRevision string `json:"target_revision"`
}

const verificationSuggestionsNote = "Addresses where a discovery scan saw a certificate trstctl delivered to this target. " +
	"None is used until an operator confirms it; an address no scan saw is not suggested."

func (a *API) verificationSuggestionRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "GET", path: "/api/v1/connectors/targets/{id}/verification-suggestions", opID: "listVerificationAddressSuggestions", summary: "List addresses where discovery saw a certificate delivered to this target, with the findings, for an operator to confirm as its verification address", handler: a.listVerificationAddressSuggestions, pathParams: idPath, resSchema: "VerificationSuggestions", successCode: "200", perm: authz.ConnectorsRead},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/verification-address", opID: "confirmVerificationAddress", summary: "Confirm a suggested address as the target's verification address; later deployments verify the listener there", handler: a.confirmVerificationAddress, pathParams: idPath, reqSchema: "VerificationAddressConfirmation", resSchema: "DeploymentTarget", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
	}
}

func (a *API) listVerificationAddressSuggestions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	target, err := a.store.GetDeploymentTarget(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	out, err := a.verificationSuggestions(r.Context(), tenantID, target)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) verificationSuggestions(ctx context.Context, tenantID string, target store.DeploymentTarget) (VerificationSuggestions, error) {
	rows, err := a.store.VerificationAddressSuggestions(ctx, tenantID, target.Type, target.Name)
	if err != nil {
		return VerificationSuggestions{}, err
	}
	out := VerificationSuggestions{TargetID: target.ID, TargetRevision: target.RevisionID,
		Suggestions: []VerificationSuggestion{}, Note: verificationSuggestionsNote}
	out.VerifyAddress, out.VerifyServerName = targetVerificationConfig(target.Config)
	for _, row := range rows {
		s := VerificationSuggestion{Address: row.Address, LastSeen: row.LastSeen.UTC().Format(time.RFC3339)}
		for _, e := range row.Evidence {
			s.Evidence = append(s.Evidence, VerificationSuggestionEvidence{FindingID: e.FindingID, RunID: e.RunID,
				SourceID: e.SourceID, Fingerprint: e.Fingerprint, DiscoveredAt: e.DiscoveredAt.UTC().Format(time.RFC3339)})
		}
		out.Suggestions = append(out.Suggestions, s)
	}
	return out, nil
}

//trstctl:mutation
func (a *API) confirmVerificationAddress(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req VerificationAddressConfirmation
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Address, req.ServerName = strings.TrimSpace(req.Address), strings.TrimSpace(req.ServerName)
		if _, _, err := net.SplitHostPort(req.Address); err != nil || strings.TrimSpace(req.TargetRevision) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "address must be host:port and target_revision is required")
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if target.RevisionID != req.TargetRevision {
			return 0, nil, errStatus(http.StatusConflict, "the target changed since its suggestions were read; read them again")
		}
		suggestions, err := a.verificationSuggestions(ctx, tenantID, target)
		if err != nil {
			return 0, nil, err
		}
		suggested := false
		for _, s := range suggestions.Suggestions {
			suggested = suggested || s.Address == req.Address
		}
		if !suggested {
			return 0, nil, errStatus(http.StatusConflict,
				"no discovery finding saw a certificate delivered to this target at that address; set any other address by updating the target")
		}
		config, err := withVerificationAddress(target.Config, req.Address, req.ServerName)
		if err != nil {
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
		}
		updated, err := a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
			ID: target.ID, Name: target.Name, Type: target.Type, Config: config,
			Enabled: target.Enabled, EnabledSet: true,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toDeploymentTargetResponse(updated), nil
	})
}

// targetVerificationConfig reads the verification keys a target's config sets.
func targetVerificationConfig(raw json.RawMessage) (address, serverName string) {
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return "", ""
	}
	address, _ = fields["verify_address"].(string)
	serverName, _ = fields["verify_server_name"].(string)
	return strings.TrimSpace(address), strings.TrimSpace(serverName)
}

// withVerificationAddress sets the verification keys on a target's config and
// leaves every other key as it was.
func withVerificationAddress(raw json.RawMessage, address, serverName string) (json.RawMessage, error) {
	fields := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
	}
	fields["verify_address"] = address
	if serverName != "" {
		fields["verify_server_name"] = serverName
	}
	return json.Marshal(fields)
}
