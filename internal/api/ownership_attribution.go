package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

var ownershipAttributionCoverage = []string{
	"human_owner",
	"team_owner",
	"vendor_owner",
	"workload_owner",
	"service_owner",
	"orphaned",
}

type ownershipAttributionResponse struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	Items       []ownershipAttributionItem `json:"items"`
	Summary     map[string]int             `json:"summary"`
	Coverage    []string                   `json:"coverage"`
}

type ownershipAttributionItem struct {
	ID                  string                     `json:"id"`
	TenantID            string                     `json:"tenant_id"`
	Kind                string                     `json:"kind"`
	Source              string                     `json:"source"`
	DisplayName         string                     `json:"display_name"`
	Ref                 string                     `json:"ref,omitempty"`
	Owner               *ownershipAttributionOwner `json:"owner,omitempty"`
	AttributionStatus   string                     `json:"attribution_status"`
	AttributionSource   string                     `json:"attribution_source"`
	AttributionEvidence []string                   `json:"attribution_evidence"`
	CreatedAt           time.Time                  `json:"created_at"`
	DiscoveredAt        *time.Time                 `json:"discovered_at,omitempty"`
}

type ownershipAttributionOwner struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
}

type ownershipOwnerIndex struct {
	byID    map[string]store.Owner
	byAlias map[string]store.Owner
}

func (a *API) listOwnershipAttribution(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.ownershipAttribution(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) ownershipAttribution(ctx context.Context, tenantID string) (ownershipAttributionResponse, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return ownershipAttributionResponse{}, err
	}
	owners, err := a.store.ListOwners(ctx, tenantID)
	if err != nil {
		return ownershipAttributionResponse{}, err
	}
	idx := newOwnershipOwnerIndex(owners)
	out := ownershipAttributionResponse{
		GeneratedAt: inventory.GeneratedAt,
		Summary:     map[string]int{},
		Coverage:    append([]string(nil), ownershipAttributionCoverage...),
	}
	for _, inv := range inventory.Items {
		owner, source, evidence := resolveOwnershipAttribution(inv, idx)
		status := "orphaned"
		out.Summary["total"]++
		if owner != nil {
			status = "attributed"
			out.Summary["attributed"]++
			out.Summary[owner.Kind]++
			if owner.Kind == string(store.OwnerUser) {
				out.Summary["human_owner"]++
			}
		} else {
			out.Summary["orphaned"]++
		}
		out.Items = append(out.Items, ownershipAttributionItem{
			ID:                  inv.ID,
			TenantID:            inv.TenantID,
			Kind:                inv.Kind,
			Source:              inv.Source,
			DisplayName:         inv.DisplayName,
			Ref:                 inv.Ref,
			Owner:               owner,
			AttributionStatus:   status,
			AttributionSource:   source,
			AttributionEvidence: evidence,
			CreatedAt:           inv.CreatedAt,
			DiscoveredAt:        inv.DiscoveredAt,
		})
	}
	sort.Slice(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if a.AttributionStatus != b.AttributionStatus {
			return a.AttributionStatus < b.AttributionStatus
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		return a.ID < b.ID
	})
	return out, nil
}

func newOwnershipOwnerIndex(owners []store.Owner) ownershipOwnerIndex {
	idx := ownershipOwnerIndex{
		byID:    map[string]store.Owner{},
		byAlias: map[string]store.Owner{},
	}
	for _, owner := range owners {
		idx.byID[owner.ID] = owner
		for _, alias := range []string{owner.ID, owner.Name, owner.Email} {
			if key := ownershipAlias(alias); key != "" {
				idx.byAlias[key] = owner
			}
		}
	}
	return idx
}

func resolveOwnershipAttribution(item nhiInventoryItem, idx ownershipOwnerIndex) (*ownershipAttributionOwner, string, []string) {
	if ownerID := strings.TrimSpace(item.OwnerID); ownerID != "" {
		if owner, ok := idx.byID[ownerID]; ok {
			return toOwnershipAttributionOwner(owner), "owner_id", []string{"owner_id:" + ownerID}
		}
		return nil, "unresolved_owner_id", []string{"owner_id:" + ownerID}
	}
	meta := decodeNHIInventoryMetadata(item.Metadata)
	if ownerID := metadataString(meta, "owner_id"); ownerID != "" {
		if owner, ok := idx.byID[ownerID]; ok {
			return toOwnershipAttributionOwner(owner), "metadata_owner_id", []string{"metadata.owner_id:" + ownerID}
		}
		return nil, "unresolved_metadata_owner_id", []string{"metadata.owner_id:" + ownerID}
	}
	for _, field := range []string{"owner", "owner_name", "human_owner", "team", "team_name"} {
		value := metadataString(meta, field)
		if owner, ok := idx.byAlias[ownershipAlias(value)]; ok {
			return toOwnershipAttributionOwner(owner), "metadata_owner", []string{"metadata." + field + ":" + value}
		}
	}
	for _, field := range []string{"vendor", "vendor_name"} {
		value := metadataString(meta, field)
		if owner, ok := idx.byAlias[ownershipAlias(value)]; ok {
			return toOwnershipAttributionOwner(owner), "metadata_vendor", []string{"metadata." + field + ":" + value}
		}
	}
	return nil, "unattributed", nil
}

func toOwnershipAttributionOwner(owner store.Owner) *ownershipAttributionOwner {
	return &ownershipAttributionOwner{
		ID:       owner.ID,
		TenantID: owner.TenantID,
		Kind:     string(owner.Kind),
		Name:     owner.Name,
		Email:    owner.Email,
	}
}

func ownershipAlias(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
