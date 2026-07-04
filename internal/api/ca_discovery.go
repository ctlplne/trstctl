// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
)

type CADiscoveryInventory struct {
	Items   []CADiscoveryItem  `json:"items"`
	Summary CADiscoverySummary `json:"summary"`
}

type CADiscoveryItem struct {
	ID               string     `json:"id"`
	SourceID         string     `json:"source_id"`
	Source           string     `json:"source"`
	Scope            string     `json:"scope"`
	Type             string     `json:"type"`
	Name             string     `json:"name"`
	Status           string     `json:"status"`
	Managed          bool       `json:"managed"`
	ParentID         *string    `json:"parent_id,omitempty"`
	Serial           string     `json:"serial,omitempty"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	InventoryPath    string     `json:"inventory_path"`
	IssuancePath     string     `json:"issuance_path,omitempty"`
	ImportPath       string     `json:"import_path,omitempty"`
	DiscoveryMethods []string   `json:"discovery_methods"`
}

type CADiscoverySummary struct {
	PublicCount           int `json:"public_count"`
	PrivateCount          int `json:"private_count"`
	ExternalRegistryCount int `json:"external_registry_count"`
	AuthorityCount        int `json:"authority_count"`
}

func (a *API) listCADiscoveryInventory(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.externalCAs == nil && a.caHierarchy == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "CA discovery inventory is not enabled"))
		return
	}
	var out CADiscoveryInventory
	if a.externalCAs != nil {
		items, err := a.externalCAs.ListExternalCAs(r.Context(), tenantID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		for _, ca := range items {
			scope := caDiscoveryExternalScope(ca.Type, ca.Name)
			out.Items = append(out.Items, CADiscoveryItem{
				ID:               "external-ca/" + ca.ID,
				SourceID:         ca.ID,
				Source:           "external_ca_registry",
				Scope:            scope,
				Type:             ca.Type,
				Name:             ca.Name,
				Status:           ca.Status,
				InventoryPath:    "/api/v1/external-cas",
				IssuancePath:     "/api/v1/external-cas/" + url.PathEscape(ca.ID) + "/issue",
				DiscoveryMethods: []string{"configured-upstream-ca", "direct-provider-api"},
			})
			out.Summary.ExternalRegistryCount++
			out.addScope(scope)
		}
	}
	if a.caHierarchy != nil {
		authorities, err := a.caHierarchy.ListAuthorities(r.Context(), tenantID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		for _, authority := range authorities {
			item := CADiscoveryItem{
				ID:               "ca-authority/" + authority.ID,
				SourceID:         authority.ID,
				Source:           "ca_hierarchy",
				Scope:            "private",
				Type:             authority.Kind,
				Name:             authority.CommonName,
				Status:           authority.Status,
				Managed:          authority.SignerHandle != "",
				ParentID:         authority.ParentID,
				Serial:           authority.Serial,
				NotAfter:         authority.NotAfter,
				InventoryPath:    "/api/v1/ca/authorities",
				ImportPath:       caDiscoveryAuthorityImportPath(authority),
				DiscoveryMethods: []string{"public-chain-inspection", "ca-hierarchy-projection"},
			}
			if authority.SignerHandle != "" {
				item.IssuancePath = "/api/v1/ca/authorities/" + url.PathEscape(authority.ID) + "/issue"
				item.DiscoveryMethods = append(item.DiscoveryMethods, "signer-backed-authority")
			}
			out.Items = append(out.Items, item)
			out.Summary.AuthorityCount++
			out.addScope(item.Scope)
		}
	}
	sort.Slice(out.Items, func(i, j int) bool {
		if out.Items[i].Scope != out.Items[j].Scope {
			return out.Items[i].Scope < out.Items[j].Scope
		}
		if out.Items[i].Source != out.Items[j].Source {
			return out.Items[i].Source < out.Items[j].Source
		}
		return out.Items[i].ID < out.Items[j].ID
	})
	a.writeJSON(w, http.StatusOK, out)
}

func (i *CADiscoveryInventory) addScope(scope string) {
	switch scope {
	case "public":
		i.Summary.PublicCount++
	default:
		i.Summary.PrivateCount++
	}
}

func caDiscoveryExternalScope(typ, name string) string {
	s := strings.ToLower(strings.TrimSpace(typ + " " + name))
	switch {
	case strings.Contains(s, "letsencrypt"), strings.Contains(s, "lets-encrypt"), strings.Contains(s, "digicert"), strings.Contains(s, "sectigo"), strings.Contains(s, "public"):
		return "public"
	default:
		return "private"
	}
}

func caDiscoveryAuthorityImportPath(authority CAAuthority) string {
	if authority.SignerHandle == "" && authority.Kind == "root" {
		return "/api/v1/ca/authorities/offline-roots"
	}
	if authority.SignerHandle != "" {
		return "/api/v1/ca/authorities/imported"
	}
	return "/api/v1/ca/authorities"
}
