// SPDX-License-Identifier: BUSL-1.1

package secretstoretest

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// OnePasswordItem is one item: Fields maps a field label to its value.
type OnePasswordItem struct {
	Vault    string
	Title    string
	Category string
	Fields   map[string]string
}

// NewOnePassword serves a 1Password Connect server's vault, item and item
// detail reads (A173, restored in OD-14), written from the Connect server's
// public API reference: GET /v1/vaults, GET /v1/vaults/{id}/items (no field
// values) and GET /v1/vaults/{id}/items/{id} (fields with values).
func NewOnePassword(token string, items []OnePasswordItem) *Server {
	vaultID := func(name string) string { return "vault-" + strings.ToLower(strings.ReplaceAll(name, " ", "-")) }
	itemID := func(i int) string { return "item-" + strconv.Itoa(i+1) }
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"status":401,"message":"Invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"status":405,"message":"read-only stand-in"}`, http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case len(parts) == 2 && parts[0] == "v1" && parts[1] == "vaults":
			seen := map[string]bool{}
			var vaults []map[string]string
			for _, it := range items {
				if !seen[it.Vault] {
					seen[it.Vault] = true
					vaults = append(vaults, map[string]string{"id": vaultID(it.Vault), "name": it.Vault})
				}
			}
			writeJSON(w, vaults)
		case len(parts) == 4 && parts[0] == "v1" && parts[1] == "vaults" && parts[3] == "items":
			list := []map[string]any{}
			for i, it := range items {
				if vaultID(it.Vault) == parts[2] {
					list = append(list, map[string]any{"id": itemID(i), "title": it.Title, "category": nonempty(it.Category, "API_CREDENTIAL"),
						"tags": []string{"a173"}, "version": 1, "updatedAt": "2026-10-30T00:00:00Z", "vault": map[string]string{"id": parts[2]}})
				}
			}
			writeJSON(w, list)
		case len(parts) == 5 && parts[0] == "v1" && parts[1] == "vaults" && parts[3] == "items":
			for i, it := range items {
				if vaultID(it.Vault) != parts[2] || itemID(i) != parts[4] {
					continue
				}
				labels := make([]string, 0, len(it.Fields))
				for label := range it.Fields {
					labels = append(labels, label)
				}
				sort.Strings(labels)
				fields := make([]map[string]string, 0, len(labels))
				for n, label := range labels {
					fields = append(fields, map[string]string{"id": "field-" + strconv.Itoa(n+1), "label": label, "type": "CONCEALED", "value": it.Fields[label]})
				}
				writeJSON(w, map[string]any{"id": itemID(i), "title": it.Title, "fields": fields})
				return
			}
			http.Error(w, `{"status":404,"message":"item not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"status":404,"message":"not found"}`, http.StatusNotFound)
		}
	})
}
