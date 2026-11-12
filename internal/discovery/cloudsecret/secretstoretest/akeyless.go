// SPDX-License-Identifier: BUSL-1.1

package secretstoretest

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// AkeylessItem is one static secret: Name is its full path ("/apps/db").
type AkeylessItem struct {
	Name, Value string
	Tags        []string
}

// AkeylessPageSize is how many items the stand-in returns per list-items
// page, so a test with more items exercises next_page.
const AkeylessPageSize = 2

// NewAkeyless serves the reads the akeyless provider makes, written from
// Akeyless's public API reference (no official image exists to check it
// against): API-key auth (POST /auth with access-type access_key), the item
// listing (POST /list-items with a static-secret type filter and a folder
// path, paged with next_page / pagination-token; no values) and the values
// of named items (POST /get-secret-value, a JSON object of name to value).
// Every call carries the token in its JSON body.
func NewAkeyless(accessID, accessKey string, items []AkeylessItem) *Server {
	const token = "t-akeyless-standin-token"
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/auth" {
			if body["access-type"] != "access_key" || body["access-id"] != accessID || body["access-key"] != accessKey {
				http.Error(w, `{"error":"failed to authenticate"}`, http.StatusUnauthorized)
				return
			}
			writeJSON(w, map[string]any{"token": token, "expiration": "2026-11-13T00:00:00Z"})
			return
		}
		if body["token"] != token {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		sorted := append([]AkeylessItem(nil), items...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
		switch r.URL.Path {
		case "/list-items":
			types, _ := body["type"].([]any)
			if len(types) != 1 || types[0] != "static-secret" {
				http.Error(w, `{"error":"the stand-in serves static secrets only"}`, http.StatusBadRequest)
				return
			}
			path, _ := body["path"].(string)
			var matched []map[string]any
			for i, it := range sorted {
				if path != "/" && path != "" && !strings.HasPrefix(it.Name, strings.TrimRight(path, "/")+"/") {
					continue
				}
				matched = append(matched, map[string]any{
					"item_name": it.Name, "item_type": "STATIC_SECRET", "item_id": 1000 + i, "item_tags": it.Tags,
					"last_version": 1, "creation_date": "2026-11-01T00:00:00Z", "modification_date": "2026-11-10T00:00:00Z",
				})
			}
			start, _ := strconv.Atoi(stringOr(body["pagination-token"], "0"))
			start = min(max(start, 0), len(matched))
			end := min(start+AkeylessPageSize, len(matched))
			next := ""
			if end < len(matched) {
				next = strconv.Itoa(end)
			}
			writeJSON(w, map[string]any{"items": matched[start:end], "folders": []string{}, "next_page": next})
		case "/get-secret-value":
			names, _ := body["names"].([]any)
			out := map[string]string{}
			for _, n := range names {
				for _, it := range sorted {
					if it.Name == n {
						out[it.Name] = it.Value
					}
				}
			}
			writeJSON(w, out)
		default:
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	})
}

func stringOr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}
