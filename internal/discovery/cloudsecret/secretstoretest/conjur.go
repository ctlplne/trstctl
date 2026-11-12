// SPDX-License-Identifier: BUSL-1.1

package secretstoretest

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ConjurVariable is one variable under the account; Value "" means the
// variable holds no version yet, and Visible false hides it from the role
// that signs in (no read privilege).
type ConjurVariable struct {
	ID          string // the path, e.g. "apps/db/password"
	Value       string
	Annotations map[string]string
	Visible     bool
}

// NewConjur serves the reads the conjur provider makes, written from
// Conjur's public API and server source and checked against the official
// cyberark/conjur 1.27.0 image: API-key authentication (POST
// /authn/{account}/{login}/authenticate, base64 token with Accept-Encoding:
// base64), the variable listing (GET /resources/{account}?kind=variable with
// limit, offset and search; no values), and one variable's value (GET
// /secrets/{account}/variable/{id}; 404 for an empty or unreadable one).
func NewConjur(account, login, apiKey string, vars []ConjurVariable) *Server {
	const token = `{"protected":"standin","payload":"standin","signature":"standin"}` // #nosec G101 -- a stand-in's fixed fake access token, not a credential (CWE-798)
	encoded := base64.StdEncoding.EncodeToString([]byte(token))
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		authn := "/authn/" + account + "/" + url.PathEscape(login) + "/authenticate"
		if r.Method == http.MethodPost && r.URL.EscapedPath() == authn {
			body, _ := io.ReadAll(r.Body)
			if string(body) != apiKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "base64") {
				w.Header().Set("Content-Encoding", "base64")
				_, _ = w.Write([]byte(encoded))
				return
			}
			_, _ = w.Write([]byte(token))
			return
		}
		if r.Header.Get("Authorization") != `Token token="`+encoded+`"` {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"read-only stand-in"}`, http.StatusMethodNotAllowed)
			return
		}
		find := func(id string) *ConjurVariable {
			for i := range vars {
				if vars[i].ID == id && vars[i].Visible {
					return &vars[i]
				}
			}
			return nil
		}
		switch path := r.URL.Path; {
		case path == "/resources/"+account && r.URL.Query().Get("kind") == "variable":
			q := r.URL.Query()
			limit, _ := strconv.Atoi(q.Get("limit"))
			offset, _ := strconv.Atoi(q.Get("offset"))
			var rows []map[string]any
			for _, v := range vars {
				if !v.Visible || (q.Get("search") != "" && !strings.Contains(v.ID, q.Get("search"))) {
					continue
				}
				annotations := []map[string]string{}
				for name, value := range v.Annotations {
					annotations = append(annotations, map[string]string{"name": name, "value": value, "policy": account + ":policy:root"})
				}
				sort.Slice(annotations, func(i, j int) bool { return annotations[i]["name"] < annotations[j]["name"] })
				versions := []map[string]any{}
				if v.Value != "" {
					versions = append(versions, map[string]any{"version": 1, "expires_at": nil})
				}
				rows = append(rows, map[string]any{
					"id": account + ":variable:" + v.ID, "owner": account + ":policy:apps", "policy": account + ":policy:root",
					"created_at": "2026-11-12T00:00:00.000+00:00", "permissions": []any{}, "annotations": annotations, "secrets": versions,
				})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i]["id"].(string) < rows[j]["id"].(string) })
			if offset > len(rows) {
				offset = len(rows)
			}
			end := len(rows)
			if limit > 0 && offset+limit < end {
				end = offset + limit
			}
			writeJSON(w, rows[offset:end])
		case strings.HasPrefix(path, "/secrets/"+account+"/variable/"):
			v := find(strings.TrimPrefix(path, "/secrets/"+account+"/variable/"))
			if v == nil || v.Value == "" {
				http.Error(w, `{"error":{"code":"not_found","message":"Variable is empty or not found."}}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(v.Value))
		default:
			http.Error(w, `{"error":{"code":"not_found"}}`, http.StatusNotFound)
		}
	})
}
