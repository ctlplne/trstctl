// SPDX-License-Identifier: BUSL-1.1

package secretstoretest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto/bwsm"
)

// BitwardenSecret is one Secrets Manager secret in the organization;
// Project is the project's name ("" for none).
type BitwardenSecret struct {
	ID, Key, Value, Project string
}

// NewBitwardenSecretsManager serves the reads the bitwarden-secrets-manager
// provider makes, written from Bitwarden's open-source SDK and server (no
// self-contained image serves Secrets Manager to check it against): the
// identity service's client-credentials sign-in (POST /connect/token, form
// encoded, scope api.secrets) returning a bearer JWT with the organization
// claim and the encrypted payload that carries the organization key under the
// access token's key; the organization's secrets (GET
// /organizations/{id}/secrets, names and project names encrypted, no values);
// and values by ID (POST /secrets/get-by-ids). Names, project names and
// values are real type-2 encrypted strings under orgKey; both services answer
// on this one server. accessToken is the machine account's token
// ("0.<id>.<secret>:<seed>").
func NewBitwardenSecretsManager(accessToken string, orgID string, orgKey []byte, secrets []BitwardenSecret) *Server {
	token, err := bwsm.ParseAccessToken([]byte(accessToken))
	if err != nil {
		panic("secretstoretest: bad Bitwarden access token: " + err.Error())
	}
	clientSecret := string(token.ClientSecret.Bytes())
	tokenKey, err := token.TokenKey()
	if err != nil {
		panic(err)
	}
	key, err := bwsm.KeyFromBytes(orgKey)
	if err != nil {
		panic(err)
	}
	seal := func(k *bwsm.Key, plain string) string {
		sealed, err := k.Encrypt([]byte(plain))
		if err != nil {
			panic(err)
		}
		return sealed
	}
	payload := seal(tokenKey, `{"encryptionKey":"`+base64.StdEncoding.EncodeToString(orgKey)+`"}`)
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"organization":"` + orgID + `","client_id":"` + token.ID + `","scope":["api.secrets"]}`))
	bearer := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + claims + ".c3RhbmRpbg"
	projectIDs := map[string]string{}
	for _, s := range secrets {
		if s.Project != "" && projectIDs[s.Project] == "" {
			projectIDs[s.Project] = fmt.Sprintf("f0000000-0000-4000-8000-%012x", len(projectIDs)+1)
		}
	}
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/connect/token" {
			raw, _ := io.ReadAll(r.Body)
			form, err := url.ParseQuery(string(raw))
			if err != nil || form.Get("grant_type") != "client_credentials" || form.Get("scope") != "api.secrets" ||
				form.Get("client_id") != token.ID || form.Get("client_secret") != clientSecret {
				http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{
				"access_token": bearer, "expires_in": 3600, "token_type": "Bearer", "scope": "api.secrets",
				"encrypted_payload": payload,
			})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+bearer {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		projectRef := func(name string) []map[string]string {
			if name == "" {
				return []map[string]string{}
			}
			return []map[string]string{{"id": projectIDs[name], "name": seal(key, name)}}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/organizations/"+orgID+"/secrets":
			var rows []map[string]any
			for _, s := range secrets {
				rows = append(rows, map[string]any{
					"id": s.ID, "organizationId": orgID, "key": seal(key, s.Key), "creationDate": "2026-11-01T00:00:00Z",
					"revisionDate": "2026-11-10T00:00:00Z", "projects": projectRef(s.Project), "read": true, "write": false,
				})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i]["id"].(string) < rows[j]["id"].(string) })
			var projects []map[string]string
			for name, id := range projectIDs {
				projects = append(projects, map[string]string{"id": id, "name": seal(key, name)})
			}
			sort.Slice(projects, func(i, j int) bool { return projects[i]["id"] < projects[j]["id"] })
			writeJSON(w, map[string]any{"secrets": rows, "projects": projects})
		case r.Method == http.MethodPost && r.URL.Path == "/secrets/get-by-ids":
			var body struct {
				IDs []string `json:"ids"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
				return
			}
			var data []map[string]any
			for _, id := range body.IDs {
				found := false
				for _, s := range secrets {
					if s.ID == id {
						found = true
						data = append(data, map[string]any{
							"id": s.ID, "organizationId": orgID, "key": seal(key, s.Key), "value": seal(key, s.Value),
							"note": seal(key, ""), "creationDate": "2026-11-01T00:00:00Z", "revisionDate": "2026-11-10T00:00:00Z",
							"projects": projectRef(s.Project), "object": "baseSecret",
						})
					}
				}
				if !found {
					http.Error(w, `{"message":"Resource not found."}`, http.StatusNotFound)
					return
				}
			}
			writeJSON(w, map[string]any{"data": data, "continuationToken": nil, "object": "list"})
		default:
			http.Error(w, `{"message":"`+strings.ReplaceAll(r.URL.Path, `"`, "")+` not found"}`, http.StatusNotFound)
		}
	})
}
