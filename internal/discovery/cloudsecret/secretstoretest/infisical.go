// SPDX-License-Identifier: BUSL-1.1

package secretstoretest

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// InfisicalHiddenValue is what Infisical returns in place of a value when a
// secrets listing asks for none (viewSecretValue=false), as its official
// image v0.167.8 does.
const InfisicalHiddenValue = "<hidden-by-infisical>"

// InfisicalSecret is one secret in a project environment's folder.
type InfisicalSecret struct {
	Project, Environment, Path, Key, Value string
	Version                                int
	Tags                                   []string
}

// InfisicalProject is one project with its environment slugs.
type InfisicalProject struct {
	ID, Name     string
	Environments []string
}

// NewInfisical serves the reads the infisical provider makes, written from
// Infisical's public API reference and checked against its official image:
// Universal Auth sign-in (POST /api/v1/auth/universal-auth/login), the
// project listing and one project (GET /api/v1/projects[/{id}]), and an
// environment's secrets (GET /api/v4/secrets), recursive below secretPath,
// with values only when viewSecretValue is true.
func NewInfisical(clientID, clientSecret string, projects []InfisicalProject, secrets []InfisicalSecret) *Server {
	const accessToken = "infisical-standin-access-token"
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/universal-auth/login" {
			var body struct{ ClientID, ClientSecret string }
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.ClientID != clientID || body.ClientSecret != clientSecret {
				http.Error(w, `{"statusCode":401,"message":"Invalid credentials"}`, http.StatusUnauthorized)
				return
			}
			writeJSON(w, map[string]any{"accessToken": accessToken, "expiresIn": 7200, "accessTokenMaxTTL": 7200, "tokenType": "Bearer"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			http.Error(w, `{"statusCode":401,"message":"Token missing"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"message":"read-only stand-in"}`, http.StatusMethodNotAllowed)
			return
		}
		view := func(p InfisicalProject) map[string]any {
			envs := make([]map[string]string, 0, len(p.Environments))
			for _, e := range p.Environments {
				envs = append(envs, map[string]string{"name": e, "slug": e, "id": p.ID + "-" + e})
			}
			return map[string]any{"id": p.ID, "_id": p.ID, "name": p.Name, "slug": strings.ToLower(p.Name), "type": "secret-manager", "environments": envs}
		}
		q := r.URL.Query()
		switch path := r.URL.Path; {
		case path == "/api/v1/projects":
			limit, _ := strconv.Atoi(q.Get("limit"))
			offset, _ := strconv.Atoi(q.Get("offset"))
			if limit <= 0 {
				limit = len(projects)
			}
			var out []map[string]any
			for i, p := range projects {
				if i >= offset && len(out) < limit {
					out = append(out, view(p))
				}
			}
			writeJSON(w, map[string]any{"projects": out})
		case strings.HasPrefix(path, "/api/v1/projects/"):
			for _, p := range projects {
				if p.ID == strings.TrimPrefix(path, "/api/v1/projects/") {
					writeJSON(w, map[string]any{"project": view(p)})
					return
				}
			}
			http.Error(w, `{"statusCode":404,"message":"Project not found"}`, http.StatusNotFound)
		case path == "/api/v4/secrets":
			base := q.Get("secretPath")
			if base == "" {
				base = "/"
			}
			recursive := q.Get("recursive") == "true"
			withValues := q.Get("viewSecretValue") != "false"
			var out []map[string]any
			for _, s := range secrets {
				inFolder := s.Path == base || (recursive && (base == "/" || strings.HasPrefix(s.Path, base+"/")))
				if s.Project != q.Get("projectId") || s.Environment != q.Get("environment") || !inFolder {
					continue
				}
				value := InfisicalHiddenValue
				if withValues {
					value = s.Value
				}
				tags := make([]map[string]string, 0, len(s.Tags))
				for _, t := range s.Tags {
					tags = append(tags, map[string]string{"id": t, "slug": t, "name": t, "color": "#000000"})
				}
				out = append(out, map[string]any{
					"id": s.Project + s.Environment + s.Path + s.Key, "secretKey": s.Key, "secretValue": value,
					"secretValueHidden": !withValues, "version": max(s.Version, 1), "type": "shared",
					"environment": s.Environment, "secretPath": s.Path, "tags": tags,
					"createdAt": "2026-11-01T00:00:00.000Z", "updatedAt": "2026-11-10T00:00:00.000Z",
				})
			}
			sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
			writeJSON(w, map[string]any{"secrets": out, "imports": []any{}})
		default:
			http.Error(w, `{"statusCode":404,"message":"Not Found"}`, http.StatusNotFound)
		}
	})
}
