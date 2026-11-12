// SPDX-License-Identifier: BUSL-1.1

package secretstoretest

import (
	"net/http"
	"sort"
	"strings"
)

// DopplerSecret is one secret in a project's config.
type DopplerSecret struct {
	Project string
	Config  string
	Name    string
	Value   string
}

// NewDoppler serves Doppler's project, config, names and values reads (A173,
// restored in OD-14), written from Doppler's public API reference: the
// names-only endpoint carries no value; GET /v3/configs/config/secrets does.
func NewDoppler(token string, secrets []DopplerSecret) *Server {
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"messages":["Invalid Auth token"],"success":false}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"messages":["read-only stand-in"],"success":false}`, http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		project, config := q.Get("project"), q.Get("config")
		switch r.URL.Path {
		case "/v3/projects":
			seen := map[string]bool{}
			var projects []map[string]string
			for _, s := range secrets {
				if !seen[s.Project] {
					seen[s.Project] = true
					projects = append(projects, map[string]string{"id": s.Project, "slug": s.Project, "name": s.Project})
				}
			}
			sort.Slice(projects, func(i, j int) bool { return projects[i]["slug"] < projects[j]["slug"] })
			writeJSON(w, map[string]any{"page": 1, "projects": page(projects, r), "success": true})
		case "/v3/configs":
			seen := map[string]bool{}
			var configs []map[string]any
			for _, s := range secrets {
				if s.Project == project && !seen[s.Config] {
					seen[s.Config] = true
					configs = append(configs, map[string]any{"name": s.Config, "environment": strings.SplitN(s.Config, "_", 2)[0], "project": project, "locked": false})
				}
			}
			sort.Slice(configs, func(i, j int) bool { return configs[i]["name"].(string) < configs[j]["name"].(string) })
			writeJSON(w, map[string]any{"page": 1, "configs": page(configs, r), "success": true})
		case "/v3/configs/config/secrets/names":
			names := []string{}
			for _, s := range secrets {
				if s.Project == project && s.Config == config {
					names = append(names, s.Name)
				}
			}
			sort.Strings(names)
			writeJSON(w, map[string]any{"names": names, "success": true})
		case "/v3/configs/config/secrets":
			values := map[string]map[string]string{}
			for _, s := range secrets {
				if s.Project == project && s.Config == config {
					values[s.Name] = map[string]string{"raw": s.Value, "computed": s.Value, "note": ""}
				}
			}
			writeJSON(w, map[string]any{"secrets": values, "success": true})
		default:
			http.Error(w, `{"messages":["not found"],"success":false}`, http.StatusNotFound)
		}
	})
}
