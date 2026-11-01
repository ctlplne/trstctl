// SPDX-License-Identifier: BUSL-1.1

// Package secretstoretest provides in-repository stand-ins for the GitHub
// Actions, GitLab CI/CD, 1Password Connect and Doppler secret APIs the A173
// discovery providers read. Each answers only the read calls the providers
// make, enforces its provider's authentication header, paginates like the
// provider, and records every request so a test can prove which calls a run
// made (a metadata-only run must never reach a value-returning endpoint).
package secretstoretest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Server is one stand-in provider.
type Server struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

// URL is the stand-in's base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client is an HTTP client that reaches the stand-in (the providers' default
// client refuses loopback addresses).
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close stops the stand-in.
func (s *Server) Close() { s.srv.Close() }

// Seen returns every request as "METHOD path?query", in order.
func (s *Server) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// Reset forgets the recorded requests.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = nil
}

func (s *Server) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := r.Method + " " + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		line += "?" + r.URL.RawQuery
	}
	s.seen = append(s.seen, line)
}

func newServer(handler func(*Server, http.ResponseWriter, *http.Request)) *Server {
	s := &Server{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.Header().Set("Content-Type", "application/json")
		handler(s, w, r)
	}))
	return s
}

func page[T any](items []T, r *http.Request) []T {
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	n, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if per <= 0 {
		per = 30
	}
	if n <= 0 {
		n = 1
	}
	start := (n - 1) * per
	if start >= len(items) {
		return []T{}
	}
	end := start + per
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func writeJSON(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

// GitHubSecret is one Actions secret: its scope is "repo", "env:<name>" or "org".
type GitHubSecret struct {
	Scope      string
	Name       string
	Visibility string
}

// NewGitHub serves GitHub's Actions secret listings for one owner/repo and
// one org. GitHub never returns a secret's value, and neither does this.
func NewGitHub(token, owner, repo, org string, secrets []GitHubSecret) *Server {
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"message":"read-only stand-in"}`, http.StatusMethodNotAllowed)
			return
		}
		scope := ""
		switch path := r.URL.Path; {
		case path == "/repos/"+owner+"/"+repo+"/actions/secrets":
			scope = "repo"
		case strings.HasPrefix(path, "/repos/"+owner+"/"+repo+"/environments/") && strings.HasSuffix(path, "/secrets"):
			scope = "env:" + strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"+owner+"/"+repo+"/environments/"), "/secrets")
		case path == "/orgs/"+org+"/actions/secrets":
			scope = "org"
		default:
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		type row struct {
			Name       string `json:"name"`
			CreatedAt  string `json:"created_at"`
			UpdatedAt  string `json:"updated_at"`
			Visibility string `json:"visibility,omitempty"`
		}
		var rows []row
		for _, s := range secrets {
			if s.Scope == scope {
				rows = append(rows, row{Name: s.Name, CreatedAt: "2026-10-01T00:00:00Z", UpdatedAt: "2026-10-30T00:00:00Z", Visibility: s.Visibility})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		writeJSON(w, map[string]any{"total_count": len(rows), "secrets": page(rows, r)})
	})
}

// GitLabVariable is one CI/CD variable. Scope is "project:<id-or-path>" or
// "group:<id-or-path>"; a hidden variable's value is never returned.
type GitLabVariable struct {
	Scope            string
	Key              string
	Value            string
	VariableType     string
	Protected        bool
	Masked           bool
	Hidden           bool
	EnvironmentScope string
}

// NewGitLab serves GitLab's project and group variable listings.
func NewGitLab(token string, vars []GitLabVariable) *Server {
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != token {
			http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, `{"message":"read-only stand-in"}`, http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.EscapedPath()
		var scope string
		for _, kind := range []string{"projects", "groups"} {
			prefix := "/api/v4/" + kind + "/"
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "/variables") {
				id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/variables")
				id = strings.ReplaceAll(id, "%2F", "/")
				scope = strings.TrimSuffix(kind, "s") + ":" + id
			}
		}
		if scope == "" {
			http.Error(w, `{"message":"404 Not Found"}`, http.StatusNotFound)
			return
		}
		type row struct {
			Key              string  `json:"key"`
			Value            *string `json:"value"`
			VariableType     string  `json:"variable_type"`
			Protected        bool    `json:"protected"`
			Masked           bool    `json:"masked"`
			Hidden           bool    `json:"hidden"`
			Raw              bool    `json:"raw"`
			EnvironmentScope string  `json:"environment_scope"`
		}
		var rows []row
		for _, v := range vars {
			if v.Scope != scope {
				continue
			}
			value := v.Value
			out := row{Key: v.Key, Value: &value, VariableType: nonempty(v.VariableType, "env_var"), Protected: v.Protected,
				Masked: v.Masked || v.Hidden, Hidden: v.Hidden, EnvironmentScope: nonempty(v.EnvironmentScope, "*")}
			if v.Hidden {
				out.Value = nil
			}
			rows = append(rows, out)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
		writeJSON(w, page(rows, r))
	})
}

// OnePasswordItem is one item: Fields maps a field label to its value.
type OnePasswordItem struct {
	Vault    string
	Title    string
	Category string
	Fields   map[string]string
}

// NewOnePassword serves a 1Password Connect server's vault, item and item
// detail reads.
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

// DopplerSecret is one secret in a project's config.
type DopplerSecret struct {
	Project string
	Config  string
	Name    string
	Value   string
}

// NewDoppler serves Doppler's project, config, names and values reads.
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

func nonempty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
