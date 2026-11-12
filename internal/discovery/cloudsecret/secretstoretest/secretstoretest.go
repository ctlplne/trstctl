// SPDX-License-Identifier: BUSL-1.1

// Package secretstoretest provides in-repository stand-ins, written from the
// providers' public API documentation, for the GitHub secret APIs (Actions,
// Dependabot and Codespaces) and the GitLab CI/CD variable APIs (project,
// group and instance) the A173 and OD-2 discovery providers read. Each answers only the read calls the providers
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

// GitHubLogin is the stand-in token owner's login, which GET /user returns.
const GitHubLogin = "standin-user"

// GitHubSecret is one secret. Scope is "repo", "env:<name>", "org" or "user"
// (the token owner's own, Codespaces only); Type is "actions" (the default
// when empty), "dependabot" or "codespaces".
type GitHubSecret struct {
	Scope      string
	Type       string
	Name       string
	Visibility string
}

// NewGitHub serves GitHub's secret listings for one owner/repo, one org and
// the token owner: Actions secrets for the repository, its environments and
// the org; Dependabot and Codespaces secrets for the repository and the org;
// and the token owner's Codespaces secrets with GET /user. GitHub never
// returns a secret's value, and neither does this.
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
		scope, typ := "", "actions"
		repoBase, orgBase := "/repos/"+owner+"/"+repo+"/", "/orgs/"+org+"/"
		switch path := r.URL.Path; {
		case path == "/user":
			writeJSON(w, map[string]any{"login": GitHubLogin, "type": "User"})
			return
		case path == "/user/codespaces/secrets":
			scope, typ = "user", "codespaces"
		case strings.HasPrefix(path, repoBase+"environments/") && strings.HasSuffix(path, "/secrets"):
			scope = "env:" + strings.TrimSuffix(strings.TrimPrefix(path, repoBase+"environments/"), "/secrets")
		case strings.HasPrefix(path, repoBase) && githubSecretPath(strings.TrimPrefix(path, repoBase)) != "":
			scope, typ = "repo", githubSecretPath(strings.TrimPrefix(path, repoBase))
		case org != "" && strings.HasPrefix(path, orgBase) && githubSecretPath(strings.TrimPrefix(path, orgBase)) != "":
			scope, typ = "org", githubSecretPath(strings.TrimPrefix(path, orgBase))
		default:
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		type row struct {
			Name                    string `json:"name"`
			CreatedAt               string `json:"created_at"`
			UpdatedAt               string `json:"updated_at"`
			Visibility              string `json:"visibility,omitempty"`
			SelectedRepositoriesURL string `json:"selected_repositories_url,omitempty"`
		}
		var rows []row
		for _, s := range secrets {
			if s.Scope == scope && nonempty(s.Type, "actions") == typ {
				out := row{Name: s.Name, CreatedAt: "2026-10-01T00:00:00Z", UpdatedAt: "2026-10-30T00:00:00Z", Visibility: s.Visibility}
				if s.Visibility == "selected" {
					out.SelectedRepositoriesURL = "https://" + r.Host + r.URL.Path + "/" + s.Name + "/repositories"
				}
				rows = append(rows, out)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		writeJSON(w, map[string]any{"total_count": len(rows), "secrets": page(rows, r)})
	})
}

// githubSecretPath names the store a "<type>/secrets" path under a
// repository or an org lists, or "" for any other path.
func githubSecretPath(rest string) string {
	for _, typ := range []string{"actions", "dependabot", "codespaces"} {
		if rest == typ+"/secrets" {
			return typ
		}
	}
	return ""
}

// GitLabVariable is one CI/CD variable. Scope is "project:<id-or-path>",
// "group:<id-or-path>" or "instance"; a hidden variable's value is never
// returned.
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

// NewGitLab serves GitLab's project, group and instance variable listings;
// the one token is an administrator's.
func NewGitLab(token string, vars []GitLabVariable) *Server {
	return NewGitLabWithAdmin(token, token, vars)
}

// NewGitLabWithAdmin is NewGitLab with a separate administrator token: GitLab
// lists instance variables (GET /api/v4/admin/ci/variables) to an
// administrator only and answers anyone else 403.
func NewGitLabWithAdmin(token, adminToken string, vars []GitLabVariable) *Server {
	return newServer(func(_ *Server, w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get("PRIVATE-TOKEN")
		if caller != token && caller != adminToken {
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
		if path == "/api/v4/admin/ci/variables" {
			if caller != adminToken {
				http.Error(w, `{"message":"403 Forbidden"}`, http.StatusForbidden)
				return
			}
			scope = "instance"
		}
		if scope == "" {
			http.Error(w, `{"message":"404 Not Found"}`, http.StatusNotFound)
			return
		}
		type row struct {
			Key              string  `json:"key"`
			Description      *string `json:"description,omitempty"`
			Value            *string `json:"value"`
			VariableType     string  `json:"variable_type"`
			Protected        bool    `json:"protected"`
			Masked           bool    `json:"masked"`
			Hidden           *bool   `json:"hidden,omitempty"`
			Raw              bool    `json:"raw"`
			EnvironmentScope *string `json:"environment_scope,omitempty"`
		}
		var rows []row
		for _, v := range vars {
			if v.Scope != scope {
				continue
			}
			value := v.Value
			out := row{Key: v.Key, Value: &value, VariableType: nonempty(v.VariableType, "env_var"), Protected: v.Protected, Masked: v.Masked || v.Hidden}
			if scope != "instance" {
				// Project and group variables carry an environment scope and
				// the hidden flag; instance variables have neither.
				hidden, envScope := v.Hidden, nonempty(v.EnvironmentScope, "*")
				out.Hidden, out.EnvironmentScope = &hidden, &envScope
				if v.Hidden {
					out.Value = nil
				}
			}
			rows = append(rows, out)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
		writeJSON(w, page(rows, r))
	})
}

func nonempty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
