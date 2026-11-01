// SPDX-License-Identifier: BUSL-1.1

// Package oauthrevoketest is an in-process stand-in for the three provider
// admin APIs oauthrevoke calls (A170, A171): Okta's user client grants and
// tokens and app lifecycle, Microsoft Graph's delegated permission grants and
// service principals, and Google Workspace's user tokens. Each API checks its
// own authorization scheme and token, and the stand-in keeps the state a test
// asserts on afterwards.
package oauthrevoketest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
)

// GraphGrant is one delegated permission grant.
type GraphGrant struct {
	ID, ClientID, PrincipalID string
}

// Server is the stand-in.
type Server struct {
	srv   *httptest.Server
	token string
	mu    sync.Mutex
	// okta: user → client → live grants / tokens; app → active
	oktaGrants map[string]map[string]int
	oktaTokens map[string]map[string]int
	oktaApps   map[string]bool
	// graph: grants; service principal → accountEnabled
	graphGrants []GraphGrant
	graphSPs    map[string]bool
	// google: user → client → token present
	googleTokens map[string]map[string]bool
	unauthorized int
}

// New starts a stand-in that accepts the given token on every API.
func New(token string) *Server {
	s := &Server{token: token, oktaGrants: map[string]map[string]int{}, oktaTokens: map[string]map[string]int{},
		oktaApps: map[string]bool{}, graphSPs: map[string]bool{}, googleTokens: map[string]map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string          { return s.srv.URL }
func (s *Server) Client() *http.Client { return s.srv.Client() }
func (s *Server) Close()               { s.srv.Close() }

// SeedOkta gives user grants and tokens to client, and registers app as active.
func (s *Server) SeedOkta(user, client string, grants, tokens int, app string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oktaGrants[user] == nil {
		s.oktaGrants[user], s.oktaTokens[user] = map[string]int{}, map[string]int{}
	}
	s.oktaGrants[user][client] += grants
	s.oktaTokens[user][client] += tokens
	if app != "" {
		s.oktaApps[app] = true
	}
}

// SeedGraph adds delegated grants and registers the service principal enabled.
func (s *Server) SeedGraph(sp string, grants ...GraphGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.graphGrants = append(s.graphGrants, grants...)
	s.graphSPs[sp] = true
}

// SeedGoogle gives user a token for client.
func (s *Server) SeedGoogle(user, client string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.googleTokens[user] == nil {
		s.googleTokens[user] = map[string]bool{}
	}
	s.googleTokens[user][client] = true
}

// OktaGrants reports the user's live grants and tokens for a client.
func (s *Server) OktaGrants(user, client string) (grants, tokens int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.oktaGrants[user][client], s.oktaTokens[user][client]
}

// OktaAppActive reports whether an app is active.
func (s *Server) OktaAppActive(app string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.oktaApps[app]
}

// GraphGrants counts the delegated grants left from principal to client.
func (s *Server) GraphGrants(client, principal string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, g := range s.graphGrants {
		if g.ClientID == client && g.PrincipalID == principal {
			n++
		}
	}
	return n
}

// GraphSPEnabled reports a service principal's accountEnabled.
func (s *Server) GraphSPEnabled(sp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.graphSPs[sp]
}

// GoogleToken reports whether the user still holds a token for client.
func (s *Server) GoogleToken(user, client string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.googleTokens[user][client]
}

// Unauthorized counts requests refused for a wrong scheme or token.
func (s *Server) Unauthorized() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unauthorized
}

func (s *Server) authorized(r *http.Request, scheme string) bool {
	if r.Header.Get("Authorization") == scheme+s.token {
		return true
	}
	s.mu.Lock()
	s.unauthorized++
	s.mu.Unlock()
	return false
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	switch {
	case strings.HasPrefix(path, "/api/v1/"):
		if !s.authorized(r, "SSWS ") {
			http.Error(w, `{"errorCode":"E0000011"}`, http.StatusUnauthorized)
			return
		}
		s.okta(w, r, strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/"))
	case strings.HasPrefix(path, "/v1.0/"):
		if !s.authorized(r, "Bearer ") {
			http.Error(w, `{"error":{"code":"InvalidAuthenticationToken"}}`, http.StatusUnauthorized)
			return
		}
		s.graph(w, r, strings.TrimPrefix(path, "/v1.0/"))
	case strings.HasPrefix(path, "/admin/directory/v1/users/"):
		if !s.authorized(r, "Bearer ") {
			http.Error(w, `{"error":{"code":401}}`, http.StatusUnauthorized)
			return
		}
		parts := strings.Split(strings.TrimPrefix(path, "/admin/directory/v1/users/"), "/")
		if r.Method != http.MethodDelete || len(parts) != 3 || parts[1] != "tokens" {
			http.NotFound(w, r)
			return
		}
		user, client := unescape(parts[0]), unescape(parts[2])
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.googleTokens[user][client] {
			http.NotFound(w, r)
			return
		}
		delete(s.googleTokens[user], client)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) okta(w http.ResponseWriter, r *http.Request, parts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodDelete && len(parts) == 5 && parts[0] == "users" && parts[2] == "clients":
		user, client := unescape(parts[1]), unescape(parts[3])
		store := s.oktaGrants
		if parts[4] == "tokens" {
			store = s.oktaTokens
		} else if parts[4] != "grants" {
			http.NotFound(w, r)
			return
		}
		if store[user][client] == 0 {
			http.NotFound(w, r)
			return
		}
		store[user][client] = 0
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[0] == "apps" && parts[2] == "lifecycle" && parts[3] == "deactivate":
		app := unescape(parts[1])
		if _, ok := s.oktaApps[app]; !ok {
			http.NotFound(w, r)
			return
		}
		s.oktaApps[app] = false
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request, rest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && rest == "oauth2PermissionGrants":
		client, principal := parseGraphFilter(r.URL.Query().Get("$filter"))
		out := []map[string]string{}
		for _, g := range s.graphGrants {
			if g.ClientID == client && g.PrincipalID == principal {
				out = append(out, map[string]string{"id": g.ID, "clientId": g.ClientID, "principalId": g.PrincipalID})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": out})
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "oauth2PermissionGrants/"):
		id := unescape(strings.TrimPrefix(rest, "oauth2PermissionGrants/"))
		for i, g := range s.graphGrants {
			if g.ID == id {
				s.graphGrants = append(s.graphGrants[:i], s.graphGrants[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.NotFound(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(rest, "servicePrincipals/"):
		sp := unescape(strings.TrimPrefix(rest, "servicePrincipals/"))
		if _, ok := s.graphSPs[sp]; !ok {
			http.NotFound(w, r)
			return
		}
		var body struct {
			AccountEnabled *bool `json:"accountEnabled"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if json.Unmarshal(raw, &body) != nil || body.AccountEnabled == nil {
			http.Error(w, `{"error":{"code":"BadRequest"}}`, http.StatusBadRequest)
			return
		}
		s.graphSPs[sp] = *body.AccountEnabled
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// parseGraphFilter reads "clientId eq 'X' and principalId eq 'Y'".
func parseGraphFilter(filter string) (client, principal string) {
	for _, clause := range strings.Split(filter, " and ") {
		field, value, ok := strings.Cut(strings.TrimSpace(clause), " eq ")
		if !ok {
			continue
		}
		value = strings.ReplaceAll(strings.Trim(value, "'"), "''", "'")
		switch field {
		case "clientId":
			client = value
		case "principalId":
			principal = value
		}
	}
	return client, principal
}

func unescape(part string) string {
	if v, err := url.PathUnescape(part); err == nil {
		return v
	}
	return part
}
