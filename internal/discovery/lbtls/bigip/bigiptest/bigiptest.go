// SPDX-License-Identifier: BUSL-1.1

// Package bigiptest is an in-process F5 BIG-IP iControl REST stand-in for the
// read-only GETs the listener TLS policy reader makes (X4): virtual servers
// with their profiles expanded, and client SSL profiles with their options.
// It requires basic authentication or an X-F5-Auth-Token, pages client SSL
// profiles one at a time with nextLink written against https://localhost as
// BIG-IP does, and counts any request that is not a GET so a test can prove
// nothing was changed.
package bigiptest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Profile is a seeded client SSL profile.
type Profile struct {
	FullPath, TMOptions, Ciphers string
}

// Virtual is a seeded virtual server and the profiles it uses (full paths;
// client SSL profiles are clientside, any other is all).
type Virtual struct {
	FullPath, Destination string
	Profiles              []string
}

// Server is the stand-in.
type Server struct {
	srv                   *httptest.Server
	user, password, token string
	mu                    sync.Mutex
	profiles              map[string]Profile
	virtuals              []Virtual
	gets, mutations       int
	refused               int
}

// New starts a stand-in that accepts the user and password, or the token.
func New(user, password, token string) *Server {
	s := &Server{user: user, password: password, token: token, profiles: map[string]Profile{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string          { return s.srv.URL }
func (s *Server) Client() *http.Client { return s.srv.Client() }
func (s *Server) Close()               { s.srv.Close() }

// Seed adds profiles and virtual servers.
func (s *Server) Seed(profiles []Profile, virtuals []Virtual) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range profiles {
		s.profiles[p.FullPath] = p
	}
	s.virtuals = append(s.virtuals, virtuals...)
}

// SetOptions changes a profile's options (an operator's change).
func (s *Server) SetOptions(fullPath, tmOptions string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.profiles[fullPath]
	p.TMOptions = tmOptions
	s.profiles[fullPath] = p
}

// Gets, Mutations and Refused count authenticated GETs, any other method, and
// requests refused for their credentials.
func (s *Server) Gets() int      { s.mu.Lock(); defer s.mu.Unlock(); return s.gets }
func (s *Server) Mutations() int { s.mu.Lock(); defer s.mu.Unlock(); return s.mutations }
func (s *Server) Refused() int   { s.mu.Lock(); defer s.mu.Unlock(); return s.refused }

func (s *Server) authorized(r *http.Request) bool {
	if s.token != "" && r.Header.Get("X-F5-Auth-Token") == s.token {
		return true
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.user+":"+s.password))
	return s.user != "" && r.Header.Get("Authorization") == want
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authorized(r) {
		s.refused++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"Authorization failed: no user authentication header or token detected"}`))
		return
	}
	if r.Method != http.MethodGet {
		s.mutations++
		http.Error(w, `{"code":405}`, http.StatusMethodNotAllowed)
		return
	}
	s.gets++
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/mgmt/tm/ltm/profile/client-ssl":
		paths := make([]string, 0, len(s.profiles))
		for p := range s.profiles {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		skip, _ := strconv.Atoi(r.URL.Query().Get("$skip"))
		out := map[string]any{"kind": "tm:ltm:profile:client-ssl:client-sslcollectionstate", "items": []any{}}
		if skip < len(paths) {
			p := s.profiles[paths[skip]]
			name := p.FullPath[strings.LastIndex(p.FullPath, "/")+1:]
			out["items"] = []any{map[string]any{"kind": "tm:ltm:profile:client-ssl:client-sslstate", "name": name,
				"fullPath": p.FullPath, "tmOptions": p.TMOptions, "ciphers": p.Ciphers, "cipherGroup": "none"}}
			if skip+1 < len(paths) {
				out["nextLink"] = "https://localhost/mgmt/tm/ltm/profile/client-ssl?$top=1&$skip=" + strconv.Itoa(skip+1) + "&ver=17.1.1"
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case "/mgmt/tm/ltm/virtual":
		expanded := r.URL.Query().Get("expandSubcollections") == "true"
		items := []any{}
		for _, v := range s.virtuals {
			ref := map[string]any{"link": "https://localhost/mgmt/tm/ltm/virtual/" + strings.ReplaceAll(v.FullPath, "/", "~") + "/profiles?ver=17.1.1", "isSubcollection": true}
			if expanded {
				var profiles []any
				for _, p := range v.Profiles {
					context := "all"
					if _, ok := s.profiles[p]; ok {
						context = "clientside"
					}
					profiles = append(profiles, map[string]any{"fullPath": p, "name": p[strings.LastIndex(p, "/")+1:], "context": context})
				}
				ref["items"] = profiles
			}
			items = append(items, map[string]any{"kind": "tm:ltm:virtual:virtualstate", "fullPath": v.FullPath,
				"name": v.FullPath[strings.LastIndex(v.FullPath, "/")+1:], "destination": v.Destination, "profilesReference": ref})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "tm:ltm:virtual:virtualcollectionstate", "items": items})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":404,"message":"Public URI path not registered"}`))
	}
}
