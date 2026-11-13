// SPDX-License-Identifier: BUSL-1.1

// Package docsystest holds documentation-system stand-ins for tests, each
// written from its vendor's public API description: credentials checked on
// every request, the documented request shapes, and the records a real
// system would keep, so a test can assert which organization holds what.
package docsystest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ITGlueAsset is one flexible asset.
type ITGlueAsset struct {
	ID     int64
	OrgID  int64
	TypeID int64
	Traits map[string]any
}

// ITGlue is an IT Glue API stand-in written from the public API reference:
// the x-api-key header (403 otherwise), JSON:API bodies of type
// application/vnd.api+json, organizations, and flexible assets of known
// types — listed with filter[flexible-asset-type-id] (required),
// filter[organization-id] and filter[name], created with POST (422 for an
// unknown organization, type or trait, or a missing title) and replaced with
// PATCH, which clears every trait it does not send.
type ITGlue struct {
	srv *httptest.Server

	mu        sync.Mutex
	key       string
	orgs      map[int64]bool
	types     map[int64]map[string]bool
	titles    map[int64]string
	assets    map[int64]*ITGlueAsset
	nextID    int64
	requests  int
	writes    int
	refused   int
	failWrite int
}

// NewITGlue starts a stand-in for one API key.
func NewITGlue(key string) *ITGlue {
	s := &ITGlue{key: key, orgs: map[int64]bool{}, types: map[int64]map[string]bool{}, titles: map[int64]string{}, assets: map[int64]*ITGlueAsset{},
		nextID: 9000}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *ITGlue) Close() { s.srv.Close() }

// URL is the API host.
func (s *ITGlue) URL() string { return s.srv.URL }

// AddOrganization records an organization.
func (s *ITGlue) AddOrganization(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[id] = true
}

// AddType records a flexible-asset type with its fields' name-keys; the
// first is the field used for the asset's name.
func (s *ITGlue) AddType(id int64, nameKeys ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.types[id] = map[string]bool{}
	for _, k := range nameKeys {
		s.types[id][k] = true
	}
	if len(nameKeys) > 0 {
		s.titles[id] = nameKeys[0]
	}
}

// DeleteAsset deletes a flexible asset, as an operator would in IT Glue.
func (s *ITGlue) DeleteAsset(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assets, id)
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *ITGlue) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Assets returns copies of every flexible asset, by ID.
func (s *ITGlue) Assets() []ITGlueAsset {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ITGlueAsset, 0, len(s.assets))
	for _, a := range s.assets {
		traits := map[string]any{}
		for k, v := range a.Traits {
			traits[k] = v
		}
		out = append(out, ITGlueAsset{ID: a.ID, OrgID: a.OrgID, TypeID: a.TypeID, Traits: traits})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Counts reports authenticated requests, applied writes and refused
// requests.
func (s *ITGlue) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func itglueJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func itglueError(w http.ResponseWriter, status int, title, detail string) {
	itglueJSON(w, status, map[string]any{"errors": []any{map[string]any{"status": strconv.Itoa(status), "title": title, "detail": detail}}})
}

func (s *ITGlue) assetJSON(a *ITGlueAsset) map[string]any {
	name, _ := a.Traits[s.titles[a.TypeID]].(string)
	return map[string]any{"id": strconv.FormatInt(a.ID, 10), "type": "flexible-assets", "attributes": map[string]any{
		"organization-id": a.OrgID, "flexible-asset-type-id": a.TypeID, "name": name, "traits": a.Traits}}
}

func (s *ITGlue) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("x-api-key") != s.key {
		s.refused++
		itglueError(w, http.StatusForbidden, "Forbidden", "The API key is missing or not valid.")
		return
	}
	s.requests++
	if r.Method != http.MethodGet && r.Header.Get("Content-Type") != "application/vnd.api+json" {
		itglueError(w, http.StatusUnsupportedMediaType, "Unsupported Media Type", "Send application/vnd.api+json.")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/flexible_assets":
		q := r.URL.Query()
		typeID, err := strconv.ParseInt(q.Get("filter[flexible-asset-type-id]"), 10, 64)
		if err != nil {
			itglueError(w, http.StatusBadRequest, "Bad Request", "filter[flexible-asset-type-id] is required.")
			return
		}
		org, _ := strconv.ParseInt(q.Get("filter[organization-id]"), 10, 64)
		name := q.Get("filter[name]")
		data := []any{}
		ids := make([]int64, 0, len(s.assets))
		for id := range s.assets {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			a := s.assets[id]
			title, _ := a.Traits[s.titles[a.TypeID]].(string)
			if a.TypeID == typeID && (org == 0 || a.OrgID == org) && (name == "" || title == name) {
				data = append(data, s.assetJSON(a))
			}
		}
		itglueJSON(w, http.StatusOK, map[string]any{"data": data, "meta": map[string]any{"current-page": 1, "total-count": len(data)}})
	case (r.Method == http.MethodPost && r.URL.Path == "/flexible_assets") ||
		(r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/flexible_assets/")):
		var body struct {
			Data struct {
				Type       string `json:"type"`
				Attributes struct {
					OrganizationID int64          `json:"organization-id"`
					TypeID         int64          `json:"flexible-asset-type-id"`
					Traits         map[string]any `json:"traits"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Data.Type != "flexible-assets" {
			itglueError(w, http.StatusBadRequest, "Bad Request", "A flexible-assets resource object is required.")
			return
		}
		var a *ITGlueAsset
		if r.Method == http.MethodPatch {
			id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/flexible_assets/"), 10, 64)
			if a = s.assets[id]; a == nil {
				itglueError(w, http.StatusNotFound, "Not Found", "Record not found.")
				return
			}
		} else {
			if !s.orgs[body.Data.Attributes.OrganizationID] || s.types[body.Data.Attributes.TypeID] == nil {
				itglueError(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "The organization or flexible asset type does not exist.")
				return
			}
			a = &ITGlueAsset{OrgID: body.Data.Attributes.OrganizationID, TypeID: body.Data.Attributes.TypeID}
		}
		known := s.types[a.TypeID]
		for k := range body.Data.Attributes.Traits {
			if !known[k] {
				itglueError(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "Unknown trait "+k+".")
				return
			}
		}
		if title, _ := body.Data.Attributes.Traits[s.titles[a.TypeID]].(string); strings.TrimSpace(title) == "" {
			itglueError(w, http.StatusUnprocessableEntity, "Unprocessable Entity", "The name field is required.")
			return
		}
		a.Traits = body.Data.Attributes.Traits // PATCH clears every trait it does not send
		status := http.StatusOK
		if r.Method == http.MethodPost {
			s.nextID++
			a.ID = s.nextID
			s.assets[a.ID] = a
			status = http.StatusCreated
		}
		s.writes++
		if s.failWrite > 0 {
			s.failWrite--
			itglueError(w, http.StatusInternalServerError, "Internal Server Error", "Try again.")
			return
		}
		itglueJSON(w, status, map[string]any{"data": s.assetJSON(a)})
	default:
		itglueError(w, http.StatusNotFound, "Not Found", "Unknown resource.")
	}
}
