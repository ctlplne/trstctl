// SPDX-License-Identifier: BUSL-1.1

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

// HuduAsset is one asset.
type HuduAsset struct {
	ID        int64
	CompanyID int64
	LayoutID  int64
	Name      string
	Fields    map[string]any
}

// Hudu is a Hudu /api/v1 stand-in written from the calls Hudu's published
// API clients make: the x-api-key header (401 otherwise), companies, asset
// layouts with their field keys, assets listed with company_id,
// asset_layout_id and name filters ({"assets": [...]}, page and page_size),
// created under a company and replaced with PUT, each body an {"asset":
// ...} object whose custom_fields list holds objects keyed by field key (422
// for an unknown field or layout, or a missing name).
type Hudu struct {
	srv *httptest.Server

	mu        sync.Mutex
	key       string
	companies map[int64]bool
	layouts   map[int64]map[string]bool
	assets    map[int64]*HuduAsset
	nextID    int64
	requests  int
	writes    int
	refused   int
	failWrite int
}

// NewHudu starts a stand-in for one API key.
func NewHudu(key string) *Hudu {
	s := &Hudu{key: key, companies: map[int64]bool{}, layouts: map[int64]map[string]bool{}, assets: map[int64]*HuduAsset{}, nextID: 500}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Hudu) Close() { s.srv.Close() }

// URL is the instance.
func (s *Hudu) URL() string { return s.srv.URL }

// AddCompany records a company.
func (s *Hudu) AddCompany(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.companies[id] = true
}

// AddLayout records an asset layout with its field keys.
func (s *Hudu) AddLayout(id int64, fieldKeys ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.layouts[id] = map[string]bool{}
	for _, k := range fieldKeys {
		s.layouts[id][k] = true
	}
}

// DeleteAsset deletes an asset, as an operator would in Hudu.
func (s *Hudu) DeleteAsset(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assets, id)
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *Hudu) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Assets returns copies of every asset, by ID.
func (s *Hudu) Assets() []HuduAsset {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HuduAsset, 0, len(s.assets))
	for _, a := range s.assets {
		fields := map[string]any{}
		for k, v := range a.Fields {
			fields[k] = v
		}
		out = append(out, HuduAsset{ID: a.ID, CompanyID: a.CompanyID, LayoutID: a.LayoutID, Name: a.Name, Fields: fields})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Counts reports authenticated requests, applied writes and refused
// requests.
func (s *Hudu) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func huduJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func huduAssetJSON(a *HuduAsset) map[string]any {
	fields := []any{}
	keys := make([]string, 0, len(a.Fields))
	for k := range a.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, map[string]any{"label": k, "value": a.Fields[k]})
	}
	return map[string]any{"id": a.ID, "company_id": a.CompanyID, "asset_layout_id": a.LayoutID, "name": a.Name, "archived": false, "fields": fields}
}

func (s *Hudu) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("x-api-key") != s.key {
		s.refused++
		huduJSON(w, http.StatusUnauthorized, map[string]any{"error": "Invalid API key"})
		return
	}
	s.requests++
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/assets":
		q := r.URL.Query()
		company, _ := strconv.ParseInt(q.Get("company_id"), 10, 64)
		layout, _ := strconv.ParseInt(q.Get("asset_layout_id"), 10, 64)
		name := q.Get("name")
		out := []any{}
		ids := make([]int64, 0, len(s.assets))
		for id := range s.assets {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			a := s.assets[id]
			if (company == 0 || a.CompanyID == company) && (layout == 0 || a.LayoutID == layout) && (name == "" || a.Name == name) {
				out = append(out, huduAssetJSON(a))
			}
		}
		huduJSON(w, http.StatusOK, map[string]any{"assets": out})
	case (r.Method == http.MethodPost && len(parts) == 5 && parts[2] == "companies" && parts[4] == "assets") ||
		(r.Method == http.MethodPut && len(parts) == 6 && parts[2] == "companies" && parts[4] == "assets"):
		company, _ := strconv.ParseInt(parts[3], 10, 64)
		var body struct {
			Asset struct {
				Name          string           `json:"name"`
				AssetLayoutID int64            `json:"asset_layout_id"`
				CustomFields  []map[string]any `json:"custom_fields"`
			} `json:"asset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Asset.Name) == "" {
			huduJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "Name can't be blank"})
			return
		}
		known := s.layouts[body.Asset.AssetLayoutID]
		if !s.companies[company] || known == nil {
			huduJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "Company or asset layout not found"})
			return
		}
		fields := map[string]any{}
		for _, group := range body.Asset.CustomFields {
			for k, v := range group {
				if !known[k] {
					huduJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "Unknown field " + k})
					return
				}
				fields[k] = v
			}
		}
		var a *HuduAsset
		if r.Method == http.MethodPut {
			id, _ := strconv.ParseInt(parts[5], 10, 64)
			if a = s.assets[id]; a == nil || a.CompanyID != company {
				huduJSON(w, http.StatusNotFound, map[string]any{"error": "Asset not found"})
				return
			}
		} else {
			s.nextID++
			a = &HuduAsset{ID: s.nextID, CompanyID: company}
			s.assets[a.ID] = a
		}
		a.Name, a.LayoutID, a.Fields = body.Asset.Name, body.Asset.AssetLayoutID, fields
		s.writes++
		if s.failWrite > 0 {
			s.failWrite--
			huduJSON(w, http.StatusInternalServerError, map[string]any{"error": "Something went wrong"})
			return
		}
		huduJSON(w, http.StatusOK, map[string]any{"asset": huduAssetJSON(a)})
	default:
		huduJSON(w, http.StatusNotFound, map[string]any{"error": "Not found"})
	}
}
