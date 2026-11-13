// SPDX-License-Identifier: BUSL-1.1

// Package rmmtest holds RMM stand-ins for tests, each written from its
// vendor's public API description: credentials checked on every request,
// the documented request shapes, and the records a real RMM would keep, so
// a test can assert which device ran what.
package rmmtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// NinjaDevice is one device.
type NinjaDevice struct {
	ID         int64
	OrgID      int64
	SystemName string
	Offline    bool
}

// NinjaRun is one script run on a device.
type NinjaRun struct {
	DeviceID   int64
	ScriptID   int64
	Parameters string
	RunAs      string
}

// NinjaOne is a NinjaOne API v2 stand-in written from the public OpenAPI
// description and published client: a client-credentials token at
// /ws/oauth/token (form, scopes monitoring management control) and, with the
// bearer, organization devices paged by pageSize and after, one device,
// script runs answered 204, and device custom fields patched by name.
type NinjaOne struct {
	srv *httptest.Server

	mu        sync.Mutex
	clientID  string
	secret    string
	issued    map[string]bool
	devices   []NinjaDevice
	scripts   map[int64]bool
	runs      []NinjaRun
	fields    map[int64]map[string]string
	requests  int
	writes    int
	refused   int
	failWrite int
	nextToken int
}

// NewNinjaOne starts a stand-in for one API client.
func NewNinjaOne(clientID, secret string) *NinjaOne {
	s := &NinjaOne{clientID: clientID, secret: secret, issued: map[string]bool{}, scripts: map[int64]bool{}, fields: map[int64]map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *NinjaOne) Close() { s.srv.Close() }

// URL is the instance host.
func (s *NinjaOne) URL() string { return s.srv.URL }

// AddDevice records a device.
func (s *NinjaOne) AddDevice(d NinjaDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = append(s.devices, d)
}

// RemoveDevice forgets a device, as when it is deleted in NinjaOne.
func (s *NinjaOne) RemoveDevice(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.devices[:0]
	for _, d := range s.devices {
		if d.ID != id {
			kept = append(kept, d)
		}
	}
	s.devices = kept
}

// AddScript records an automation-library script.
func (s *NinjaOne) AddScript(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripts[id] = true
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *NinjaOne) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Runs returns every script run.
func (s *NinjaOne) Runs() []NinjaRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]NinjaRun(nil), s.runs...)
}

// Fields returns a device's custom fields.
func (s *NinjaOne) Fields(device int64) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.fields[device] {
		out[k] = v
	}
	return out
}

// Counts reports authenticated API requests, applied writes and refused
// requests.
func (s *NinjaOne) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func ninjaJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ninjaError(w http.ResponseWriter, status int, code, message string) {
	ninjaJSON(w, status, map[string]any{"resultCode": code, "errorMessage": message})
}

func ninjaDeviceJSON(d NinjaDevice) map[string]any {
	return map[string]any{"id": d.ID, "organizationId": d.OrgID, "systemName": d.SystemName, "dnsName": strings.ToLower(d.SystemName) + ".local",
		"displayName": d.SystemName, "offline": d.Offline, "nodeClass": "WINDOWS_SERVER"}
}

func (s *NinjaOne) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/ws/oauth/token" && r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != s.clientID ||
			r.PostForm.Get("client_secret") != s.secret || !strings.Contains(r.PostForm.Get("scope"), "management") {
			s.refused++
			ninjaJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
			return
		}
		s.nextToken++
		token := "ninja-access-" + strconv.Itoa(s.nextToken)
		s.issued[token] = true
		ninjaJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		ninjaError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or missing token")
		return
	}
	s.requests++
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "v2" && parts[1] == "organization" && parts[3] == "devices":
		org, _ := strconv.ParseInt(parts[2], 10, 64)
		size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if size <= 0 || size > 1000 {
			size = 1000
		}
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		var list []NinjaDevice
		for _, d := range s.devices {
			if d.OrgID == org && d.ID > after {
				list = append(list, d)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		if len(list) > size {
			list = list[:size]
		}
		out := []any{}
		for _, d := range list {
			out = append(out, ninjaDeviceJSON(d))
		}
		ninjaJSON(w, http.StatusOK, out)
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "v2" && parts[1] == "device":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		for _, d := range s.devices {
			if d.ID == id {
				ninjaJSON(w, http.StatusOK, ninjaDeviceJSON(d))
				return
			}
		}
		ninjaError(w, http.StatusNotFound, "NOT_FOUND", "device not found")
	case r.Method == http.MethodPost && len(parts) == 5 && parts[1] == "device" && parts[3] == "script" && parts[4] == "run":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		var body struct {
			Type       string `json:"type"`
			ID         int64  `json:"id"`
			Parameters string `json:"parameters"`
			RunAs      string `json:"runAs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Type != "SCRIPT" || !s.scripts[body.ID] || body.RunAs == "" {
			ninjaError(w, http.StatusBadRequest, "BAD_REQUEST", "a script run names a library script, its type and runAs")
			return
		}
		if !s.hasDevice(id) {
			ninjaError(w, http.StatusNotFound, "NOT_FOUND", "device not found")
			return
		}
		s.runs = append(s.runs, NinjaRun{DeviceID: id, ScriptID: body.ID, Parameters: body.Parameters, RunAs: body.RunAs})
		s.writes++
		if s.lost(w) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPatch && len(parts) == 4 && parts[1] == "device" && parts[3] == "custom-fields":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) == 0 {
			ninjaError(w, http.StatusBadRequest, "BAD_REQUEST", "custom fields are an object keyed by field name")
			return
		}
		if !s.hasDevice(id) {
			ninjaError(w, http.StatusNotFound, "NOT_FOUND", "device not found")
			return
		}
		if s.fields[id] == nil {
			s.fields[id] = map[string]string{}
		}
		for k, v := range body {
			s.fields[id][k] = v
		}
		s.writes++
		if s.lost(w) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ninjaError(w, http.StatusNotFound, "NOT_FOUND", "unknown resource")
	}
}

func (s *NinjaOne) hasDevice(id int64) bool {
	for _, d := range s.devices {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (s *NinjaOne) lost(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	ninjaError(w, http.StatusInternalServerError, "INTERNAL", "try again")
	return true
}
