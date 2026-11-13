// SPDX-License-Identifier: BUSL-1.1

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

// NCentralDevice is one device.
type NCentralDevice struct {
	ID         int64
	CustomerID int64
	Name       string
}

// NCentralTask is one direct scheduled task run on a device.
type NCentralTask struct {
	DeviceID   int64
	CustomerID int64
	ItemID     int64
	Credential string
	Params     map[string]string
}

// NCentral is an N-able N-central REST API stand-in written from the public
// API reference: an access token from POST /api/auth/authenticate with the
// API user's JWT as the bearer and, with the access token, a customer org
// unit's devices paged by pageNumber and pageSize, one device wrapped in data,
// direct scheduled tasks of API-enabled scripts (unique names, answered 201
// with the task ID) and device custom properties (PUT, answered 200 with
// the preview warning), errors as {status, message, errors}.
type NCentral struct {
	srv *httptest.Server

	mu         sync.Mutex
	jwt        string
	issued     map[string]bool
	devices    []NCentralDevice
	scripts    map[int64]bool
	properties map[int64]bool
	names      map[string]bool
	tasks      []NCentralTask
	values     map[int64]map[int64]string
	requests   int
	writes     int
	refused    int
	failWrite  int
	nextToken  int
}

// NewNCentral starts a stand-in for one API user.
func NewNCentral(jwt string) *NCentral {
	s := &NCentral{jwt: jwt, issued: map[string]bool{}, scripts: map[int64]bool{}, properties: map[int64]bool{}, names: map[string]bool{},
		values: map[int64]map[int64]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *NCentral) Close() { s.srv.Close() }

// URL is the server.
func (s *NCentral) URL() string { return s.srv.URL }

// AddDevice records a device.
func (s *NCentral) AddDevice(d NCentralDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = append(s.devices, d)
}

// MoveDevice moves a device to another customer.
func (s *NCentral) MoveDevice(id, customer int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.devices {
		if s.devices[i].ID == id {
			s.devices[i].CustomerID = customer
		}
	}
}

// AddScript records a script repository item with its API toggle on.
func (s *NCentral) AddScript(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripts[id] = true
}

// AddProperty records a device custom property.
func (s *NCentral) AddProperty(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.properties[id] = true
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *NCentral) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Tasks returns every task.
func (s *NCentral) Tasks() []NCentralTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]NCentralTask(nil), s.tasks...)
}

// Property returns a device's custom property value.
func (s *NCentral) Property(device, property int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[device][property]
}

// Counts reports authenticated API requests, applied writes and refused
// requests.
func (s *NCentral) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func ncentralJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ncentralError(w http.ResponseWriter, status int, message string) {
	ncentralJSON(w, status, map[string]any{"status": status, "message": "[ID=stand-in] " + message, "errors": []any{}})
}

func ncentralDeviceJSON(d NCentralDevice) map[string]any {
	return map[string]any{"deviceId": d.ID, "orgUnitId": d.CustomerID, "soId": 50, "customerId": d.CustomerID, "siteId": 0, "longName": d.Name,
		"discoveredName": strings.ToLower(d.Name), "customerName": "customer " + strconv.FormatInt(d.CustomerID, 10), "deviceClass": "Servers - Windows",
		"isProbe": false}
}

func (s *NCentral) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/api/auth/authenticate" && r.Method == http.MethodPost {
		if r.Header.Get("Authorization") != "Bearer "+s.jwt {
			s.refused++
			ncentralError(w, http.StatusUnauthorized, "Authentication Failure")
			return
		}
		s.nextToken++
		token := "ncentral-access-" + strconv.Itoa(s.nextToken)
		s.issued[token] = true
		ncentralJSON(w, http.StatusOK, map[string]any{"tokens": map[string]any{
			"access":  map[string]any{"token": token, "type": "Bearer", "expirySeconds": 3600},
			"refresh": map[string]any{"token": "ncentral-refresh-" + strconv.Itoa(s.nextToken), "type": "Bearer", "expirySeconds": 90000}}})
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		ncentralError(w, http.StatusUnauthorized, "Authentication Failure")
		return
	}
	s.requests++
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "api" && parts[1] == "org-units" && parts[3] == "devices":
		unit, _ := strconv.ParseInt(parts[2], 10, 64)
		size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if size <= 0 {
			size = 50
		}
		if size > 1000 {
			ncentralError(w, http.StatusBadRequest, "pageSize must be 1 to 1000")
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("pageNumber"))
		if page < 1 {
			page = 1
		}
		var list []NCentralDevice
		for _, d := range s.devices {
			if d.CustomerID == unit {
				list = append(list, d)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		total := len(list)
		pages := (total + size - 1) / size
		start := (page - 1) * size
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		data := []any{}
		for _, d := range list[start:end] {
			data = append(data, ncentralDeviceJSON(d))
		}
		ncentralJSON(w, http.StatusOK, map[string]any{"data": data, "pageNumber": page, "pageSize": size, "itemCount": len(data),
			"totalItems": total, "totalPages": pages, "_links": map[string]any{}, "_warning": "This is a preview API"})
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "api" && parts[1] == "devices":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		if d, ok := s.device(id); ok {
			ncentralJSON(w, http.StatusOK, map[string]any{"data": ncentralDeviceJSON(d), "_links": map[string]any{}})
			return
		}
		ncentralError(w, http.StatusNotFound, "NOT FOUND: device")
	case r.Method == http.MethodPost && r.URL.Path == "/api/scheduled-tasks/direct":
		var body struct {
			Name       string `json:"name"`
			ItemID     int64  `json:"itemId"`
			TaskType   string `json:"taskType"`
			CustomerID int64  `json:"customerId"`
			DeviceID   int64  `json:"deviceId"`
			Credential struct {
				Type string `json:"type"`
			} `json:"credential"`
			Parameters []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
				Type  string `json:"type"`
			} `json:"parameters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" || body.TaskType != "Script" ||
			!s.scripts[body.ItemID] || body.Credential.Type == "" {
			ncentralError(w, http.StatusBadRequest, "BAD REQUEST: a direct task names a unique task, an API-enabled script, its type and credential")
			return
		}
		if s.names[body.Name] {
			ncentralError(w, http.StatusBadRequest, "BAD REQUEST: a task with this name exists")
			return
		}
		d, ok := s.device(body.DeviceID)
		if !ok || d.CustomerID != body.CustomerID {
			ncentralError(w, http.StatusBadRequest, "BAD REQUEST: the device is not under this customer")
			return
		}
		params := map[string]string{}
		for _, p := range body.Parameters {
			params[p.Name] = p.Value
		}
		s.names[body.Name] = true
		s.tasks = append(s.tasks, NCentralTask{DeviceID: body.DeviceID, CustomerID: body.CustomerID, ItemID: body.ItemID, Credential: body.Credential.Type, Params: params})
		s.writes++
		if s.lost(w) {
			return
		}
		ncentralJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"taskId": 9000 + len(s.tasks)}})
	case r.Method == http.MethodPut && len(parts) == 5 && parts[1] == "devices" && parts[3] == "custom-properties":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		property, _ := strconv.ParseInt(parts[4], 10, 64)
		var body map[string]json.RawMessage
		var value string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || json.Unmarshal(body["value"], &value) != nil {
			ncentralError(w, http.StatusBadRequest, "BAD REQUEST: only value is writable")
			return
		}
		if _, ok := s.device(id); !ok || !s.properties[property] {
			ncentralError(w, http.StatusNotFound, "NOT FOUND: device or property")
			return
		}
		if s.values[id] == nil {
			s.values[id] = map[int64]string{}
		}
		s.values[id][property] = value
		s.writes++
		if s.lost(w) {
			return
		}
		ncentralJSON(w, http.StatusOK, map[string]any{"_warnings": []string{"This is a preview API"}})
	default:
		ncentralError(w, http.StatusNotFound, "NOT FOUND")
	}
}

func (s *NCentral) device(id int64) (NCentralDevice, bool) {
	for _, d := range s.devices {
		if d.ID == id {
			return d, true
		}
	}
	return NCentralDevice{}, false
}

func (s *NCentral) lost(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	ncentralError(w, http.StatusInternalServerError, "INTERNAL SERVER ERROR")
	return true
}
