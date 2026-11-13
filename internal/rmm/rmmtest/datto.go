// SPDX-License-Identifier: BUSL-1.1

package rmmtest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DattoDevice is one device.
type DattoDevice struct {
	UID      string
	SiteUID  string
	Hostname string
	Online   bool
}

// DattoJob is one quick job run on a device.
type DattoJob struct {
	DeviceUID    string
	ComponentUID string
	Name         string
	Variables    map[string]string
}

// Datto is a Datto RMM API v2 stand-in written from the public OpenAPI
// description and its published clients: a password-grant token at
// /auth/oauth/token through the public client (Basic public-client:public,
// the API key and secret as user name and password) and, with the bearer, a
// site's devices paged by max and page with pageDetails.nextPageUrl, one
// device, quick jobs (PUT /api/v2/device/{uid}/quickjob, answered with the
// job) of known components, and user-defined fields udf1-udf30.
type Datto struct {
	srv *httptest.Server

	mu         sync.Mutex
	apiKey     string
	secret     string
	issued     map[string]bool
	devices    []DattoDevice
	components map[string]bool
	jobs       []DattoJob
	udfs       map[string]map[string]string
	requests   int
	writes     int
	refused    int
	failWrite  int
	nextToken  int
}

// NewDatto starts a stand-in for one API user.
func NewDatto(apiKey, secret string) *Datto {
	s := &Datto{apiKey: apiKey, secret: secret, issued: map[string]bool{}, components: map[string]bool{}, udfs: map[string]map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Datto) Close() { s.srv.Close() }

// URL is the platform's API host.
func (s *Datto) URL() string { return s.srv.URL }

// AddDevice records a device.
func (s *Datto) AddDevice(d DattoDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = append(s.devices, d)
}

// MoveDevice moves a device to another site.
func (s *Datto) MoveDevice(uid, site string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.devices {
		if s.devices[i].UID == uid {
			s.devices[i].SiteUID = site
		}
	}
}

// AddComponent records a ComStore component.
func (s *Datto) AddComponent(uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.components[uid] = true
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *Datto) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Jobs returns every quick job.
func (s *Datto) Jobs() []DattoJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]DattoJob(nil), s.jobs...)
}

// UDFs returns a device's user-defined fields.
func (s *Datto) UDFs(uid string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.udfs[uid] {
		out[k] = v
	}
	return out
}

// Counts reports authenticated API requests, applied writes and refused
// requests.
func (s *Datto) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func dattoJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func dattoError(w http.ResponseWriter, r *http.Request, status int, reason string) {
	dattoJSON(w, status, map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339), "status": status, "error": reason, "path": r.URL.Path})
}

func dattoDeviceJSON(d DattoDevice) map[string]any {
	return map[string]any{"id": len(d.UID), "uid": d.UID, "siteUid": d.SiteUID, "siteName": "site " + d.SiteUID[:8], "hostname": d.Hostname,
		"online": d.Online, "deleted": false, "deviceType": map[string]any{"category": "Server", "type": "Windows"}}
}

func (s *Datto) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/auth/oauth/token" && r.Method == http.MethodPost {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("public-client:public"))
		if err := r.ParseForm(); err != nil || r.Header.Get("Authorization") != basic || r.PostForm.Get("grant_type") != "password" ||
			r.PostForm.Get("username") != s.apiKey || r.PostForm.Get("password") != s.secret {
			s.refused++
			dattoJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_grant", "error_description": "Bad credentials"})
			return
		}
		s.nextToken++
		token := "datto-access-" + strconv.Itoa(s.nextToken)
		s.issued[token] = true
		dattoJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 359999, "scope": "default"})
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		dattoError(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}
	s.requests++
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 5 && parts[0] == "api" && parts[1] == "v2" && parts[2] == "site" && parts[4] == "devices":
		size, _ := strconv.Atoi(r.URL.Query().Get("max"))
		if size <= 0 || size > 250 {
			size = 250
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var list []DattoDevice
		for _, d := range s.devices {
			if d.SiteUID == parts[3] {
				list = append(list, d)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].UID < list[j].UID })
		total := len(list)
		start := page * size
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		out := []any{}
		for _, d := range list[start:end] {
			out = append(out, dattoDeviceJSON(d))
		}
		var next any
		if end < total {
			next = fmt.Sprintf("%s/api/v2/site/%s/devices?max=%d&page=%d", s.srv.URL, parts[3], size, page+1)
		}
		dattoJSON(w, http.StatusOK, map[string]any{"pageDetails": map[string]any{"count": len(out), "totalCount": total, "prevPageUrl": nil, "nextPageUrl": next},
			"devices": out})
	case r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "api" && parts[2] == "device":
		if d, ok := s.device(parts[3]); ok {
			dattoJSON(w, http.StatusOK, dattoDeviceJSON(d))
			return
		}
		dattoError(w, r, http.StatusNotFound, "Not Found")
	case r.Method == http.MethodPut && len(parts) == 5 && parts[2] == "device" && parts[4] == "quickjob":
		var body struct {
			JobName      string `json:"jobName"`
			JobComponent struct {
				ComponentUID string `json:"componentUid"`
				Variables    []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"variables"`
			} `json:"jobComponent"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.JobName) == "" || !s.components[body.JobComponent.ComponentUID] {
			dattoError(w, r, http.StatusBadRequest, "Bad Request")
			return
		}
		if _, ok := s.device(parts[3]); !ok {
			dattoError(w, r, http.StatusNotFound, "Not Found")
			return
		}
		vars := map[string]string{}
		for _, v := range body.JobComponent.Variables {
			vars[v.Name] = v.Value
		}
		s.jobs = append(s.jobs, DattoJob{DeviceUID: parts[3], ComponentUID: body.JobComponent.ComponentUID, Name: body.JobName, Variables: vars})
		s.writes++
		if s.lost(w, r) {
			return
		}
		jobUID := fmt.Sprintf("00000000-0000-4000-8000-%012d", len(s.jobs))
		dattoJSON(w, http.StatusOK, map[string]any{"job": map[string]any{"id": len(s.jobs), "uid": jobUID, "name": body.JobName,
			"dateCreated": time.Now().UnixMilli(), "status": "active"}, "jobComponents": []any{map[string]any{"uid": body.JobComponent.ComponentUID}}})
	case r.Method == http.MethodPost && len(parts) == 5 && parts[2] == "device" && parts[4] == "udf":
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) == 0 {
			dattoError(w, r, http.StatusBadRequest, "Bad Request")
			return
		}
		for k := range body {
			n, err := strconv.Atoi(strings.TrimPrefix(k, "udf"))
			if !strings.HasPrefix(k, "udf") || err != nil || n < 1 || n > 30 {
				dattoError(w, r, http.StatusBadRequest, "Bad Request")
				return
			}
		}
		if _, ok := s.device(parts[3]); !ok {
			dattoError(w, r, http.StatusNotFound, "Not Found")
			return
		}
		if s.udfs[parts[3]] == nil {
			s.udfs[parts[3]] = map[string]string{}
		}
		for k, v := range body {
			s.udfs[parts[3]][k] = v
		}
		s.writes++
		if s.lost(w, r) {
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		dattoError(w, r, http.StatusNotFound, "Not Found")
	}
}

func (s *Datto) device(uid string) (DattoDevice, bool) {
	for _, d := range s.devices {
		if d.UID == uid {
			return d, true
		}
	}
	return DattoDevice{}, false
}

func (s *Datto) lost(w http.ResponseWriter, r *http.Request) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	dattoError(w, r, http.StatusInternalServerError, "Internal Server Error")
	return true
}
