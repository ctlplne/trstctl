// SPDX-License-Identifier: BUSL-1.1

package rmmtest

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

// KaseyaAgent is one VSA agent.
type KaseyaAgent struct {
	ID       int64
	OrgID    int64
	Computer string
	Online   bool
}

// KaseyaRun is one agent procedure run now, with the agent's enrollment
// custom field as it stood when the procedure was started.
type KaseyaRun struct {
	AgentID     int64
	ProcedureID int64
	Enrollment  string
}

// Kaseya is a Kaseya VSA 9 REST API stand-in written from the public help
// pages and the published module: a session token from GET /api/v1.0/auth
// with Basic user:personal-access-token (Result.Token) and, with the bearer,
// the agents in the {TotalRecords, Result, ResponseCode, Status, Error}
// envelope paged by $top and $skip, one agent, procedures run now (PUT, no
// body, 204; 404 for an unknown procedure) and agent custom fields (PUT
// [{"key":"FieldValue","value":...}]).
type Kaseya struct {
	srv *httptest.Server

	mu          sync.Mutex
	user, pat   string
	issued      map[string]bool
	agents      []KaseyaAgent
	procedures  map[int64]bool
	fields      map[int64]map[string]string
	knownFields map[string]bool
	runs        []KaseyaRun
	requests    int
	writes      int
	refused     int
	failWrite   int
	nextToken   int
}

// NewKaseya starts a stand-in for one user and personal access token.
func NewKaseya(user, pat string) *Kaseya {
	s := &Kaseya{user: user, pat: pat, issued: map[string]bool{}, procedures: map[int64]bool{}, fields: map[int64]map[string]string{},
		knownFields: map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Kaseya) Close() { s.srv.Close() }

// URL is the server.
func (s *Kaseya) URL() string { return s.srv.URL }

// AddAgent records an agent.
func (s *Kaseya) AddAgent(a KaseyaAgent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = append(s.agents, a)
}

// MoveAgent moves an agent to another organization.
func (s *Kaseya) MoveAgent(id, org int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.agents {
		if s.agents[i].ID == id {
			s.agents[i].OrgID = org
		}
	}
}

// AddProcedure records an agent procedure.
func (s *Kaseya) AddProcedure(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procedures[id] = true
}

// AddField records a custom field.
func (s *Kaseya) AddField(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.knownFields[name] = true
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *Kaseya) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Runs returns every procedure run.
func (s *Kaseya) Runs() []KaseyaRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]KaseyaRun(nil), s.runs...)
}

// Field returns an agent's custom field.
func (s *Kaseya) Field(agent int64, name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fields[agent][name]
}

// Counts reports authenticated API requests, applied writes and refused
// requests.
func (s *Kaseya) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

func kaseyaJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func kaseyaError(w http.ResponseWriter, status, code int, message string) {
	kaseyaJSON(w, status, map[string]any{"Result": nil, "ResponseCode": code, "Status": "Error", "Error": message})
}

func kaseyaAgentJSON(a KaseyaAgent) map[string]any {
	online := 0
	if a.Online {
		online = 1
	}
	return map[string]any{"AgentId": strconv.FormatInt(a.ID, 10), "AgentName": strings.ToLower(a.Computer) + ".root.org" + strconv.FormatInt(a.OrgID, 10),
		"ComputerName": a.Computer, "OrgId": strconv.FormatInt(a.OrgID, 10), "MachineGroup": "root.org" + strconv.FormatInt(a.OrgID, 10), "Online": online}
}

func (s *Kaseya) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.EqualFold(r.URL.Path, "/api/v1.0/auth") && r.Method == http.MethodGet {
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(s.user+":"+s.pat)) {
			s.refused++
			kaseyaError(w, http.StatusUnauthorized, 401, "Invalid credentials")
			return
		}
		s.nextToken++
		token := "vsa-session-" + strconv.Itoa(s.nextToken)
		s.issued[token] = true
		kaseyaJSON(w, http.StatusOK, map[string]any{"Result": map[string]any{"Token": token, "UserName": s.user, "SessionExpiration": "2099-01-01T00:00:00Z",
			"OffSetInMinutes": 0}, "ResponseCode": 0, "Status": "OK", "Error": "None"})
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		kaseyaError(w, http.StatusUnauthorized, 401, "Unauthorized")
		return
	}
	s.requests++
	parts := strings.Split(strings.Trim(strings.ToLower(r.URL.Path), "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 4 && parts[2] == "assetmgmt" && parts[3] == "agents":
		top, _ := strconv.Atoi(r.URL.Query().Get("$top"))
		if top <= 0 || top > 100 {
			top = 100
		}
		skip, _ := strconv.Atoi(r.URL.Query().Get("$skip"))
		list := append([]KaseyaAgent(nil), s.agents...)
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		total := len(list)
		if skip > total {
			skip = total
		}
		end := skip + top
		if end > total {
			end = total
		}
		result := []any{}
		for _, a := range list[skip:end] {
			result = append(result, kaseyaAgentJSON(a))
		}
		kaseyaJSON(w, http.StatusOK, map[string]any{"TotalRecords": total, "Result": result, "ResponseCode": 0, "Status": "OK", "Error": "None"})
	case r.Method == http.MethodGet && len(parts) == 5 && parts[2] == "assetmgmt" && parts[3] == "agents":
		id, _ := strconv.ParseInt(parts[4], 10, 64)
		if a, ok := s.agent(id); ok {
			kaseyaJSON(w, http.StatusOK, map[string]any{"Result": kaseyaAgentJSON(a), "ResponseCode": 0, "Status": "OK", "Error": "None"})
			return
		}
		kaseyaError(w, http.StatusNotFound, 404, "Agent not found")
	case r.Method == http.MethodPut && len(parts) == 7 && parts[2] == "automation" && parts[3] == "agentprocs" && parts[6] == "runnow":
		id, _ := strconv.ParseInt(parts[4], 10, 64)
		proc, _ := strconv.ParseInt(parts[5], 10, 64)
		if _, ok := s.agent(id); !ok || !s.procedures[proc] {
			kaseyaError(w, http.StatusNotFound, 404, "Agent procedure not found or not permitted")
			return
		}
		enrollment := ""
		for name, value := range s.fields[id] {
			if strings.Contains(strings.ToLower(name), "enroll") {
				enrollment = value
			}
		}
		s.runs = append(s.runs, KaseyaRun{AgentID: id, ProcedureID: proc, Enrollment: enrollment})
		s.writes++
		if s.lost(w) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut && len(parts) == 7 && parts[2] == "assetmgmt" && parts[3] == "assets" && parts[5] == "customfields":
		id, _ := strconv.ParseInt(parts[4], 10, 64)
		name := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[6]
		var body []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body[0].Key != "FieldValue" {
			kaseyaError(w, http.StatusBadRequest, 400, "Expected [{\"key\":\"FieldValue\",\"value\":...}]")
			return
		}
		if _, ok := s.agent(id); !ok || !s.knownFields[name] {
			kaseyaError(w, http.StatusNotFound, 404, "Asset or custom field not found")
			return
		}
		if s.fields[id] == nil {
			s.fields[id] = map[string]string{}
		}
		s.fields[id][name] = body[0].Value
		s.writes++
		if s.lost(w) {
			return
		}
		kaseyaJSON(w, http.StatusOK, map[string]any{"Result": true, "ResponseCode": 0, "Status": "OK", "Error": "None"})
	default:
		kaseyaError(w, http.StatusNotFound, 404, "Not found")
	}
}

func (s *Kaseya) agent(id int64) (KaseyaAgent, bool) {
	for _, a := range s.agents {
		if a.ID == id {
			return a, true
		}
	}
	return KaseyaAgent{}, false
}

func (s *Kaseya) lost(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	kaseyaError(w, http.StatusInternalServerError, 500, "Internal error")
	return true
}
