// SPDX-License-Identifier: BUSL-1.1

package psatest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// Gradient is a Gradient Synthesize vendor API stand-in written from the
// public reference: the GRADIENT-TOKEN header on every request and POST
// /api/vendor-api/service/{serviceId}/count {unitCount, accountId}, answered
// 201 {"status":201,"message":"Success"}, or 404 {"statusCode":404,
// "message":"No account map found with id: ..."} when the MSP has not mapped
// the account to the service.
type Gradient struct {
	srv *httptest.Server

	mu        sync.Mutex
	token     string
	mapped    map[string]map[string]bool
	counts    map[string]map[string]int64
	posts     int
	refused   int
	failWrite int
	seen      []string
}

// NewGradient starts a vendor API stand-in accepting one token.
func NewGradient(token string) *Gradient {
	s := &Gradient{token: token, mapped: map[string]map[string]bool{}, counts: map[string]map[string]int64{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Gradient) Close() { s.srv.Close() }

// URL is the API root.
func (s *Gradient) URL() string { return s.srv.URL }

// MapAccount records that the MSP mapped an account to a service.
func (s *Gradient) MapAccount(service, account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mapped[service] == nil {
		s.mapped[service] = map[string]bool{}
	}
	s.mapped[service][account] = true
}

// FailWritesAfterApplying makes the next n counts take effect and then
// answer 500, as a count whose answer was lost.
func (s *Gradient) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Count is an account's current count of a service and whether one exists.
func (s *Gradient) Count(service, account string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.counts[service][account]
	return v, ok
}

// Counts reports accepted posts and refused (unauthenticated) requests.
func (s *Gradient) Counts() (posts, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts, s.refused
}

// Seen lists every authenticated request.
func (s *Gradient) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func (s *Gradient) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("GRADIENT-TOKEN") != s.token {
		s.refused++
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": 401, "message": "Unauthorized"})
		return
	}
	s.seen = append(s.seen, r.Method+" "+r.URL.Path)
	service, ok := strings.CutPrefix(r.URL.Path, "/api/vendor-api/service/")
	service, okCount := strings.CutSuffix(service, "/count")
	if r.Method != http.MethodPost || !ok || !okCount || service == "" || strings.Contains(service, "/") {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": 404, "message": "Cannot " + r.Method + " " + r.URL.Path})
		return
	}
	var body struct {
		UnitCount *float64 `json:"unitCount"`
		AccountID string   `json:"accountId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UnitCount == nil || body.AccountID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": 400, "message": "unitCount and accountId are required"})
		return
	}
	if !s.mapped[service][body.AccountID] {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": 404, "message": "No account map found with id: " + body.AccountID})
		return
	}
	if s.counts[service] == nil {
		s.counts[service] = map[string]int64{}
	}
	s.counts[service][body.AccountID] = int64(*body.UnitCount)
	s.posts++
	if s.failWrite > 0 {
		s.failWrite--
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": 500, "message": "Internal server error"})
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": 201, "message": "Success", "count": strconv.FormatFloat(*body.UnitCount, 'f', -1, 64)})
}
