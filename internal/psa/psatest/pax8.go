// SPDX-License-Identifier: BUSL-1.1

package psatest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
)

// Pax8Line is one stored usage line.
type Pax8Line struct {
	Subscription      string
	BillingPeriod     string
	Day               string
	ProductID         string
	Quantity          float64
	SummaryKey        string
	SummaryName       string
	UnitOfMeasurement string
}

var pax8UUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Pax8 is a Pax8 Usage API stand-in written from the public developer
// reference: a client-credentials token exchange (JSON body with audience)
// and POST /v2/usage/lines?subscriptionId&billingPeriod=yyyy-MM with an
// array of 1-50 {productId, quantity, summaryKey, summaryDisplayName,
// unitOfMeasurement}, where a line posted the same day with the same
// subscription and summary key overwrites the earlier one
// (overwriteSameDayUsage, default true); answers a page {content, page}.
type Pax8 struct {
	srv *httptest.Server

	mu            sync.Mutex
	clientID      string
	clientSecret  string
	audience      string
	issued        map[string]bool
	subscriptions map[string]bool
	lines         []Pax8Line
	day           string
	nextToken     int
	posts         int
	refused       int
	failWrite     int
}

// NewPax8 starts a stand-in for one vendor application.
func NewPax8(clientID, clientSecret, audience string) *Pax8 {
	s := &Pax8{clientID: clientID, clientSecret: clientSecret, audience: audience, issued: map[string]bool{},
		subscriptions: map[string]bool{}, day: "2026-11-13"}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Pax8) Close() { s.srv.Close() }

// URL is the API root; TokenURL the token endpoint.
func (s *Pax8) URL() string      { return s.srv.URL }
func (s *Pax8) TokenURL() string { return s.srv.URL + "/oauth/token" }

// AddSubscription records a subscription usage may be posted for.
func (s *Pax8) AddSubscription(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptions[id] = true
}

// SetDay sets the stand-in's calendar day (lines posted the same day
// overwrite each other).
func (s *Pax8) SetDay(day string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.day = day
}

// FailWritesAfterApplying makes the next n uploads take effect and then
// answer 500, as an upload whose answer was lost.
func (s *Pax8) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// Lines returns every stored usage line.
func (s *Pax8) Lines() []Pax8Line {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Pax8Line(nil), s.lines...)
}

// Counts reports accepted uploads and refused requests.
func (s *Pax8) Counts() (posts, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts, s.refused
}

func pax8JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Pax8) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/oauth/token" && r.Method == http.MethodPost {
		var body struct {
			GrantType    string `json:"grant_type"`
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			Audience     string `json:"audience"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.GrantType != "client_credentials" ||
			body.ClientID != s.clientID || body.ClientSecret != s.clientSecret || body.Audience != s.audience {
			s.refused++
			pax8JSON(w, http.StatusUnauthorized, map[string]any{"error": "access_denied", "error_description": "Unauthorized"})
			return
		}
		s.nextToken++
		token := "pax8-access-" + strings.Repeat("x", s.nextToken)
		s.issued[token] = true
		pax8JSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 86400})
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		pax8JSON(w, http.StatusUnauthorized, map[string]any{"message": "Unauthorized"})
		return
	}
	if r.URL.Path != "/v2/usage/lines" || r.Method != http.MethodPost {
		pax8JSON(w, http.StatusNotFound, map[string]any{"message": "Not found"})
		return
	}
	q := r.URL.Query()
	subscription, period := q.Get("subscriptionId"), q.Get("billingPeriod")
	if !s.subscriptions[subscription] {
		pax8JSON(w, http.StatusNotFound, map[string]any{"message": "Subscription not found"})
		return
	}
	if len(period) != 7 || period[4] != '-' {
		pax8JSON(w, http.StatusBadRequest, map[string]any{"message": "billingPeriod must be yyyy-MM"})
		return
	}
	var body []struct {
		ProductID          string   `json:"productId"`
		Quantity           *float64 `json:"quantity"`
		SummaryKey         string   `json:"summaryKey"`
		SummaryDisplayName string   `json:"summaryDisplayName"`
		UnitOfMeasurement  string   `json:"unitOfMeasurement"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) == 0 || len(body) > 50 {
		pax8JSON(w, http.StatusBadRequest, map[string]any{"message": "post 1-50 usage lines"})
		return
	}
	for _, l := range body {
		if !pax8UUID.MatchString(l.ProductID) || l.Quantity == nil || *l.Quantity < 0 || l.SummaryKey == "" || len(l.SummaryKey) > 255 ||
			l.SummaryDisplayName == "" || len(l.SummaryDisplayName) > 255 || l.UnitOfMeasurement == "" {
			pax8JSON(w, http.StatusBadRequest, map[string]any{"message": "every line needs productId, quantity, summaryKey, summaryDisplayName and unitOfMeasurement"})
			return
		}
	}
	overwrite := q.Get("overwriteSameDayUsage") != "false"
	content := []any{}
	for _, l := range body {
		line := Pax8Line{Subscription: subscription, BillingPeriod: period, Day: s.day, ProductID: l.ProductID, Quantity: *l.Quantity,
			SummaryKey: l.SummaryKey, SummaryName: l.SummaryDisplayName, UnitOfMeasurement: l.UnitOfMeasurement}
		replaced := false
		if overwrite {
			for i := range s.lines {
				e := &s.lines[i]
				if e.Subscription == subscription && e.BillingPeriod == period && e.Day == s.day && e.SummaryKey == l.SummaryKey {
					*e, replaced = line, true
				}
			}
		}
		if !replaced {
			s.lines = append(s.lines, line)
		}
		content = append(content, map[string]any{"productId": l.ProductID, "quantity": *l.Quantity, "summaryKey": l.SummaryKey})
	}
	s.posts++
	if s.failWrite > 0 {
		s.failWrite--
		pax8JSON(w, http.StatusInternalServerError, map[string]any{"message": "Internal Server Error"})
		return
	}
	pax8JSON(w, http.StatusOK, map[string]any{"content": content, "page": map[string]any{"number": 0, "size": len(content),
		"totalElements": len(content), "totalPages": 1}})
}
