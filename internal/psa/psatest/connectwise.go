// SPDX-License-Identifier: BUSL-1.1

// Package psatest holds PSA stand-ins for tests, each written from its
// vendor's public API descriptions. They check what the vendor checks
// (credentials on every request, the documented request shapes) and keep
// the records a real system would, so a test can assert what landed where.
package psatest

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

// ConnectWiseRoot is the REST root path the stand-in serves under, as a
// cloud site's codebase does.
const ConnectWiseRoot = "/v4_6_release/apis/3.0"

// CWCompany is one company record.
type CWCompany struct {
	ID         int64
	Identifier string
	Name       string
	Deleted    bool
}

// CWAgreement is one agreement of a company.
type CWAgreement struct {
	ID        int64
	CompanyID int64
	TypeName  string
	Status    string
	Cancelled bool
}

// CWAddition is one agreement addition.
type CWAddition struct {
	ID            int64
	AgreementID   int64
	Product       string
	Quantity      float64
	BillCustomer  string
	EffectiveDate string
	Cancelled     bool
}

// ConnectWise is a ConnectWise PSA REST 3.0 stand-in: Basic
// companyId+publicKey:privateKey and the clientId header on every request,
// conditions queries (quoted strings, numbers, null, true/false joined by
// "and"), companies, agreements and agreement additions (POST, JSON Patch).
type ConnectWise struct {
	srv *httptest.Server

	mu         sync.Mutex
	companyID  string
	clientID   string
	authHeader string
	companies  []CWCompany
	agreements []CWAgreement
	additions  []CWAddition
	nextID     int64
	requests   int
	writes     int
	refused    int
	failWrite  int
	rejected   map[string]bool
	seen       []string
}

// NewConnectWise starts a stand-in for one PSA login company whose API
// member holds publicKey and privateKey, for the integration clientID.
func NewConnectWise(companyID, clientID, publicKey, privateKey string) *ConnectWise {
	s := &ConnectWise{
		companyID: companyID, clientID: clientID, nextID: 9000,
		authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte(companyID+"+"+publicKey+":"+privateKey)),
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *ConnectWise) Close() { s.srv.Close() }

// URL is the REST root a target's endpoint names.
func (s *ConnectWise) URL() string { return s.srv.URL + ConnectWiseRoot }

// AddCompany records a company.
func (s *ConnectWise) AddCompany(c CWCompany) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.companies = append(s.companies, c)
}

// AddAgreement records an agreement.
func (s *ConnectWise) AddAgreement(a CWAgreement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agreements = append(s.agreements, a)
}

// AddAddition records an addition an operator made by hand.
func (s *ConnectWise) AddAddition(a CWAddition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.additions = append(s.additions, a)
}

// Additions returns an agreement's additions.
func (s *ConnectWise) Additions(agreementID int64) []CWAddition {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []CWAddition
	for _, a := range s.additions {
		if a.AgreementID == agreementID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 503, as a write whose answer was lost.
func (s *ConnectWise) FailWritesAfterApplying(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrite = n
}

// RejectProduct makes the catalog refuse additions of a product, as for a
// product identifier the site's catalog does not have.
func (s *ConnectWise) RejectProduct(identifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejected == nil {
		s.rejected = map[string]bool{}
	}
	s.rejected[identifier] = true
}

// Counts reports authenticated requests, applied writes and refused
// (unauthenticated) requests.
func (s *ConnectWise) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

// Seen lists every authenticated request as "METHOD path?query".
func (s *ConnectWise) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func cwError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "errors": []any{}})
}

func cwJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *ConnectWise) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != s.authHeader || r.Header.Get("clientId") != s.clientID {
		s.refused++
		cwError(w, http.StatusUnauthorized, "Unauthorized", "the API member's credentials or the clientId were not accepted")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, ConnectWiseRoot)
	if !ok {
		cwError(w, http.StatusNotFound, "NotFound", "unknown codebase")
		return
	}
	s.requests++
	s.seen = append(s.seen, r.Method+" "+path+"?"+r.URL.RawQuery)
	conds, err := parseConditions(r.URL.Query().Get("conditions"))
	if err != nil {
		cwError(w, http.StatusBadRequest, "InvalidObject", err.Error())
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "company" && parts[1] == "companies":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		for _, c := range s.companies {
			if c.ID == id {
				cwJSON(w, http.StatusOK, cwCompanyJSON(c))
				return
			}
		}
		cwError(w, http.StatusNotFound, "NotFound", "Company not found")
	case r.Method == http.MethodGet && path == "/company/companies":
		out := []any{}
		for _, c := range s.companies {
			if conds.match(map[string]any{"identifier": c.Identifier, "id": c.ID}) {
				out = append(out, cwCompanyJSON(c))
			}
		}
		cwJSON(w, http.StatusOK, out)
	case r.Method == http.MethodGet && path == "/finance/agreements":
		out := []any{}
		for _, a := range s.agreements {
			if conds.match(map[string]any{"company/id": a.CompanyID, "type/name": a.TypeName, "cancelledFlag": a.Cancelled, "agreementStatus": a.Status}) {
				out = append(out, s.agreementJSON(a))
			}
		}
		cwJSON(w, http.StatusOK, out)
	case len(parts) >= 4 && parts[0] == "finance" && parts[1] == "agreements" && parts[3] == "additions":
		agreementID, _ := strconv.ParseInt(parts[2], 10, 64)
		if !s.hasAgreement(agreementID) {
			cwError(w, http.StatusNotFound, "NotFound", "Agreement not found")
			return
		}
		s.serveAdditions(w, r, agreementID, parts[4:], conds)
	default:
		cwError(w, http.StatusNotFound, "NotFound", "unknown resource")
	}
}

func (s *ConnectWise) serveAdditions(w http.ResponseWriter, r *http.Request, agreementID int64, rest []string, conds conditions) {
	switch {
	case r.Method == http.MethodGet && len(rest) == 0:
		out := []any{}
		for _, a := range s.additions {
			var cancelled any
			if a.Cancelled {
				cancelled = "2026-01-01T00:00:00Z"
			}
			if a.AgreementID == agreementID && conds.match(map[string]any{"product/identifier": a.Product, "cancelledDate": cancelled}) {
				out = append(out, cwAdditionJSON(a))
			}
		}
		cwJSON(w, http.StatusOK, out)
	case r.Method == http.MethodPost && len(rest) == 0:
		var body struct {
			Product struct {
				Identifier string `json:"identifier"`
			} `json:"product"`
			Quantity      *float64 `json:"quantity"`
			BillCustomer  string   `json:"billCustomer"`
			EffectiveDate string   `json:"effectiveDate"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Product.Identifier == "" || body.Quantity == nil {
			cwError(w, http.StatusBadRequest, "InvalidObject", "an addition needs its product and quantity")
			return
		}
		switch body.BillCustomer {
		case "Billable", "DoNotBill", "NoCharge":
		default:
			cwError(w, http.StatusBadRequest, "InvalidObject", "billCustomer is required")
			return
		}
		if body.EffectiveDate != "" {
			if _, err := time.Parse(time.RFC3339, body.EffectiveDate); err != nil {
				cwError(w, http.StatusBadRequest, "InvalidObject", "effectiveDate is not a date")
				return
			}
		}
		if s.rejected[body.Product.Identifier] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "InvalidObject", "message": "addition object is invalid",
				"errors": []any{map[string]any{"code": "InvalidField", "message": "Product " + body.Product.Identifier + " was not found", "resource": "addition", "field": "product"}}})
			return
		}
		s.nextID++
		a := CWAddition{ID: s.nextID, AgreementID: agreementID, Product: body.Product.Identifier, Quantity: *body.Quantity,
			BillCustomer: body.BillCustomer, EffectiveDate: body.EffectiveDate}
		s.additions = append(s.additions, a)
		s.writes++
		if s.lostAnswer(w) {
			return
		}
		cwJSON(w, http.StatusCreated, cwAdditionJSON(a))
	case r.Method == http.MethodPatch && len(rest) == 1:
		id, _ := strconv.ParseInt(rest[0], 10, 64)
		var ops []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&ops); err != nil || len(ops) == 0 {
			cwError(w, http.StatusBadRequest, "InvalidObject", "a patch is a JSON Patch operation list")
			return
		}
		for i := range s.additions {
			a := &s.additions[i]
			if a.ID != id || a.AgreementID != agreementID {
				continue
			}
			for _, op := range ops {
				if op.Op != "replace" || op.Path != "quantity" {
					cwError(w, http.StatusBadRequest, "InvalidObject", "this stand-in replaces quantity only")
					return
				}
				if err := json.Unmarshal(op.Value, &a.Quantity); err != nil {
					cwError(w, http.StatusBadRequest, "InvalidObject", "quantity is a number")
					return
				}
			}
			s.writes++
			if s.lostAnswer(w) {
				return
			}
			cwJSON(w, http.StatusOK, cwAdditionJSON(*a))
			return
		}
		cwError(w, http.StatusNotFound, "NotFound", "Addition not found")
	default:
		cwError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "unsupported")
	}
}

// lostAnswer answers 503 after a write took effect, when asked to.
func (s *ConnectWise) lostAnswer(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	cwError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "try again")
	return true
}

func (s *ConnectWise) hasAgreement(id int64) bool {
	for _, a := range s.agreements {
		if a.ID == id {
			return true
		}
	}
	return false
}

func cwCompanyJSON(c CWCompany) map[string]any {
	return map[string]any{"id": c.ID, "identifier": c.Identifier, "name": c.Name, "deletedFlag": c.Deleted}
}

func (s *ConnectWise) agreementJSON(a CWAgreement) map[string]any {
	company := map[string]any{"id": a.CompanyID}
	for _, c := range s.companies {
		if c.ID == a.CompanyID {
			company = map[string]any{"id": c.ID, "identifier": c.Identifier, "name": c.Name}
		}
	}
	return map[string]any{"id": a.ID, "name": fmt.Sprintf("agreement %d", a.ID), "type": map[string]any{"id": 1, "name": a.TypeName},
		"company": company, "agreementStatus": a.Status, "cancelledFlag": a.Cancelled}
}

func cwAdditionJSON(a CWAddition) map[string]any {
	var cancelled any
	if a.Cancelled {
		cancelled = "2026-01-01T00:00:00Z"
	}
	return map[string]any{"id": a.ID, "agreementId": a.AgreementID, "product": map[string]any{"id": 1, "identifier": a.Product},
		"quantity": a.Quantity, "billCustomer": a.BillCustomer, "effectiveDate": a.EffectiveDate, "cancelledDate": cancelled}
}

// conditions is a parsed conditions parameter: field=value clauses joined
// by "and", values quoted strings, integers, null, true or false.
type conditions map[string]any

func parseConditions(raw string) (conditions, error) {
	out := conditions{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, nil
	}
	for _, clause := range splitAnd(raw) {
		field, value, ok := strings.Cut(clause, "=")
		field, value = strings.TrimSpace(field), strings.TrimSpace(value)
		if !ok || field == "" || value == "" {
			return nil, fmt.Errorf("conditions clause %q is not field=value", clause)
		}
		switch {
		case strings.HasPrefix(value, `"`):
			if len(value) < 2 || !strings.HasSuffix(value, `"`) || strings.Contains(value[1:len(value)-1], `"`) {
				return nil, fmt.Errorf("conditions value %s is not one quoted string", value)
			}
			out[field] = value[1 : len(value)-1]
		case value == "null":
			out[field] = nil
		case value == "true" || value == "false":
			out[field] = value == "true"
		default:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("conditions value %s is not a string, number, boolean or null", value)
			}
			out[field] = n
		}
	}
	return out, nil
}

// splitAnd splits on " and " outside quotes.
func splitAnd(raw string) []string {
	var out []string
	inQuote, start := false, 0
	lower := strings.ToLower(raw)
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && strings.HasPrefix(lower[i:], " and ") {
			out = append(out, raw[start:i])
			start = i + len(" and ")
			i = start - 1
		}
	}
	return append(out, raw[start:])
}

// match reports whether a record's fields satisfy every clause. A clause on
// a field the record does not have never matches.
func (c conditions) match(record map[string]any) bool {
	for field, want := range c {
		got, ok := record[field]
		if !ok {
			return false
		}
		switch w := want.(type) {
		case nil:
			if got != nil {
				return false
			}
		case string:
			g, ok := got.(string)
			if !ok || !strings.EqualFold(g, w) {
				return false
			}
		case bool:
			if g, ok := got.(bool); !ok || g != w {
				return false
			}
		case int64:
			if g, ok := got.(int64); !ok || g != w {
				return false
			}
		}
	}
	return true
}
