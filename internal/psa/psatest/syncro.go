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

// SyncroRoot is the API root path of an account.
const SyncroRoot = "/api/v1"

// SyncroCustomer is one customer.
type SyncroCustomer struct {
	ID           int64
	BusinessName string
	Disabled     bool
}

// SyncroSchedule is one recurring invoice schedule with its lines.
type SyncroSchedule struct {
	ID         int64
	CustomerID int64
	Name       string
	Paused     bool
	Status     string
	Lines      []SyncroLine
}

// SyncroLine is one schedule line item.
type SyncroLine struct {
	ID        int64
	ProductID *int64
	Quantity  float64
	Name      string
}

// SyncroTicket is one ticket with its comments.
type SyncroTicket struct {
	ID          int64
	CustomerID  int64
	Subject     string
	ProblemType string
	Status      string
	Comments    []SyncroComment
}

// SyncroComment is one ticket comment.
type SyncroComment struct {
	ID         int64
	Subject    string
	Body       string
	Hidden     bool
	DoNotEmail bool
}

// Syncro is a Syncro API v1 stand-in written from the public OpenAPI
// description: a bearer token on every request; customers; recurring
// invoice schedules whose line items are added (add_line_item) and updated
// (PUT line_items/{id}) and whose quantities read back as strings such as
// "3.0"; tickets created with their first comment and searched by
// customer_id and query; ticket comments read in pages and added one by one;
// {"error": "..."} on a refusal; page metadata in "meta".
type Syncro struct {
	srv *httptest.Server

	mu        sync.Mutex
	token     string
	customers []SyncroCustomer
	schedules []SyncroSchedule
	tickets   []SyncroTicket
	nextID    int64
	requests  int
	writes    int
	refused   int
	failWrite int
	pageSize  int
	seen      []string
}

// NewSyncro starts an account stand-in accepting one API token.
func NewSyncro(token string) *Syncro {
	s := &Syncro{token: token, nextID: 5000, pageSize: 25}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Syncro) Close() { s.srv.Close() }

// URL is the account's API root.
func (s *Syncro) URL() string { return s.srv.URL + SyncroRoot }

func (s *Syncro) with(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// AddCustomer records a customer.
func (s *Syncro) AddCustomer(c SyncroCustomer) {
	s.with(func() { s.customers = append(s.customers, c) })
}

// AddSchedule records a schedule.
func (s *Syncro) AddSchedule(sc SyncroSchedule) {
	s.with(func() { s.schedules = append(s.schedules, sc) })
}

// SetPageSize makes lists answer at most n records per page.
func (s *Syncro) SetPageSize(n int) { s.with(func() { s.pageSize = n }) }

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *Syncro) FailWritesAfterApplying(n int) { s.with(func() { s.failWrite = n }) }

// Schedule returns a schedule with its lines.
func (s *Syncro) Schedule(id int64) SyncroSchedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.schedules {
		if sc.ID == id {
			sc.Lines = append([]SyncroLine(nil), sc.Lines...)
			return sc
		}
	}
	return SyncroSchedule{}
}

// Tickets returns every ticket with its comments.
func (s *Syncro) Tickets() []SyncroTicket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SyncroTicket, 0, len(s.tickets))
	for _, t := range s.tickets {
		t.Comments = append([]SyncroComment(nil), t.Comments...)
		out = append(out, t)
	}
	return out
}

// Counts reports authenticated requests, applied writes and refused
// requests.
func (s *Syncro) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

// Seen lists every authenticated request as "METHOD path?query".
func (s *Syncro) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func syncroJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func syncroError(w http.ResponseWriter, status int, message string) {
	syncroJSON(w, status, map[string]any{"error": message})
}

func (s *Syncro) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+s.token || r.URL.Query().Get("api_key") != "" {
		s.refused++
		syncroError(w, http.StatusUnauthorized, "Not authorized")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, SyncroRoot)
	if !ok {
		syncroError(w, http.StatusNotFound, "Not found")
		return
	}
	s.requests++
	s.seen = append(s.seen, r.Method+" "+path+"?"+r.URL.RawQuery)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "customers":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		for _, c := range s.customers {
			if c.ID == id {
				syncroJSON(w, http.StatusOK, map[string]any{"customer": map[string]any{"id": c.ID, "business_name": c.BusinessName, "disabled": c.Disabled}})
				return
			}
		}
		syncroError(w, http.StatusNotFound, "Not found")
	case r.Method == http.MethodGet && path == "/schedules":
		customerID, _ := strconv.ParseInt(q.Get("customer_id"), 10, 64)
		var all []any
		for _, sc := range s.schedules {
			if customerID == 0 || sc.CustomerID == customerID {
				all = append(all, syncroScheduleJSON(sc, false))
			}
		}
		s.list(w, "schedules", all, page)
	case len(parts) >= 2 && parts[0] == "schedules":
		s.serveSchedule(w, r, parts[1:])
	case r.Method == http.MethodGet && path == "/tickets":
		customerID, _ := strconv.ParseInt(q.Get("customer_id"), 10, 64)
		query := q.Get("query")
		var all []any
		for _, t := range s.tickets {
			if (customerID == 0 || t.CustomerID == customerID) && (query == "" || strings.Contains(t.Subject, query) || strconv.FormatInt(t.ID, 10) == query) {
				all = append(all, syncroTicketJSON(t))
			}
		}
		s.list(w, "tickets", all, page)
	case r.Method == http.MethodPost && path == "/tickets":
		var body struct {
			CustomerID  int64  `json:"customer_id"`
			Subject     string `json:"subject"`
			ProblemType string `json:"problem_type"`
			Status      string `json:"status"`
			Comments    []struct {
				Subject    string `json:"subject"`
				Body       string `json:"body"`
				Hidden     bool   `json:"hidden"`
				DoNotEmail bool   `json:"do_not_email"`
			} `json:"comments_attributes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CustomerID == 0 {
			syncroError(w, http.StatusUnprocessableEntity, "Customer required field")
			return
		}
		if strings.TrimSpace(body.Subject) == "" || body.ProblemType == "" || !s.hasCustomer(body.CustomerID) {
			syncroError(w, http.StatusUnprocessableEntity, "Subject, problem type and an existing customer are required")
			return
		}
		s.nextID++
		t := SyncroTicket{ID: s.nextID, CustomerID: body.CustomerID, Subject: body.Subject, ProblemType: body.ProblemType, Status: body.Status}
		if t.Status == "" {
			t.Status = "New"
		}
		for _, c := range body.Comments {
			s.nextID++
			t.Comments = append(t.Comments, SyncroComment{ID: s.nextID, Subject: c.Subject, Body: c.Body, Hidden: c.Hidden, DoNotEmail: c.DoNotEmail})
		}
		s.tickets = append(s.tickets, t)
		s.writes++
		if s.lost(w) {
			return
		}
		syncroJSON(w, http.StatusOK, map[string]any{"ticket": syncroTicketJSON(t)})
	case len(parts) >= 2 && parts[0] == "tickets":
		s.serveTicket(w, r, parts[1:], page)
	default:
		syncroError(w, http.StatusNotFound, "Not found")
	}
}

func (s *Syncro) serveSchedule(w http.ResponseWriter, r *http.Request, rest []string) {
	id, _ := strconv.ParseInt(rest[0], 10, 64)
	var sc *SyncroSchedule
	for i := range s.schedules {
		if s.schedules[i].ID == id {
			sc = &s.schedules[i]
		}
	}
	if sc == nil {
		syncroError(w, http.StatusNotFound, "Not found")
		return
	}
	switch {
	case r.Method == http.MethodGet && len(rest) == 1:
		syncroJSON(w, http.StatusOK, map[string]any{"schedule": syncroScheduleJSON(*sc, true)})
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "add_line_item":
		var body struct {
			ProductID *int64          `json:"product_id"`
			Quantity  json.RawMessage `json:"quantity"`
			Name      string          `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			syncroError(w, http.StatusUnprocessableEntity, "Name can't be blank")
			return
		}
		quantity, err := strconv.ParseFloat(strings.Trim(string(body.Quantity), `"`), 64)
		if err != nil {
			syncroError(w, http.StatusUnprocessableEntity, "Quantity is not a number")
			return
		}
		s.nextID++
		line := SyncroLine{ID: s.nextID, ProductID: body.ProductID, Quantity: quantity, Name: body.Name}
		sc.Lines = append(sc.Lines, line)
		s.writes++
		if s.lost(w) {
			return
		}
		syncroJSON(w, http.StatusOK, map[string]any{"schedule_line_item": syncroLineJSON(line, sc.ID)})
	case r.Method == http.MethodPut && len(rest) == 3 && rest[1] == "line_items":
		lineID, _ := strconv.ParseInt(rest[2], 10, 64)
		var body struct {
			Quantity json.RawMessage `json:"quantity"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			syncroError(w, http.StatusUnprocessableEntity, "Invalid request")
			return
		}
		quantity, err := strconv.ParseFloat(strings.Trim(string(body.Quantity), `"`), 64)
		if err != nil {
			syncroError(w, http.StatusUnprocessableEntity, "Quantity is not a number")
			return
		}
		for i := range sc.Lines {
			if sc.Lines[i].ID == lineID {
				sc.Lines[i].Quantity = quantity
				s.writes++
				if s.lost(w) {
					return
				}
				syncroJSON(w, http.StatusOK, map[string]any{"schedule_line_item": syncroLineJSON(sc.Lines[i], sc.ID)})
				return
			}
		}
		syncroError(w, http.StatusNotFound, "Not found")
	default:
		syncroError(w, http.StatusNotFound, "Not found")
	}
}

func (s *Syncro) serveTicket(w http.ResponseWriter, r *http.Request, rest []string, page int) {
	id, _ := strconv.ParseInt(rest[0], 10, 64)
	var t *SyncroTicket
	for i := range s.tickets {
		if s.tickets[i].ID == id {
			t = &s.tickets[i]
		}
	}
	if t == nil {
		syncroError(w, http.StatusNotFound, "Not found")
		return
	}
	switch {
	case r.Method == http.MethodGet && len(rest) == 1:
		syncroJSON(w, http.StatusOK, map[string]any{"ticket": syncroTicketJSON(*t)})
	case r.Method == http.MethodPut && len(rest) == 1:
		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Status == "" {
			syncroError(w, http.StatusUnprocessableEntity, "Invalid request")
			return
		}
		t.Status = body.Status
		s.writes++
		if s.lost(w) {
			return
		}
		syncroJSON(w, http.StatusOK, map[string]any{"ticket": syncroTicketJSON(*t)})
	case r.Method == http.MethodGet && len(rest) == 2 && rest[1] == "comments":
		var all []any
		for _, c := range t.Comments {
			all = append(all, map[string]any{"id": c.ID, "ticket_id": t.ID, "subject": c.Subject, "body": c.Body, "hidden": c.Hidden})
		}
		s.list(w, "comments", all, page)
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "comment":
		var body struct {
			Subject    string `json:"subject"`
			Body       string `json:"body"`
			Hidden     bool   `json:"hidden"`
			DoNotEmail bool   `json:"do_not_email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Body) == "" {
			syncroError(w, http.StatusUnprocessableEntity, "Body can't be blank")
			return
		}
		s.nextID++
		t.Comments = append(t.Comments, SyncroComment{ID: s.nextID, Subject: body.Subject, Body: body.Body, Hidden: body.Hidden, DoNotEmail: body.DoNotEmail})
		s.writes++
		if s.lost(w) {
			return
		}
		syncroJSON(w, http.StatusOK, map[string]any{"comment": map[string]any{"id": s.nextID, "ticket_id": t.ID, "body": body.Body}})
	default:
		syncroError(w, http.StatusNotFound, "Not found")
	}
}

func (s *Syncro) list(w http.ResponseWriter, key string, all []any, page int) {
	if all == nil {
		all = []any{}
	}
	total := (len(all) + s.pageSize - 1) / s.pageSize
	if total == 0 {
		total = 1
	}
	from := (page - 1) * s.pageSize
	items := []any{}
	if from < len(all) {
		to := min(from+s.pageSize, len(all))
		items = all[from:to]
	}
	syncroJSON(w, http.StatusOK, map[string]any{key: items, "meta": map[string]any{"total_pages": total, "page": page, "per_page": s.pageSize}})
}

func (s *Syncro) lost(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	syncroError(w, http.StatusInternalServerError, "Something went wrong")
	return true
}

func (s *Syncro) hasCustomer(id int64) bool {
	for _, c := range s.customers {
		if c.ID == id && !c.Disabled {
			return true
		}
	}
	return false
}

func syncroScheduleJSON(sc SyncroSchedule, withLines bool) map[string]any {
	out := map[string]any{"id": sc.ID, "customer_id": sc.CustomerID, "name": sc.Name, "paused": sc.Paused,
		"subscription_status": sc.Status, "frequency": "Monthly"}
	lines := []any{}
	if withLines {
		for _, l := range sc.Lines {
			lines = append(lines, syncroLineJSON(l, sc.ID))
		}
	}
	out["lines"] = lines
	return out
}

func syncroLineJSON(l SyncroLine, scheduleID int64) map[string]any {
	var product any
	if l.ProductID != nil {
		product = *l.ProductID
	}
	return map[string]any{"id": l.ID, "schedule_id": scheduleID, "product_id": product, "name": l.Name,
		"quantity": strconv.FormatFloat(l.Quantity, 'f', 1, 64)}
}

func syncroTicketJSON(t SyncroTicket) map[string]any {
	return map[string]any{"id": t.ID, "number": t.ID, "customer_id": t.CustomerID, "subject": t.Subject, "problem_type": t.ProblemType,
		"status": t.Status, "properties": map[string]any{}}
}
