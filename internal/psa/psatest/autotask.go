// SPDX-License-Identifier: BUSL-1.1

package psatest

import (
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

// AutotaskRoot is the REST root path of a zone.
const AutotaskRoot = "/atservicesrest/v1.0"

// ATCompany is one company.
type ATCompany struct {
	ID     int64
	Name   string
	Active bool
}

// ATContract is one contract.
type ATContract struct {
	ID        int64
	CompanyID int64
	Name      string
	Type      int64
	Start     time.Time
	End       time.Time
}

// ATContractService is one service on a contract.
type ATContractService struct {
	ID         int64
	ContractID int64
	ServiceID  int64
}

// ATAdjustment is one unit adjustment of a contract service.
type ATAdjustment struct {
	ID                int64
	ContractServiceID int64
	UnitChange        int64
	Effective         time.Time
}

// ATTicket is one ticket.
type ATTicket struct {
	ID          int64
	CompanyID   int64
	Title       string
	Description string
	ExternalID  string
	Status      int64
	Priority    int64
	QueueID     int64
}

// ATNote is one ticket note.
type ATNote struct {
	ID          int64
	TicketID    int64
	Title       string
	Description string
	NoteType    int64
	Publish     int64
}

// Autotask is an Autotask PSA REST v1.0 stand-in written from the public
// entity reference: UserName, Secret and ApiIntegrationcode on every
// request; POST /{Entity}/query with an and-filter of eq/lt/lte/gt/gte
// clauses answering {"items", "pageDetails"} (with a GET next page past
// PageSize); companies; Recurring Service contracts; contract services whose
// units per monthly period derive from create-only adjustments; tickets and
// ticket notes; {"itemId"} on create and {"errors": [...]} on failure.
type Autotask struct {
	srv *httptest.Server

	mu          sync.Mutex
	username    string
	secret      string
	code        string
	companies   []ATCompany
	contracts   []ATContract
	services    []ATContractService
	adjustments []ATAdjustment
	tickets     []ATTicket
	notes       []ATNote
	nextID      int64
	requests    int
	writes      int
	refused     int
	failWrite   int
	pageSize    int
	pages       map[string]atPage
	seen        []string
}

// NewAutotask starts a zone stand-in for one API user.
func NewAutotask(username, secret, integrationCode string) *Autotask {
	s := &Autotask{username: username, secret: secret, code: integrationCode, nextID: 7000, pageSize: 500, pages: map[string]atPage{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *Autotask) Close() { s.srv.Close() }

// URL is the zone's REST root.
func (s *Autotask) URL() string { return s.srv.URL + AutotaskRoot }

// AddCompany records a company.
func (s *Autotask) AddCompany(c ATCompany) { s.with(func() { s.companies = append(s.companies, c) }) }

// AddContract records a contract.
func (s *Autotask) AddContract(c ATContract) { s.with(func() { s.contracts = append(s.contracts, c) }) }

// AddContractService records a service on a contract.
func (s *Autotask) AddContractService(c ATContractService) {
	s.with(func() { s.services = append(s.services, c) })
}

// SetPageSize makes queries answer at most n items per page.
func (s *Autotask) SetPageSize(n int) { s.with(func() { s.pageSize = n }) }

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *Autotask) FailWritesAfterApplying(n int) { s.with(func() { s.failWrite = n }) }

func (s *Autotask) with(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// Units is a contract service's units in force at a date.
func (s *Autotask) Units(contractServiceID int64, at time.Time) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unitsAt(contractServiceID, at)
}

func (s *Autotask) unitsAt(contractServiceID int64, at time.Time) int64 {
	var units int64
	for _, a := range s.adjustments {
		if a.ContractServiceID == contractServiceID && !a.Effective.After(at) {
			units += a.UnitChange
		}
	}
	return units
}

// Adjustments returns every adjustment made.
func (s *Autotask) Adjustments() []ATAdjustment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ATAdjustment(nil), s.adjustments...)
}

// Tickets returns every ticket.
func (s *Autotask) Tickets() []ATTicket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ATTicket(nil), s.tickets...)
}

// Notes returns every ticket note.
func (s *Autotask) Notes() []ATNote {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ATNote(nil), s.notes...)
}

// Counts reports authenticated requests, applied writes and refused
// requests.
func (s *Autotask) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

// Seen lists every authenticated request as "METHOD path".
func (s *Autotask) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func atJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func atError(w http.ResponseWriter, status int, message string) {
	atJSON(w, status, map[string]any{"errors": []string{message}})
}

func (s *Autotask) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("UserName") != s.username || r.Header.Get("Secret") != s.secret || r.Header.Get("ApiIntegrationcode") != s.code {
		s.refused++
		atError(w, http.StatusUnauthorized, "the API user, secret or tracking identifier was not accepted")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, AutotaskRoot)
	if !ok {
		atError(w, http.StatusNotFound, "unknown zone path")
		return
	}
	s.requests++
	s.seen = append(s.seen, r.Method+" "+path)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "query" && parts[2] == "next":
		s.nextPage(w, r.URL.Query().Get("paging"))
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "query":
		s.query(w, r, parts[0])
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "Companies":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		for _, c := range s.companies {
			if c.ID == id {
				atJSON(w, http.StatusOK, map[string]any{"item": map[string]any{"id": c.ID, "companyName": c.Name, "isActive": c.Active}})
				return
			}
		}
		atJSON(w, http.StatusOK, map[string]any{"item": nil})
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "Tickets":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		for _, t := range s.tickets {
			if t.ID == id {
				atJSON(w, http.StatusOK, map[string]any{"item": atTicketJSON(t)})
				return
			}
		}
		atJSON(w, http.StatusOK, map[string]any{"item": nil})
	case r.Method == http.MethodPost && path == "/ContractServiceAdjustments":
		var body struct {
			ContractServiceID int64           `json:"contractServiceID"`
			UnitChange        json.RawMessage `json:"unitChange"`
			EffectiveDate     string          `json:"effectiveDate"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			atError(w, http.StatusBadRequest, "the request body is not an adjustment")
			return
		}
		change, err := strconv.ParseInt(string(body.UnitChange), 10, 64)
		if err != nil {
			atError(w, http.StatusInternalServerError, "unitChange must be a whole number")
			return
		}
		effective, err := time.Parse(time.RFC3339, body.EffectiveDate)
		if err != nil {
			atError(w, http.StatusInternalServerError, "effectiveDate is required")
			return
		}
		if !s.hasService(body.ContractServiceID) {
			atError(w, http.StatusInternalServerError, "contractServiceID does not exist")
			return
		}
		s.nextID++
		s.adjustments = append(s.adjustments, ATAdjustment{ID: s.nextID, ContractServiceID: body.ContractServiceID, UnitChange: change, Effective: effective})
		s.created(w)
	case r.Method == http.MethodPost && path == "/Tickets":
		var body struct {
			CompanyID   int64  `json:"companyID"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Status      int64  `json:"status"`
			Priority    int64  `json:"priority"`
			QueueID     int64  `json:"queueID"`
			ExternalID  string `json:"externalID"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CompanyID == 0 || strings.TrimSpace(body.Title) == "" ||
			len([]rune(body.Title)) > 255 || body.Status == 0 || body.Priority == 0 || len(body.ExternalID) > 50 {
			atError(w, http.StatusInternalServerError, "a ticket needs companyID, a title of at most 255 characters, status and priority")
			return
		}
		if !s.hasCompany(body.CompanyID) {
			atError(w, http.StatusInternalServerError, "companyID does not exist")
			return
		}
		s.nextID++
		s.tickets = append(s.tickets, ATTicket{ID: s.nextID, CompanyID: body.CompanyID, Title: body.Title, Description: body.Description,
			ExternalID: body.ExternalID, Status: body.Status, Priority: body.Priority, QueueID: body.QueueID})
		s.created(w)
	case r.Method == http.MethodPatch && path == "/Tickets":
		var body struct {
			ID     int64 `json:"id"`
			Status int64 `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 || body.Status == 0 {
			atError(w, http.StatusInternalServerError, "a ticket update names the ticket and its status")
			return
		}
		for i := range s.tickets {
			if s.tickets[i].ID == body.ID {
				s.tickets[i].Status = body.Status
				s.writes++
				if s.lost(w) {
					return
				}
				atJSON(w, http.StatusOK, map[string]any{"itemId": body.ID})
				return
			}
		}
		atError(w, http.StatusNotFound, "ticket not found")
	case r.Method == http.MethodPost && path == "/TicketNotes":
		var body struct {
			TicketID    int64  `json:"ticketID"`
			NoteType    int64  `json:"noteType"`
			Publish     int64  `json:"publish"`
			Title       string `json:"title"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TicketID == 0 || body.NoteType == 0 || body.Publish == 0 ||
			strings.TrimSpace(body.Description) == "" || len(body.Description) > 32000 || len([]rune(body.Title)) > 250 {
			atError(w, http.StatusInternalServerError, "a note needs ticketID, noteType, publish and a description")
			return
		}
		s.nextID++
		s.notes = append(s.notes, ATNote{ID: s.nextID, TicketID: body.TicketID, Title: body.Title, Description: body.Description,
			NoteType: body.NoteType, Publish: body.Publish})
		s.created(w)
	default:
		atError(w, http.StatusNotFound, "unknown resource")
	}
}

func (s *Autotask) created(w http.ResponseWriter) {
	s.writes++
	if s.lost(w) {
		return
	}
	atJSON(w, http.StatusOK, map[string]any{"itemId": s.nextID})
}

func (s *Autotask) lost(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	atError(w, http.StatusInternalServerError, "the request timed out")
	return true
}

func (s *Autotask) hasCompany(id int64) bool {
	for _, c := range s.companies {
		if c.ID == id {
			return true
		}
	}
	return false
}

func (s *Autotask) hasService(id int64) bool {
	for _, c := range s.services {
		if c.ID == id {
			return true
		}
	}
	return false
}

func atTicketJSON(t ATTicket) map[string]any {
	return map[string]any{"id": t.ID, "companyID": t.CompanyID, "title": t.Title, "externalID": t.ExternalID, "status": t.Status,
		"priority": t.Priority, "queueID": t.QueueID}
}

type atClause struct {
	Op    string          `json:"op"`
	Field string          `json:"field"`
	Value json.RawMessage `json:"value"`
}

func (s *Autotask) query(w http.ResponseWriter, r *http.Request, entity string) {
	var body struct {
		Filter []atClause `json:"filter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Filter) == 0 {
		atError(w, http.StatusInternalServerError, "a query needs a filter")
		return
	}
	var records []map[string]any
	switch entity {
	case "Contracts":
		for _, c := range s.contracts {
			records = append(records, map[string]any{"id": c.ID, "companyID": c.CompanyID, "contractName": c.Name, "contractType": c.Type,
				"startDate": c.Start.Format(time.RFC3339), "endDate": c.End.Format(time.RFC3339)})
		}
	case "ContractServices":
		for _, c := range s.services {
			records = append(records, map[string]any{"id": c.ID, "contractID": c.ContractID, "serviceID": c.ServiceID})
		}
	case "ContractServiceUnits":
		at, ok := atDateClause(body.Filter)
		if !ok {
			atError(w, http.StatusInternalServerError, "this stand-in answers units for one date (startDate lte, endDate gt)")
			return
		}
		start := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		for _, c := range s.services {
			if units := s.unitsAt(c.ID, at); units != 0 {
				records = append(records, map[string]any{"contractServiceID": c.ID, "contractID": c.ContractID, "serviceID": c.ServiceID,
					"startDate": start.Format(time.RFC3339), "endDate": start.AddDate(0, 1, 0).Format(time.RFC3339), "units": units})
			}
		}
	case "Tickets":
		for _, t := range s.tickets {
			records = append(records, atTicketJSON(t))
		}
	case "TicketNotes":
		for _, n := range s.notes {
			records = append(records, map[string]any{"id": n.ID, "ticketID": n.TicketID, "title": n.Title, "description": n.Description})
		}
	default:
		atError(w, http.StatusNotFound, "unknown entity "+entity)
		return
	}
	var items []any
	for _, rec := range records {
		ok, err := atMatch(rec, body.Filter)
		if err != nil {
			atError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ok {
			items = append(items, rec)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return fmt.Sprint(items[i].(map[string]any)["id"]) < fmt.Sprint(items[j].(map[string]any)["id"])
	})
	s.page(w, entity, items)
}

func (s *Autotask) page(w http.ResponseWriter, entity string, items []any) {
	if items == nil {
		items = []any{}
	}
	next := any(nil)
	if len(items) > s.pageSize {
		token := strconv.FormatInt(int64(len(s.pages)+1), 10)
		s.pages[token] = atPage{entity: entity, items: items[s.pageSize:]}
		items = items[:s.pageSize]
		next = s.srv.URL + AutotaskRoot + "/" + entity + "/query/next?paging=" + token
	}
	atJSON(w, http.StatusOK, map[string]any{"items": items, "pageDetails": map[string]any{"count": len(items), "requestCount": s.pageSize,
		"prevPageUrl": nil, "nextPageUrl": next}})
}

func (s *Autotask) nextPage(w http.ResponseWriter, token string) {
	rest, ok := s.pages[token]
	if !ok {
		atError(w, http.StatusNotFound, "unknown page")
		return
	}
	delete(s.pages, token)
	s.page(w, rest.entity, rest.items)
}

// atPage is the rest of a query's items past a page.
type atPage struct {
	entity string
	items  []any
}

func atDateClause(filters []atClause) (time.Time, bool) {
	var at time.Time
	found := false
	for _, f := range filters {
		if f.Field == "startDate" && f.Op == "lte" {
			var raw string
			if json.Unmarshal(f.Value, &raw) != nil {
				return at, false
			}
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return at, false
			}
			at, found = t, true
		}
	}
	return at, found
}

// atMatch applies an and-filter to one record. Dates compare as times,
// numbers as numbers, strings exactly.
func atMatch(rec map[string]any, filters []atClause) (bool, error) {
	for _, f := range filters {
		got, ok := rec[f.Field]
		if !ok {
			if f.Field == "endDate" || f.Field == "startDate" {
				continue
			}
			return false, fmt.Errorf("unknown field %s", f.Field)
		}
		var want any
		if err := json.Unmarshal(f.Value, &want); err != nil {
			return false, fmt.Errorf("bad value for %s", f.Field)
		}
		cmp, err := atCompare(got, want)
		if err != nil {
			return false, fmt.Errorf("%s: %v", f.Field, err)
		}
		var pass bool
		switch f.Op {
		case "eq":
			pass = cmp == 0
		case "lt":
			pass = cmp < 0
		case "lte":
			pass = cmp <= 0
		case "gt":
			pass = cmp > 0
		case "gte":
			pass = cmp >= 0
		default:
			return false, fmt.Errorf("unsupported op %s", f.Op)
		}
		if !pass {
			return false, nil
		}
	}
	return true, nil
}

func atCompare(got, want any) (int, error) {
	switch g := got.(type) {
	case int64:
		w, ok := want.(float64)
		if !ok {
			return 0, fmt.Errorf("want a number")
		}
		switch {
		case float64(g) < w:
			return -1, nil
		case float64(g) > w:
			return 1, nil
		}
		return 0, nil
	case string:
		w, ok := want.(string)
		if !ok {
			return 0, fmt.Errorf("want a string")
		}
		gt, gErr := time.Parse(time.RFC3339, g)
		wt, wErr := time.Parse(time.RFC3339, w)
		if gErr == nil && wErr == nil {
			return gt.Compare(wt), nil
		}
		return strings.Compare(g, w), nil
	}
	return 0, fmt.Errorf("unsupported field type")
}
