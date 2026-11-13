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

// HaloClient is one client (customer).
type HaloClient struct {
	ID       int64
	Name     string
	Inactive bool
}

// HaloRecurringInvoice is one recurring invoice with its lines.
type HaloRecurringInvoice struct {
	ID          int64
	ClientID    int64
	InvoiceName string
	Lines       []HaloLine
}

// HaloLine is one recurring invoice line.
type HaloLine struct {
	ID       int64
	ItemID   int64
	QtyOrder float64
}

// HaloTicket is one ticket with its actions.
type HaloTicket struct {
	ID           int64
	ClientID     int64
	Summary      string
	Details      string
	TicketTypeID int64
	StatusID     int64
	Actions      []HaloAction
}

// HaloAction is one ticket action (note).
type HaloAction struct {
	ID             int64
	Note           string
	HiddenFromUser bool
}

// HaloPSA is a HaloPSA stand-in written from Halo's public descriptions:
// the OAuth2 client-credentials token at /auth/token (form-encoded,
// ?tenant= for a hosted tenant, scope all) and the /api resources as the
// published HaloAPI client calls them — writes are POSTs of JSON arrays and
// an update is a POST carrying the record's id; recurring invoice lines carry
// qty_order and change one per save; lists answer {"record_count", <key>}.
// Field names the published client does not show (summary, details,
// client_id, tickettype_id, status_id, ticket_id, note, hiddenfromuser,
// item_id, invoice_name, inactive) follow Halo's conventions; a live
// instance (Track B) settles them. Errors answer {"ClassName", "Message"}.
type HaloPSA struct {
	srv *httptest.Server

	mu           sync.Mutex
	clientID     string
	clientSecret string
	tenant       string
	issued       map[string]bool
	clients      []HaloClient
	invoices     []HaloRecurringInvoice
	tickets      []HaloTicket
	nextID       int64
	requests     int
	writes       int
	refused      int
	failWrite    int
	seen         []string
}

// NewHaloPSA starts an instance stand-in for one API application, for a
// hosted tenant (or "" for a self-hosted instance).
func NewHaloPSA(clientID, clientSecret, tenant string) *HaloPSA {
	s := &HaloPSA{clientID: clientID, clientSecret: clientSecret, tenant: tenant, issued: map[string]bool{}, nextID: 8000}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the stand-in.
func (s *HaloPSA) Close() { s.srv.Close() }

// URL is the instance root.
func (s *HaloPSA) URL() string { return s.srv.URL }

func (s *HaloPSA) with(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// AddClient records a client.
func (s *HaloPSA) AddClient(c HaloClient) { s.with(func() { s.clients = append(s.clients, c) }) }

// AddRecurringInvoice records a recurring invoice.
func (s *HaloPSA) AddRecurringInvoice(r HaloRecurringInvoice) {
	s.with(func() { s.invoices = append(s.invoices, r) })
}

// FailWritesAfterApplying makes the next n writes take effect and then
// answer 500, as a write whose answer was lost.
func (s *HaloPSA) FailWritesAfterApplying(n int) { s.with(func() { s.failWrite = n }) }

// RecurringInvoice returns a recurring invoice with its lines.
func (s *HaloPSA) RecurringInvoice(id int64) HaloRecurringInvoice {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.invoices {
		if r.ID == id {
			r.Lines = append([]HaloLine(nil), r.Lines...)
			return r
		}
	}
	return HaloRecurringInvoice{}
}

// Tickets returns every ticket with its actions.
func (s *HaloPSA) Tickets() []HaloTicket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HaloTicket, 0, len(s.tickets))
	for _, t := range s.tickets {
		t.Actions = append([]HaloAction(nil), t.Actions...)
		out = append(out, t)
	}
	return out
}

// Counts reports authenticated API requests, applied writes and refused
// requests (token or API).
func (s *HaloPSA) Counts() (requests, writes, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.writes, s.refused
}

// Seen lists every authenticated API request as "METHOD path?query".
func (s *HaloPSA) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func haloJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func haloError(w http.ResponseWriter, status int, message string) {
	haloJSON(w, status, map[string]any{"ClassName": "HaloException", "Message": message})
}

func (s *HaloPSA) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/auth/token" {
		s.token(w, r)
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.issued[bearer] {
		s.refused++
		haloError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/api/")
	if !ok {
		haloError(w, http.StatusNotFound, "Not found")
		return
	}
	s.requests++
	s.seen = append(s.seen, r.Method+" /api/"+path+"?"+r.URL.RawQuery)
	parts := strings.Split(strings.ToLower(strings.Trim(path, "/")), "/")
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "client":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		for _, c := range s.clients {
			if c.ID == id {
				haloJSON(w, http.StatusOK, map[string]any{"id": c.ID, "name": c.Name, "inactive": c.Inactive})
				return
			}
		}
		haloError(w, http.StatusNotFound, "Client not found")
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "recurringinvoice":
		clientID, _ := strconv.ParseInt(q.Get("client_id"), 10, 64)
		withLines := q.Get("includelines") == "true"
		list := []any{}
		for _, inv := range s.invoices {
			if clientID == 0 || inv.ClientID == clientID {
				list = append(list, haloInvoiceJSON(inv, withLines))
			}
		}
		haloJSON(w, http.StatusOK, map[string]any{"record_count": len(list), "invoices": list})
	case r.Method == http.MethodPost && len(parts) == 1 && parts[0] == "recurringinvoice":
		s.saveRecurringInvoice(w, r)
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "tickets":
		clientID, _ := strconv.ParseInt(q.Get("client_id"), 10, 64)
		search := q.Get("search")
		list := []any{}
		for _, t := range s.tickets {
			if (clientID == 0 || t.ClientID == clientID) && (search == "" || strings.Contains(t.Summary, search)) {
				list = append(list, haloTicketJSON(t))
			}
		}
		haloJSON(w, http.StatusOK, map[string]any{"record_count": len(list), "tickets": list})
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "tickets":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		for _, t := range s.tickets {
			if t.ID == id {
				haloJSON(w, http.StatusOK, haloTicketJSON(t))
				return
			}
		}
		haloError(w, http.StatusNotFound, "Ticket not found")
	case r.Method == http.MethodPost && len(parts) == 1 && parts[0] == "tickets":
		s.saveTicket(w, r)
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "actions":
		ticketID, err := strconv.ParseInt(q.Get("ticket_id"), 10, 64)
		if err != nil {
			haloError(w, http.StatusBadRequest, "ticket_id is required")
			return
		}
		list := []any{}
		for _, t := range s.tickets {
			if t.ID == ticketID {
				for _, a := range t.Actions {
					list = append(list, map[string]any{"id": a.ID, "ticket_id": t.ID, "note": a.Note, "hiddenfromuser": a.HiddenFromUser})
				}
			}
		}
		haloJSON(w, http.StatusOK, map[string]any{"record_count": len(list), "actions": list})
	case r.Method == http.MethodPost && len(parts) == 1 && parts[0] == "actions":
		var body []struct {
			TicketID       int64  `json:"ticket_id"`
			Note           string `json:"note"`
			HiddenFromUser bool   `json:"hiddenfromuser"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || strings.TrimSpace(body[0].Note) == "" {
			haloError(w, http.StatusBadRequest, "an action is posted as an array of one with ticket_id and note")
			return
		}
		for i := range s.tickets {
			if s.tickets[i].ID == body[0].TicketID {
				s.nextID++
				s.tickets[i].Actions = append(s.tickets[i].Actions, HaloAction{ID: s.nextID, Note: body[0].Note, HiddenFromUser: body[0].HiddenFromUser})
				s.writes++
				if s.lost(w) {
					return
				}
				haloJSON(w, http.StatusCreated, map[string]any{"id": s.nextID, "ticket_id": body[0].TicketID})
				return
			}
		}
		haloError(w, http.StatusBadRequest, "ticket_id does not exist")
	default:
		haloError(w, http.StatusNotFound, "Not found")
	}
}

// token is the client-credentials exchange.
func (s *HaloPSA) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		haloError(w, http.StatusBadRequest, "the token request is a form post")
		return
	}
	if err := r.ParseForm(); err != nil {
		haloError(w, http.StatusBadRequest, "unreadable form")
		return
	}
	if r.URL.Query().Get("tenant") != s.tenant || r.PostForm.Get("grant_type") != "client_credentials" ||
		r.PostForm.Get("client_id") != s.clientID || r.PostForm.Get("client_secret") != s.clientSecret || r.PostForm.Get("scope") != "all" {
		s.refused++
		haloJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client"})
		return
	}
	s.nextID++
	token := "halo-access-" + strconv.FormatInt(s.nextID, 10)
	s.issued[token] = true
	haloJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
}

func (s *HaloPSA) saveRecurringInvoice(w http.ResponseWriter, r *http.Request) {
	var body []struct {
		ID    int64 `json:"id"`
		Lines []struct {
			ID       int64           `json:"id"`
			ItemID   int64           `json:"item_id"`
			QtyOrder json.RawMessage `json:"qty_order"`
		} `json:"lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body[0].ID == 0 {
		haloError(w, http.StatusBadRequest, "a recurring invoice is posted as an array of one with its id")
		return
	}
	if len(body[0].Lines) != 1 {
		haloError(w, http.StatusBadRequest, "change one line per save")
		return
	}
	change := body[0].Lines[0]
	qty, err := strconv.ParseFloat(string(change.QtyOrder), 64)
	if err != nil {
		haloError(w, http.StatusBadRequest, "qty_order is a number")
		return
	}
	for i := range s.invoices {
		inv := &s.invoices[i]
		if inv.ID != body[0].ID {
			continue
		}
		if change.ID == 0 {
			if change.ItemID == 0 {
				haloError(w, http.StatusBadRequest, "a new line names its item_id")
				return
			}
			s.nextID++
			inv.Lines = append(inv.Lines, HaloLine{ID: s.nextID, ItemID: change.ItemID, QtyOrder: qty})
		} else {
			found := false
			for j := range inv.Lines {
				if inv.Lines[j].ID == change.ID {
					inv.Lines[j].QtyOrder, found = qty, true
				}
			}
			if !found {
				haloError(w, http.StatusBadRequest, "line does not exist")
				return
			}
		}
		s.writes++
		if s.lost(w) {
			return
		}
		haloJSON(w, http.StatusCreated, haloInvoiceJSON(*inv, true))
		return
	}
	haloError(w, http.StatusBadRequest, "recurring invoice does not exist")
}

func (s *HaloPSA) saveTicket(w http.ResponseWriter, r *http.Request) {
	var body []struct {
		ID           int64  `json:"id"`
		Summary      string `json:"summary"`
		Details      string `json:"details"`
		ClientID     int64  `json:"client_id"`
		TicketTypeID int64  `json:"tickettype_id"`
		StatusID     int64  `json:"status_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 {
		haloError(w, http.StatusBadRequest, "a ticket is posted as an array of one")
		return
	}
	b := body[0]
	if b.ID != 0 {
		for i := range s.tickets {
			if s.tickets[i].ID == b.ID {
				if b.StatusID != 0 {
					s.tickets[i].StatusID = b.StatusID
				}
				s.writes++
				if s.lost(w) {
					return
				}
				haloJSON(w, http.StatusCreated, haloTicketJSON(s.tickets[i]))
				return
			}
		}
		haloError(w, http.StatusBadRequest, "ticket does not exist")
		return
	}
	known := false
	for _, c := range s.clients {
		known = known || (c.ID == b.ClientID && !c.Inactive)
	}
	if strings.TrimSpace(b.Summary) == "" || !known || b.TicketTypeID == 0 {
		haloError(w, http.StatusBadRequest, "check client_id, summary and tickettype_id")
		return
	}
	s.nextID++
	status := b.StatusID
	if status == 0 {
		status = 1
	}
	t := HaloTicket{ID: s.nextID, ClientID: b.ClientID, Summary: b.Summary, Details: b.Details, TicketTypeID: b.TicketTypeID, StatusID: status}
	s.tickets = append(s.tickets, t)
	s.writes++
	if s.lost(w) {
		return
	}
	haloJSON(w, http.StatusCreated, haloTicketJSON(t))
}

func (s *HaloPSA) lost(w http.ResponseWriter) bool {
	if s.failWrite <= 0 {
		return false
	}
	s.failWrite--
	haloError(w, http.StatusInternalServerError, "An error occurred")
	return true
}

func haloInvoiceJSON(inv HaloRecurringInvoice, withLines bool) map[string]any {
	out := map[string]any{"id": inv.ID, "client_id": inv.ClientID, "invoice_name": inv.InvoiceName}
	if withLines {
		lines := []any{}
		for _, l := range inv.Lines {
			lines = append(lines, map[string]any{"id": l.ID, "item_id": l.ItemID, "qty_order": l.QtyOrder})
		}
		out["lines"] = lines
	}
	return out
}

func haloTicketJSON(t HaloTicket) map[string]any {
	return map[string]any{"id": t.ID, "client_id": t.ClientID, "summary": t.Summary, "tickettype_id": t.TicketTypeID, "status_id": t.StatusID}
}
