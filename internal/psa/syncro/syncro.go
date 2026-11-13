// SPDX-License-Identifier: BUSL-1.1

// Package syncro is the Syncro client of the Provider billing sync (MSP-6),
// written from Syncro's public OpenAPI description (api-docs.syncromsp.com):
// a bearer API token, customers, recurring invoice schedules and their line
// items, tickets and ticket comments.
//
// A customer's usage lands as the quantities of line items on its one
// recurring invoice schedule: one line per configured product, set (never
// added to), so a retry after a lost answer sets the same figure. Syncro
// tickets have no external reference field, so a ticket's reference rides at
// the end of its subject and is found again with the documented search.
package syncro

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/secrettext"
)

// Config is one Syncro account.
type Config struct {
	// BaseURL is the account's API root, https://{subdomain}.syncromsp.com/api/v1.
	BaseURL string
	// ScheduleName, when set, picks the schedule among the customer's
	// active recurring invoice schedules.
	ScheduleName string
	// Products maps a meter to the product whose line carries it.
	Products map[string]int64
	// Tickets is the problem type and statuses of alert tickets; nil when
	// the target opens no tickets.
	Tickets *TicketConfig
}

// TicketConfig is the problem type and the statuses alert tickets use.
type TicketConfig struct {
	ProblemType  string
	StatusNew    string
	StatusClosed string
}

// Credentials are the API token, borrowed for one call: the caller owns and
// wipes it.
type Credentials struct {
	APIToken []byte
}

// Client speaks to one Syncro account.
type Client struct {
	cfg   Config
	http  *http.Client
	creds Credentials
}

const (
	maxResponse = 1 << 20
	maxPages    = 20
	maxSubject  = 150
)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("syncro: the target needs an absolute API base URL")
	}
	if httpClient == nil || len(creds.APIToken) == 0 {
		return nil, errors.New("syncro: the target needs its API token")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

type customer struct {
	ID           int64  `json:"id"`
	BusinessName string `json:"business_name"`
	Disabled     bool   `json:"disabled"`
}

type schedule struct {
	ID                 int64      `json:"id"`
	CustomerID         int64      `json:"customer_id"`
	Name               string     `json:"name"`
	Paused             bool       `json:"paused"`
	SubscriptionStatus string     `json:"subscription_status"`
	Lines              []lineItem `json:"lines"`
}

type lineItem struct {
	ID        int64       `json:"id"`
	ProductID *int64      `json:"product_id"`
	Quantity  json.Number `json:"quantity"`
	Name      string      `json:"name"`
}

func (l lineItem) quantity() (float64, bool) {
	q, err := strconv.ParseFloat(l.Quantity.String(), 64)
	return q, err == nil
}

// PushUsage sets one customer's period as the quantities of its schedule's
// line items. Every lookup happens before the first write.
func (c *Client) PushUsage(ctx context.Context, p psa.UsagePeriod) (psa.UsageOutcome, error) {
	var out psa.UsageOutcome
	cu, err := c.customer(ctx, p.ExternalCompanyID)
	if err != nil {
		return out, err
	}
	sc, err := c.schedule(ctx, cu)
	if err != nil {
		return out, err
	}
	values := map[string]int64{}
	for _, line := range p.Lines {
		values[line.Meter] = line.Value
	}
	meters := make([]string, 0, len(c.cfg.Products))
	for meter := range c.cfg.Products {
		meters = append(meters, meter)
	}
	sort.Strings(meters)
	type planned struct {
		meter   string
		product int64
		value   int64
		line    *lineItem
	}
	plan := make([]planned, 0, len(meters))
	for _, meter := range meters {
		product := c.cfg.Products[meter]
		var found []lineItem
		for _, l := range sc.Lines {
			if l.ProductID != nil && *l.ProductID == product {
				found = append(found, l)
			}
		}
		if len(found) > 1 {
			return out, fmt.Errorf("%w: schedule %d has %d lines of product %d, want at most one", psa.ErrBeforeWrite, sc.ID, len(found), product)
		}
		entry := planned{meter: meter, product: product, value: values[meter]}
		if len(found) == 1 {
			if _, ok := found[0].quantity(); !ok {
				return out, fmt.Errorf("%w: schedule %d line %d has an unreadable quantity", psa.ErrBeforeWrite, sc.ID, found[0].ID)
			}
			entry.line = &found[0]
		}
		plan = append(plan, entry)
	}
	base := "/schedules/" + strconv.FormatInt(sc.ID, 10)
	for _, line := range plan {
		out.Set = append(out.Set, line.meter)
		switch line.line {
		case nil:
			body := map[string]any{"product_id": line.product, "quantity": line.value, "name": "trstctl " + strings.ReplaceAll(line.meter, "_", " ")}
			status, err := c.do(ctx, http.MethodPost, base+"/add_line_item", nil, body, nil, true)
			if err != nil {
				return out, err
			}
			out.Status = status
		default:
			current, _ := line.line.quantity()
			if current == float64(line.value) {
				if out.Status == 0 {
					out.Status = http.StatusOK
				}
				continue
			}
			status, err := c.do(ctx, http.MethodPut, base+"/line_items/"+strconv.FormatInt(line.line.ID, 10), nil,
				map[string]any{"quantity": line.value}, nil, true)
			if err != nil {
				return out, err
			}
			out.Status = status
		}
	}
	return out, nil
}

// customer resolves the mapped customer by its numeric ID; it must not be
// disabled.
func (c *Client) customer(ctx context.Context, external string) (customer, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(external), 10, 64)
	if err != nil || id <= 0 {
		return customer{}, fmt.Errorf("%w: a Syncro customer is mapped by its numeric ID, not %q", psa.ErrBeforeWrite, external)
	}
	var body struct {
		Customer *customer `json:"customer"`
	}
	status, err := c.do(ctx, http.MethodGet, "/customers/"+strconv.FormatInt(id, 10), nil, nil, &body, false)
	if status == http.StatusNotFound || (err == nil && body.Customer == nil) {
		return customer{}, fmt.Errorf("%w: Syncro has no customer %d", psa.ErrBeforeWrite, id)
	}
	if err != nil {
		return customer{}, err
	}
	if body.Customer.ID != id {
		return customer{}, fmt.Errorf("%w: Syncro answered customer %d for customer %d", psa.ErrBeforeWrite, body.Customer.ID, id)
	}
	if body.Customer.Disabled {
		return customer{}, fmt.Errorf("%w: Syncro customer %d is disabled", psa.ErrBeforeWrite, id)
	}
	return *body.Customer, nil
}

// schedule finds the customer's one active recurring invoice schedule (named
// ScheduleName when set) and reads its lines.
func (c *Client) schedule(ctx context.Context, cu customer) (schedule, error) {
	var active []schedule
	for page := 1; page <= maxPages; page++ {
		var body struct {
			Schedules []schedule `json:"schedules"`
			Meta      struct {
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
		}
		q := url.Values{"customer_id": {strconv.FormatInt(cu.ID, 10)}, "page": {strconv.Itoa(page)}}
		if _, err := c.do(ctx, http.MethodGet, "/schedules", q, nil, &body, false); err != nil {
			return schedule{}, err
		}
		for _, s := range body.Schedules {
			if s.CustomerID != cu.ID || s.Paused || (s.SubscriptionStatus != "" && s.SubscriptionStatus != "active") {
				continue
			}
			if c.cfg.ScheduleName != "" && s.Name != c.cfg.ScheduleName {
				continue
			}
			active = append(active, s)
		}
		if body.Meta.TotalPages <= page {
			break
		}
	}
	if len(active) != 1 {
		name := ""
		if c.cfg.ScheduleName != "" {
			name = " named " + strconv.Quote(c.cfg.ScheduleName)
		}
		return schedule{}, fmt.Errorf("%w: customer %d has %d active recurring invoice schedules%s, want exactly one", psa.ErrBeforeWrite, cu.ID, len(active), name)
	}
	var body struct {
		Schedule *schedule `json:"schedule"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/schedules/"+strconv.FormatInt(active[0].ID, 10), nil, nil, &body, false); err != nil {
		return schedule{}, err
	}
	if body.Schedule == nil || body.Schedule.ID != active[0].ID {
		return schedule{}, fmt.Errorf("%w: Syncro did not answer schedule %d", psa.ErrBeforeWrite, active[0].ID)
	}
	return *body.Schedule, nil
}

type ticket struct {
	ID         int64  `json:"id"`
	CustomerID int64  `json:"customer_id"`
	Subject    string `json:"subject"`
	Status     string `json:"status"`
}

type comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func referenceTag(reference string) string { return "[" + reference + "]" }

// OpenTicket opens the subject's ticket for the mapped customer, or finds
// the one a previous attempt opened (its subject ends with the reference),
// and returns its ID.
func (c *Client) OpenTicket(ctx context.Context, t psa.TicketOpen) (string, error) {
	if c.cfg.Tickets == nil {
		return "", fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	if t.Reference == "" || len(t.Reference) > 64 || strings.ContainsAny(t.Reference, "[] ") {
		return "", fmt.Errorf("%w: a ticket reference is 1-64 characters without brackets or spaces", psa.ErrBeforeWrite)
	}
	cu, err := c.customer(ctx, t.ExternalCompanyID)
	if err != nil {
		return "", err
	}
	tag := referenceTag(t.Reference)
	var found []ticket
	for page := 1; page <= maxPages; page++ {
		var body struct {
			Tickets []ticket `json:"tickets"`
			Meta    struct {
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
		}
		q := url.Values{"customer_id": {strconv.FormatInt(cu.ID, 10)}, "query": {t.Reference}, "page": {strconv.Itoa(page)}}
		if _, err := c.do(ctx, http.MethodGet, "/tickets", q, nil, &body, false); err != nil {
			return "", err
		}
		for _, tk := range body.Tickets {
			if tk.CustomerID == cu.ID && strings.HasSuffix(tk.Subject, tag) {
				found = append(found, tk)
			}
		}
		if body.Meta.TotalPages <= page {
			break
		}
	}
	switch len(found) {
	case 1:
		return strconv.FormatInt(found[0].ID, 10), nil
	case 0:
	default:
		return "", fmt.Errorf("%w: customer %d has %d tickets with reference %s", psa.ErrBeforeWrite, cu.ID, len(found), t.Reference)
	}
	subject := truncateRunes(strings.TrimSpace(t.Summary), maxSubject) + " " + tag
	body := map[string]any{
		"customer_id":  cu.ID,
		"subject":      subject,
		"problem_type": c.cfg.Tickets.ProblemType,
		"status":       c.cfg.Tickets.StatusNew,
		"comments_attributes": []map[string]any{{"subject": "trstctl alert", "body": t.Description,
			"hidden": true, "do_not_email": true}},
	}
	var created struct {
		Ticket *ticket `json:"ticket"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/tickets", nil, body, &created, true); err != nil {
		return "", err
	}
	if created.Ticket == nil || created.Ticket.ID <= 0 {
		return "", errors.New("syncro: the created ticket carries no ID")
	}
	return strconv.FormatInt(created.Ticket.ID, 10), nil
}

// AddNote adds a hidden comment to an open ticket, unless a comment already
// carries its reference.
func (c *Client) AddNote(ctx context.Context, n psa.TicketNote) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(n.TicketID)
	if err != nil {
		return err
	}
	return c.addComment(ctx, id, n.Reference, "trstctl alert", n.Text)
}

func (c *Client) addComment(ctx context.Context, id int64, reference, subject, text string) error {
	marker := psa.NoteMarker(reference)
	path := "/tickets/" + strconv.FormatInt(id, 10)
	for page := 1; page <= maxPages; page++ {
		var body struct {
			Comments []comment `json:"comments"`
			Meta     struct {
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}}
		if _, err := c.do(ctx, http.MethodGet, path+"/comments", q, nil, &body, false); err != nil {
			return err
		}
		for _, cm := range body.Comments {
			if strings.Contains(cm.Body, marker) {
				return nil
			}
		}
		if body.Meta.TotalPages <= page {
			break
		}
	}
	payload := map[string]any{"subject": subject, "body": strings.TrimSpace(text) + "\n\n" + marker, "hidden": true, "do_not_email": true}
	_, err := c.do(ctx, http.MethodPost, path+"/comment", nil, payload, nil, true)
	return err
}

// CloseTicket comments the resolution and sets the closed status. A ticket
// already closed, or gone, is left alone.
func (c *Client) CloseTicket(ctx context.Context, cl psa.TicketClose) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(cl.TicketID)
	if err != nil {
		return err
	}
	var body struct {
		Ticket *ticket `json:"ticket"`
	}
	status, err := c.do(ctx, http.MethodGet, "/tickets/"+strconv.FormatInt(id, 10), nil, nil, &body, false)
	if status == http.StatusNotFound || (err == nil && body.Ticket == nil) {
		return nil
	}
	if err != nil {
		return err
	}
	if body.Ticket.Status == c.cfg.Tickets.StatusClosed {
		return nil
	}
	if err := c.addComment(ctx, id, cl.Reference, "trstctl resolution", cl.Resolution); err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPut, "/tickets/"+strconv.FormatInt(id, 10), nil, map[string]any{"status": c.cfg.Tickets.StatusClosed}, nil, true)
	return err
}

func ticketID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: %q is not a Syncro ticket ID", psa.ErrBeforeWrite, raw)
	}
	return id, nil
}

// do sends one request with the bearer token in its header, never in the
// URL. A lookup failure is always before any write; a write's 4xx other
// than 408 and 429 is the system's definitive refusal.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, write bool) (int, error) {
	target := c.cfg.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("%w: encode %s %s: %v", psa.ErrBeforeWrite, method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, fmt.Errorf("%w: build %s %s: %v", psa.ErrBeforeWrite, method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.creds.APIToken))
	label := method + " " + path
	resp, err := c.http.Do(req)
	if err != nil {
		cause := transportCause(err)
		if !write {
			return 0, fmt.Errorf("%w: syncro: %s: %v", psa.ErrBeforeWrite, label, cause)
		}
		return 0, fmt.Errorf("syncro: %s: %v", label, cause)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("syncro: %s answered %d%s", label, resp.StatusCode, c.errorDetail(raw))
		retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		switch {
		case !write:
			return resp.StatusCode, fmt.Errorf("%w: %s", psa.ErrBeforeWrite, cause)
		case !retryable:
			return resp.StatusCode, fmt.Errorf("%w: %s", psa.ErrRefused, cause)
		default:
			return resp.StatusCode, errors.New(cause)
		}
	}
	if readErr != nil {
		return resp.StatusCode, fmt.Errorf("syncro: read %s: %v", label, readErr)
	}
	if out != nil && len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("syncro: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the documented {"error": "..."} body, bounded,
// printable, and with any echo of the token removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Error == nil {
		return ""
	}
	text := []byte(fmt.Sprint(body.Error))
	if len(c.creds.APIToken) > 0 {
		text = bytes.ReplaceAll(text, c.creds.APIToken, []byte("[redacted]"))
	}
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, string(text))
	if len(s) > 300 {
		s = s[:300]
	}
	return " (" + s + ")"
}

func transportCause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
