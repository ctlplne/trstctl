// SPDX-License-Identifier: BUSL-1.1

// Package autotask is the Autotask PSA client of the Provider billing sync
// (MSP-4), written from the vendor's public REST v1.0 entity reference:
// UserName, Secret and ApiIntegrationcode headers on every call, POST
// /{Entity}/query filters, companies, Recurring Service contracts, contract
// services, their per-period units and unit adjustments, tickets and ticket
// notes.
//
// Autotask holds a contract service's quantity as whole units changed only
// by adjustments, which cannot be read back. The client reads the units in
// force at the effective date first and adds only the difference, so a retry
// after a lost answer reads the units already set and changes nothing.
package autotask

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
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/secrettext"
)

// RecurringServiceContract is the contractType of a Recurring Service
// contract, the only type that carries contract services.
const RecurringServiceContract = 7

// Config is one Autotask target.
type Config struct {
	// BaseURL is the zone's REST root, https://webservicesN.autotask.net/atservicesrest/v1.0.
	BaseURL string
	// Username is the API user.
	Username string
	// ContractName, when set, picks the contract among the company's
	// current Recurring Service contracts.
	ContractName string
	// Services maps a meter to the Autotask service whose units carry it.
	Services map[string]int64
	// Tickets is the queue, statuses, priority and note picklist values of
	// alert tickets; nil when the target opens no tickets.
	Tickets *TicketConfig
}

// TicketConfig holds the instance's picklist values for alert tickets.
type TicketConfig struct {
	QueueID        int64
	StatusNew      int64
	StatusComplete int64
	Priority       int64
	NoteType       int64
	NotePublish    int64
}

// Credentials are the API user's secret and the integration's tracking
// identifier, borrowed for one call: the caller owns and wipes them.
type Credentials struct {
	Secret          []byte
	IntegrationCode []byte
}

// Client speaks to one Autotask zone.
type Client struct {
	cfg   Config
	http  *http.Client
	creds Credentials
	now   func() time.Time
}

const maxResponse = 1 << 20

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("autotask: the target needs an absolute REST base URL")
	}
	if httpClient == nil {
		return nil, errors.New("autotask: no HTTP client")
	}
	if strings.TrimSpace(cfg.Username) == "" || len(creds.Secret) == 0 || len(creds.IntegrationCode) == 0 {
		return nil, errors.New("autotask: the target needs its API user, secret and tracking identifier")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds, now: time.Now}, nil
}

type filter struct {
	Op    string `json:"op"`
	Field string `json:"field"`
	Value any    `json:"value"`
}

type company struct {
	ID          int64  `json:"id"`
	CompanyName string `json:"companyName"`
	IsActive    bool   `json:"isActive"`
}

type contract struct {
	ID           int64     `json:"id"`
	CompanyID    int64     `json:"companyID"`
	ContractName string    `json:"contractName"`
	ContractType int64     `json:"contractType"`
	StartDate    time.Time `json:"startDate"`
	EndDate      time.Time `json:"endDate"`
}

type contractService struct {
	ID         int64 `json:"id"`
	ContractID int64 `json:"contractID"`
	ServiceID  int64 `json:"serviceID"`
}

type serviceUnits struct {
	ContractServiceID int64     `json:"contractServiceID"`
	StartDate         time.Time `json:"startDate"`
	EndDate           time.Time `json:"endDate"`
	Units             int64     `json:"units"`
}

type plannedService struct {
	meter   string
	service int64
	cs      int64
	value   int64
	current int64
}

// PushUsage sets one customer's period as the units of its contract's
// services, effective from the period's end (the first day the next invoice
// bills). Every lookup happens before the first write.
func (c *Client) PushUsage(ctx context.Context, p psa.UsagePeriod) (psa.UsageOutcome, error) {
	var out psa.UsageOutcome
	co, err := c.company(ctx, p.ExternalCompanyID)
	if err != nil {
		return out, err
	}
	effective := p.PeriodEnd.UTC()
	ct, err := c.contract(ctx, co, effective)
	if err != nil {
		return out, err
	}
	values := map[string]int64{}
	for _, line := range p.Lines {
		values[line.Meter] = line.Value
	}
	meters := make([]string, 0, len(c.cfg.Services))
	for meter := range c.cfg.Services {
		meters = append(meters, meter)
	}
	sort.Strings(meters)
	plan := make([]plannedService, 0, len(meters))
	for _, meter := range meters {
		service := c.cfg.Services[meter]
		var services []contractService
		if err := c.query(ctx, "ContractServices", []filter{{"eq", "contractID", ct.ID}, {"eq", "serviceID", service}}, &services); err != nil {
			return out, err
		}
		if len(services) != 1 {
			return out, fmt.Errorf("%w: contract %d has %d instances of service %d, want exactly one (add the service to the contract once)",
				psa.ErrBeforeWrite, ct.ID, len(services), service)
		}
		var units []serviceUnits
		if err := c.query(ctx, "ContractServiceUnits", []filter{{"eq", "contractServiceID", services[0].ID},
			{"lte", "startDate", effective.Format(time.RFC3339)}, {"gt", "endDate", effective.Format(time.RFC3339)}}, &units); err != nil {
			return out, err
		}
		var current int64
		for _, u := range units {
			if u.ContractServiceID == services[0].ID && !u.StartDate.After(effective) && u.EndDate.After(effective) {
				current = u.Units
			}
		}
		plan = append(plan, plannedService{meter: meter, service: service, cs: services[0].ID, value: values[meter], current: current})
	}
	for _, line := range plan {
		out.Set = append(out.Set, line.meter)
		if line.value == line.current {
			if out.Status == 0 {
				out.Status = http.StatusOK
			}
			continue
		}
		body := map[string]any{"contractServiceID": line.cs, "unitChange": line.value - line.current, "effectiveDate": effective.Format(time.RFC3339)}
		status, err := c.do(ctx, http.MethodPost, "/ContractServiceAdjustments", body, nil, true)
		if err != nil {
			return out, err
		}
		out.Status = status
	}
	return out, nil
}

// company resolves the mapped company by its numeric ID; it must be active.
func (c *Client) company(ctx context.Context, external string) (company, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(external), 10, 64)
	if err != nil || id <= 0 {
		return company{}, fmt.Errorf("%w: an Autotask company is mapped by its numeric ID, not %q", psa.ErrBeforeWrite, external)
	}
	var item struct {
		Item *company `json:"item"`
	}
	status, err := c.do(ctx, http.MethodGet, "/Companies/"+strconv.FormatInt(id, 10), nil, &item, false)
	if status == http.StatusNotFound || (err == nil && item.Item == nil) {
		return company{}, fmt.Errorf("%w: Autotask has no company %d", psa.ErrBeforeWrite, id)
	}
	if err != nil {
		return company{}, err
	}
	if item.Item.ID != id {
		return company{}, fmt.Errorf("%w: Autotask answered company %d for company %d", psa.ErrBeforeWrite, item.Item.ID, id)
	}
	if !item.Item.IsActive {
		return company{}, fmt.Errorf("%w: Autotask company %d is inactive", psa.ErrBeforeWrite, id)
	}
	return *item.Item, nil
}

// contract finds the company's one Recurring Service contract in force at
// the effective date (and named ContractName when set).
func (c *Client) contract(ctx context.Context, co company, at time.Time) (contract, error) {
	var list []contract
	if err := c.query(ctx, "Contracts", []filter{{"eq", "companyID", co.ID}, {"eq", "contractType", RecurringServiceContract}}, &list); err != nil {
		return contract{}, err
	}
	var current []contract
	for _, ct := range list {
		if ct.CompanyID != co.ID || ct.ContractType != RecurringServiceContract || ct.StartDate.After(at) || !ct.EndDate.After(at) {
			continue
		}
		if c.cfg.ContractName != "" && ct.ContractName != c.cfg.ContractName {
			continue
		}
		current = append(current, ct)
	}
	if len(current) != 1 {
		return contract{}, fmt.Errorf("%w: company %d has %d Recurring Service contracts in force on %s%s, want exactly one",
			psa.ErrBeforeWrite, co.ID, len(current), at.Format("2006-01-02"), nameClause(c.cfg.ContractName))
	}
	return current[0], nil
}

func nameClause(name string) string {
	if name == "" {
		return ""
	}
	return " named " + strconv.Quote(name)
}

// maxTitle and maxDescription are the ticket bounds the client sends.
const (
	maxTitle       = 255
	maxDescription = 8000
	maxNote        = 32000
)

type ticket struct {
	ID         int64  `json:"id"`
	CompanyID  int64  `json:"companyID"`
	ExternalID string `json:"externalID"`
	Status     int64  `json:"status"`
}

type ticketNote struct {
	ID          int64  `json:"id"`
	TicketID    int64  `json:"ticketID"`
	Description string `json:"description"`
}

// OpenTicket opens the subject's ticket under the mapped company, or finds
// the one a previous attempt opened (the same externalID under the same
// company), and returns its ID.
func (c *Client) OpenTicket(ctx context.Context, t psa.TicketOpen) (string, error) {
	if c.cfg.Tickets == nil {
		return "", fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	if t.Reference == "" || len(t.Reference) > 50 {
		return "", fmt.Errorf("%w: an Autotask externalID is 1-50 characters", psa.ErrBeforeWrite)
	}
	co, err := c.company(ctx, t.ExternalCompanyID)
	if err != nil {
		return "", err
	}
	var found []ticket
	if err := c.query(ctx, "Tickets", []filter{{"eq", "externalID", t.Reference}, {"eq", "companyID", co.ID}}, &found); err != nil {
		return "", err
	}
	var same []ticket
	for _, tk := range found {
		if tk.ExternalID == t.Reference && tk.CompanyID == co.ID {
			same = append(same, tk)
		}
	}
	switch len(same) {
	case 1:
		return strconv.FormatInt(same[0].ID, 10), nil
	case 0:
	default:
		return "", fmt.Errorf("%w: company %d has %d tickets with externalID %s", psa.ErrBeforeWrite, co.ID, len(same), t.Reference)
	}
	body := map[string]any{
		"companyID":   co.ID,
		"title":       truncateRunes(t.Summary, maxTitle),
		"description": truncateRunes(t.Description, maxDescription),
		"status":      c.cfg.Tickets.StatusNew,
		"priority":    c.cfg.Tickets.Priority,
		"externalID":  t.Reference,
	}
	if c.cfg.Tickets.QueueID > 0 {
		body["queueID"] = c.cfg.Tickets.QueueID
	}
	var created struct {
		ItemID int64 `json:"itemId"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/Tickets", body, &created, true); err != nil {
		return "", err
	}
	if created.ItemID <= 0 {
		return "", errors.New("autotask: the created ticket carries no itemId")
	}
	return strconv.FormatInt(created.ItemID, 10), nil
}

// AddNote adds a note to an open ticket, unless a note already carries its
// reference.
func (c *Client) AddNote(ctx context.Context, n psa.TicketNote) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(n.TicketID)
	if err != nil {
		return err
	}
	return c.addNote(ctx, id, n.Reference, "trstctl alert", n.Text)
}

func (c *Client) addNote(ctx context.Context, id int64, reference, title, text string) error {
	marker := psa.NoteMarker(reference)
	var notes []ticketNote
	if err := c.query(ctx, "TicketNotes", []filter{{"eq", "ticketID", id}}, &notes); err != nil {
		return err
	}
	for _, note := range notes {
		if note.TicketID == id && strings.Contains(note.Description, marker) {
			return nil
		}
	}
	description := truncateRunes(strings.TrimSpace(text), maxNote-len(marker)-2) + "\n\n" + marker
	body := map[string]any{"ticketID": id, "noteType": c.cfg.Tickets.NoteType, "publish": c.cfg.Tickets.NotePublish,
		"title": title, "description": description}
	_, err := c.do(ctx, http.MethodPost, "/TicketNotes", body, nil, true)
	return err
}

// CloseTicket notes the resolution and sets the complete status. A ticket
// already complete, or gone, is left alone.
func (c *Client) CloseTicket(ctx context.Context, cl psa.TicketClose) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(cl.TicketID)
	if err != nil {
		return err
	}
	var item struct {
		Item *ticket `json:"item"`
	}
	status, err := c.do(ctx, http.MethodGet, "/Tickets/"+strconv.FormatInt(id, 10), nil, &item, false)
	if status == http.StatusNotFound || (err == nil && item.Item == nil) {
		return nil
	}
	if err != nil {
		return err
	}
	if item.Item.Status == c.cfg.Tickets.StatusComplete {
		return nil
	}
	if err := c.addNote(ctx, id, cl.Reference, "trstctl resolution", cl.Resolution); err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, "/Tickets", map[string]any{"id": id, "status": c.cfg.Tickets.StatusComplete}, nil, true)
	return err
}

func ticketID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: %q is not an Autotask ticket ID", psa.ErrBeforeWrite, raw)
	}
	return id, nil
}

// query runs POST /{entity}/query with an and-filter and follows
// nextPageUrl, at most ten pages of up to 500 records.
func (c *Client) query(ctx context.Context, entity string, filters []filter, out any) error {
	var all []json.RawMessage
	next, method := "/"+entity+"/query", http.MethodPost
	var body any = map[string]any{"filter": filters}
	for page := 0; page < 10 && next != ""; page++ {
		var resp struct {
			Items       []json.RawMessage `json:"items"`
			PageDetails struct {
				NextPageURL string `json:"nextPageUrl"`
			} `json:"pageDetails"`
		}
		if _, err := c.do(ctx, method, next, body, &resp, false); err != nil {
			return err
		}
		all = append(all, resp.Items...)
		next = ""
		if resp.PageDetails.NextPageURL != "" {
			u, err := url.Parse(resp.PageDetails.NextPageURL)
			if err != nil {
				return fmt.Errorf("%w: autotask: a next page URL that does not parse", psa.ErrBeforeWrite)
			}
			// Only a page of the same zone is followed.
			base, _ := url.Parse(c.cfg.BaseURL)
			if u.Host != base.Host {
				return fmt.Errorf("%w: autotask: a next page on another host", psa.ErrBeforeWrite)
			}
			// A next page is read with GET; it carries the query itself.
			next, method, body = strings.TrimPrefix(u.RequestURI(), base.Path), http.MethodGet, nil
		}
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		raw = []byte("[]")
	}
	return json.Unmarshal(raw, out)
}

// do sends one request. A lookup failure is always before any write; a
// write's 4xx other than 408 and 429 is the system's definitive refusal.
func (c *Client) do(ctx context.Context, method, path string, body, out any, write bool) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("%w: encode %s %s: %v", psa.ErrBeforeWrite, method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return 0, fmt.Errorf("%w: build %s %s: %v", psa.ErrBeforeWrite, method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("UserName", c.cfg.Username)
	req.Header.Set("Secret", secrettext.Prefixed("", c.creds.Secret))
	req.Header.Set("ApiIntegrationcode", secrettext.Prefixed("", c.creds.IntegrationCode))
	label := method + " " + strings.SplitN(path, "?", 2)[0]
	resp, err := c.http.Do(req)
	if err != nil {
		cause := transportCause(err)
		if !write {
			return 0, fmt.Errorf("%w: autotask: %s: %v", psa.ErrBeforeWrite, label, cause)
		}
		return 0, fmt.Errorf("autotask: %s: %v", label, cause)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("autotask: %s answered %d%s", label, resp.StatusCode, c.errorDetail(raw))
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
		return resp.StatusCode, fmt.Errorf("autotask: read %s: %v", label, readErr)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("autotask: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the documented {"errors": [...]} body, bounded,
// printable, and with any echo of the credentials removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &body) != nil || len(body.Errors) == 0 {
		return ""
	}
	if len(body.Errors) > 3 {
		body.Errors = body.Errors[:3]
	}
	text := []byte(strings.Join(body.Errors, "; "))
	for _, key := range [][]byte{c.creds.Secret, c.creds.IntegrationCode} {
		if len(key) > 0 {
			text = bytes.ReplaceAll(text, key, []byte("[redacted]"))
		}
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
