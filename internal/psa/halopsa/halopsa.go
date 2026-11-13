// SPDX-License-Identifier: BUSL-1.1

// Package halopsa is the HaloPSA client of the Provider billing sync
// (MSP-5), written from Halo's public descriptions: the OAuth2
// client-credentials token at {base}/auth/token (with ?tenant= for a hosted
// tenant) and the /api resources as the published HaloAPI client calls them
// (clients, recurring invoices and their lines with qty_order, tickets,
// actions), where every write is a POST of a JSON array and an update is a
// POST that carries the record's id.
//
// Halo's public reference is thin on field names; where the published
// client shows none, this follows Halo's conventions (summary, details,
// client_id, status_id, note, hiddenfromuser) and the stand-in says so. A
// live Halo instance (Track B) settles them.
package halopsa

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
)

// Config is one HaloPSA instance.
type Config struct {
	// BaseURL is the instance root, https://{instance}.halopsa.com; the API
	// is under /api and the token endpoint at /auth/token.
	BaseURL string
	// Tenant is the hosted tenant name sent as ?tenant= on the token
	// request; empty for a self-hosted instance.
	Tenant string
	// ClientID is the API application's client ID.
	ClientID string
	// RecurringInvoiceName, when set, picks the recurring invoice among a
	// client's recurring invoices.
	RecurringInvoiceName string
	// Items maps a meter to the item whose recurring invoice line carries
	// it.
	Items map[string]int64
	// Tickets is the ticket type and statuses of alert tickets; nil when
	// the target opens no tickets.
	Tickets *TicketConfig
}

// TicketConfig is the ticket type and status IDs alert tickets use.
type TicketConfig struct {
	TicketTypeID   int64
	StatusNewID    int64
	StatusClosedID int64
}

// Credentials are the API application's client secret, borrowed for one
// call: the caller owns and wipes it.
type Credentials struct {
	ClientSecret []byte
}

// Client speaks to one HaloPSA instance. It signs in once per client and
// keeps the access token only for its own lifetime (one delivery).
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
}

const (
	maxResponse = 1 << 20
	maxSummary  = 150
	maxPages    = 20
	pageSize    = 100
)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("halopsa: the target needs an absolute instance URL")
	}
	if httpClient == nil || strings.TrimSpace(cfg.ClientID) == "" || len(creds.ClientSecret) == 0 {
		return nil, errors.New("halopsa: the target needs its client ID and client secret")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

// signIn exchanges the client credentials for an access token.
func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "scope": {"all"}}
	encoded := []byte(form.Encode() + "&client_secret=")
	encoded = appendQueryEscaped(encoded, c.creds.ClientSecret)
	target := c.cfg.BaseURL + "/auth/token"
	if c.cfg.Tenant != "" {
		target += "?" + url.Values{"tenant": {c.cfg.Tenant}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("%w: halopsa: build the token request: %v", psa.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	for i := range encoded {
		encoded[i] = 0
	}
	if err != nil {
		return fmt.Errorf("%w: halopsa: sign in: %v", psa.ErrBeforeWrite, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: halopsa: sign in answered %d%s", psa.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(raw, &token); err != nil || token.AccessToken == "" {
		return fmt.Errorf("%w: halopsa: sign in returned no access token", psa.ErrBeforeWrite)
	}
	c.bearer = "Bearer " + token.AccessToken
	return nil
}

// appendQueryEscaped form-encodes src onto dst byte by byte, so the secret
// never becomes a Go string that cannot be wiped.
func appendQueryEscaped(dst, src []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, b := range src {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_', b == '.', b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hex[b>>4], hex[b&15])
		}
	}
	return dst
}

type client struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Inactive bool   `json:"inactive"`
}

type recurringInvoice struct {
	ID          int64  `json:"id"`
	ClientID    int64  `json:"client_id"`
	InvoiceName string `json:"invoice_name"`
	Lines       []line `json:"lines"`
}

type line struct {
	ID       int64   `json:"id"`
	ItemID   int64   `json:"item_id"`
	QtyOrder float64 `json:"qty_order"`
}

// PushUsage sets one customer's period as the line quantities (qty_order) of
// its client's recurring invoice: one save per line, as Halo applies one
// line change per save. Every lookup happens before the first write.
func (c *Client) PushUsage(ctx context.Context, p psa.UsagePeriod) (psa.UsageOutcome, error) {
	var out psa.UsageOutcome
	cl, err := c.client(ctx, p.ExternalCompanyID)
	if err != nil {
		return out, err
	}
	inv, err := c.recurringInvoice(ctx, cl)
	if err != nil {
		return out, err
	}
	values := map[string]int64{}
	for _, l := range p.Lines {
		values[l.Meter] = l.Value
	}
	meters := make([]string, 0, len(c.cfg.Items))
	for meter := range c.cfg.Items {
		meters = append(meters, meter)
	}
	sort.Strings(meters)
	type planned struct {
		meter string
		item  int64
		value int64
		line  *line
	}
	plan := make([]planned, 0, len(meters))
	for _, meter := range meters {
		item := c.cfg.Items[meter]
		var found []line
		for _, l := range inv.Lines {
			if l.ItemID == item {
				found = append(found, l)
			}
		}
		if len(found) > 1 {
			return out, fmt.Errorf("%w: recurring invoice %d has %d lines of item %d, want at most one", psa.ErrBeforeWrite, inv.ID, len(found), item)
		}
		entry := planned{meter: meter, item: item, value: values[meter]}
		if len(found) == 1 {
			entry.line = &found[0]
		}
		plan = append(plan, entry)
	}
	for _, l := range plan {
		out.Set = append(out.Set, l.meter)
		var change map[string]any
		switch {
		case l.line == nil:
			change = map[string]any{"item_id": l.item, "qty_order": l.value}
		case l.line.QtyOrder == float64(l.value):
			if out.Status == 0 {
				out.Status = http.StatusOK
			}
			continue
		default:
			change = map[string]any{"id": l.line.ID, "qty_order": l.value}
		}
		status, err := c.do(ctx, http.MethodPost, "/api/RecurringInvoice", nil,
			[]map[string]any{{"id": inv.ID, "lines": []map[string]any{change}}}, nil, true)
		if err != nil {
			return out, err
		}
		out.Status = status
	}
	return out, nil
}

// client resolves the mapped client by its numeric ID; it must be active.
func (c *Client) client(ctx context.Context, external string) (client, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(external), 10, 64)
	if err != nil || id <= 0 {
		return client{}, fmt.Errorf("%w: a HaloPSA client is mapped by its numeric ID, not %q", psa.ErrBeforeWrite, external)
	}
	var cl client
	status, err := c.do(ctx, http.MethodGet, "/api/Client/"+strconv.FormatInt(id, 10), nil, nil, &cl, false)
	if status == http.StatusNotFound {
		return client{}, fmt.Errorf("%w: HaloPSA has no client %d", psa.ErrBeforeWrite, id)
	}
	if err != nil {
		return client{}, err
	}
	if cl.ID != id {
		return client{}, fmt.Errorf("%w: HaloPSA answered client %d for client %d", psa.ErrBeforeWrite, cl.ID, id)
	}
	if cl.Inactive {
		return client{}, fmt.Errorf("%w: HaloPSA client %d is inactive", psa.ErrBeforeWrite, id)
	}
	return cl, nil
}

// recurringInvoice finds the client's one recurring invoice (named
// RecurringInvoiceName when set), with its lines.
func (c *Client) recurringInvoice(ctx context.Context, cl client) (recurringInvoice, error) {
	var list []recurringInvoice
	for page := 1; page <= maxPages; page++ {
		var body struct {
			RecordCount int                `json:"record_count"`
			Invoices    []recurringInvoice `json:"invoices"`
		}
		q := url.Values{"client_id": {strconv.FormatInt(cl.ID, 10)}, "includelines": {"true"}, "pageinate": {"true"},
			"page_size": {strconv.Itoa(pageSize)}, "page_no": {strconv.Itoa(page)}}
		if _, err := c.do(ctx, http.MethodGet, "/api/RecurringInvoice", q, nil, &body, false); err != nil {
			return recurringInvoice{}, err
		}
		list = append(list, body.Invoices...)
		if len(body.Invoices) < pageSize || len(list) >= body.RecordCount {
			break
		}
	}
	var matched []recurringInvoice
	for _, inv := range list {
		if inv.ClientID != cl.ID {
			continue
		}
		if c.cfg.RecurringInvoiceName != "" && inv.InvoiceName != c.cfg.RecurringInvoiceName {
			continue
		}
		matched = append(matched, inv)
	}
	if len(matched) != 1 {
		name := ""
		if c.cfg.RecurringInvoiceName != "" {
			name = " named " + strconv.Quote(c.cfg.RecurringInvoiceName)
		}
		return recurringInvoice{}, fmt.Errorf("%w: client %d has %d recurring invoices%s, want exactly one", psa.ErrBeforeWrite, cl.ID, len(matched), name)
	}
	return matched[0], nil
}

type ticket struct {
	ID       int64  `json:"id"`
	ClientID int64  `json:"client_id"`
	Summary  string `json:"summary"`
	StatusID int64  `json:"status_id"`
}

type action struct {
	ID       int64  `json:"id"`
	TicketID int64  `json:"ticket_id"`
	Note     string `json:"note"`
}

func referenceTag(reference string) string { return "[" + reference + "]" }

// OpenTicket opens the subject's ticket for the mapped client, or finds the
// one a previous attempt opened (its summary ends with the reference), and
// returns its ID. Halo tickets have no published third-party reference
// field, so the reference rides at the end of the summary.
func (c *Client) OpenTicket(ctx context.Context, t psa.TicketOpen) (string, error) {
	if c.cfg.Tickets == nil {
		return "", fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	if t.Reference == "" || len(t.Reference) > 64 || strings.ContainsAny(t.Reference, "[] ") {
		return "", fmt.Errorf("%w: a ticket reference is 1-64 characters without brackets or spaces", psa.ErrBeforeWrite)
	}
	cl, err := c.client(ctx, t.ExternalCompanyID)
	if err != nil {
		return "", err
	}
	tag := referenceTag(t.Reference)
	var body struct {
		RecordCount int      `json:"record_count"`
		Tickets     []ticket `json:"tickets"`
	}
	q := url.Values{"client_id": {strconv.FormatInt(cl.ID, 10)}, "search": {t.Reference}, "search_summary": {"true"}}
	if _, err := c.do(ctx, http.MethodGet, "/api/Tickets", q, nil, &body, false); err != nil {
		return "", err
	}
	var found []ticket
	for _, tk := range body.Tickets {
		if tk.ClientID == cl.ID && strings.HasSuffix(tk.Summary, tag) {
			found = append(found, tk)
		}
	}
	switch len(found) {
	case 1:
		return strconv.FormatInt(found[0].ID, 10), nil
	case 0:
	default:
		return "", fmt.Errorf("%w: client %d has %d tickets with reference %s", psa.ErrBeforeWrite, cl.ID, len(found), t.Reference)
	}
	fields := map[string]any{
		"summary":       truncateRunes(strings.TrimSpace(t.Summary), maxSummary) + " " + tag,
		"details":       t.Description,
		"client_id":     cl.ID,
		"tickettype_id": c.cfg.Tickets.TicketTypeID,
	}
	if c.cfg.Tickets.StatusNewID > 0 {
		fields["status_id"] = c.cfg.Tickets.StatusNewID
	}
	var created json.RawMessage
	if _, err := c.do(ctx, http.MethodPost, "/api/Tickets", nil, []map[string]any{fields}, &created, true); err != nil {
		return "", err
	}
	id := createdID(created)
	if id <= 0 {
		return "", errors.New("halopsa: the created ticket carries no id")
	}
	return strconv.FormatInt(id, 10), nil
}

// createdID reads the id of a created record, answered as the record or as
// an array of records.
func createdID(raw json.RawMessage) int64 {
	var one struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal(raw, &one) == nil && one.ID > 0 {
		return one.ID
	}
	var many []struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal(raw, &many) == nil && len(many) == 1 {
		return many[0].ID
	}
	return 0
}

// AddNote adds a private action to an open ticket, unless one already
// carries its reference.
func (c *Client) AddNote(ctx context.Context, n psa.TicketNote) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(n.TicketID)
	if err != nil {
		return err
	}
	return c.addAction(ctx, id, n.Reference, n.Text)
}

func (c *Client) addAction(ctx context.Context, id int64, reference, text string) error {
	marker := psa.NoteMarker(reference)
	var body struct {
		RecordCount int      `json:"record_count"`
		Actions     []action `json:"actions"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/api/Actions", url.Values{"ticket_id": {strconv.FormatInt(id, 10)}}, nil, &body, false); err != nil {
		return err
	}
	for _, a := range body.Actions {
		if a.TicketID == id && strings.Contains(a.Note, marker) {
			return nil
		}
	}
	payload := []map[string]any{{"ticket_id": id, "note": strings.TrimSpace(text) + "\n\n" + marker, "hiddenfromuser": true, "outcome": "trstctl"}}
	_, err := c.do(ctx, http.MethodPost, "/api/Actions", nil, payload, nil, true)
	return err
}

// CloseTicket adds the resolution as an action and sets the closed status.
// A ticket already closed, or gone, is left alone.
func (c *Client) CloseTicket(ctx context.Context, cl psa.TicketClose) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(cl.TicketID)
	if err != nil {
		return err
	}
	var tk ticket
	status, err := c.do(ctx, http.MethodGet, "/api/Tickets/"+strconv.FormatInt(id, 10), nil, nil, &tk, false)
	if status == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if tk.StatusID == c.cfg.Tickets.StatusClosedID {
		return nil
	}
	if err := c.addAction(ctx, id, cl.Reference, cl.Resolution); err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, "/api/Tickets", nil, []map[string]any{{"id": id, "status_id": c.cfg.Tickets.StatusClosedID}}, nil, true)
	return err
}

func ticketID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: %q is not a HaloPSA ticket ID", psa.ErrBeforeWrite, raw)
	}
	return id, nil
}

// do sends one API request with the access token. A lookup failure is
// always before any write; a write's 4xx other than 408 and 429 is the
// system's definitive refusal.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, write bool) (int, error) {
	if err := c.signIn(ctx); err != nil {
		return 0, err
	}
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
	req.Header.Set("Authorization", c.bearer)
	label := method + " " + path
	resp, err := c.http.Do(req)
	if err != nil {
		cause := transportCause(err)
		if !write {
			return 0, fmt.Errorf("%w: halopsa: %s: %v", psa.ErrBeforeWrite, label, cause)
		}
		return 0, fmt.Errorf("halopsa: %s: %v", label, cause)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("halopsa: %s answered %d%s", label, resp.StatusCode, c.errorDetail(raw))
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
		return resp.StatusCode, fmt.Errorf("halopsa: read %s: %v", label, readErr)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("halopsa: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the shapes Halo answers with ({ClassName, Message},
// {Message}, {error}, {resultCode, errorMessage}), bounded, printable, and
// with any echo of the client secret removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		ClassName    string `json:"ClassName"`
		Message      string `json:"Message"`
		Error        string `json:"error"`
		ErrorMessage string `json:"errorMessage"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.ClassName, body.Message, body.Error, body.ErrorMessage} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := []byte(strings.Join(parts, "; "))
	if len(c.creds.ClientSecret) > 0 {
		text = bytes.ReplaceAll(text, c.creds.ClientSecret, []byte("[redacted]"))
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
