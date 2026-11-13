// SPDX-License-Identifier: BUSL-1.1

// Package connectwise is the ConnectWise PSA client of the Provider billing
// sync (MSP-3), written from the vendor's public REST 3.0 descriptions (the
// published client libraries' request shapes and models): Basic credentials
// companyId+publicKey:privateKey with the integration's clientId header,
// conditions queries, companies, agreements and agreement additions.
//
// A customer's usage lands as additions of its company's one active
// agreement of the configured type: one addition per configured product,
// whose quantity is the period's figure. A quantity is absolute, so a retry
// after a lost answer sets the same number again and never adds to it.
package connectwise

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/secrettext"
)

// Config is one ConnectWise target.
type Config struct {
	// BaseURL is the REST root, https://{host}/{codebase}/apis/3.0.
	BaseURL string
	// CompanyID is the PSA login company the API member belongs to.
	CompanyID string
	// ClientID is the integration's clientId header.
	ClientID string
	// AgreementType names the agreement type a customer's company has one
	// active agreement of.
	AgreementType string
	// Products maps a meter to the catalog product identifier of its
	// addition. A meter without a product is not pushed.
	Products map[string]string
	// Tickets is the board and statuses alert tickets use; nil when the
	// target opens no tickets.
	Tickets *TicketConfig
}

// TicketConfig is the service board and statuses of alert tickets.
type TicketConfig struct {
	Board        string
	NewStatus    string
	ClosedStatus string
}

// Credentials are the API member's keys, borrowed for one push: the caller
// owns them and wipes them afterwards.
type Credentials struct {
	PublicKey  []byte
	PrivateKey []byte
}

// Client speaks to one ConnectWise PSA site.
type Client struct {
	cfg   Config
	http  *http.Client
	creds Credentials
}

// maxResponse bounds one answer the client reads.
const maxResponse = 1 << 20

// conditionValue is what this client puts inside a quoted conditions value:
// the published grammar shows no escaping, so a value that would need one is
// refused before anything is sent.
var conditionValue = regexp.MustCompile(`^[A-Za-z0-9 _.,:;/()&@#+-]{1,100}$`)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("connectwise: the target needs an absolute REST base URL")
	}
	if httpClient == nil {
		return nil, errors.New("connectwise: no HTTP client")
	}
	if strings.TrimSpace(cfg.CompanyID) == "" || strings.TrimSpace(cfg.ClientID) == "" ||
		len(creds.PublicKey) == 0 || len(creds.PrivateKey) == 0 {
		return nil, errors.New("connectwise: the target needs its company, clientId and both API keys")
	}
	if cfg.AgreementType != "" && !conditionValue.MatchString(cfg.AgreementType) {
		return nil, errors.New("connectwise: the agreement type cannot be used in a conditions query")
	}
	for meter, product := range cfg.Products {
		if !conditionValue.MatchString(product) {
			return nil, fmt.Errorf("connectwise: the product of %s cannot be used in a conditions query", meter)
		}
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

type companyRef struct {
	ID          int64  `json:"id"`
	Identifier  string `json:"identifier"`
	Name        string `json:"name"`
	DeletedFlag bool   `json:"deletedFlag"`
}

type agreementRef struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	AgreementStatus string `json:"agreementStatus"`
	CancelledFlag   bool   `json:"cancelledFlag"`
	Company         struct {
		ID int64 `json:"id"`
	} `json:"company"`
}

type addition struct {
	ID      int64 `json:"id"`
	Product struct {
		ID         int64  `json:"id"`
		Identifier string `json:"identifier"`
	} `json:"product"`
	Quantity      float64 `json:"quantity"`
	CancelledDate *string `json:"cancelledDate"`
}

// plannedLine is one product's addition before any write.
type plannedLine struct {
	meter    string
	product  string
	value    int64
	existing *addition
}

// PushUsage sets one customer's period on its company's agreement. Every
// lookup happens before the first write, so a company, agreement or addition
// that cannot be resolved unambiguously refuses the period with nothing
// written (psa.ErrBeforeWrite).
func (c *Client) PushUsage(ctx context.Context, p psa.UsagePeriod) (psa.UsageOutcome, error) {
	var out psa.UsageOutcome
	company, err := c.company(ctx, p.ExternalCompanyID)
	if err != nil {
		return out, err
	}
	agreement, err := c.agreement(ctx, company)
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
	plan := make([]plannedLine, 0, len(meters))
	for _, meter := range meters {
		product := c.cfg.Products[meter]
		existing, err := c.addition(ctx, agreement.ID, product)
		if err != nil {
			return out, err
		}
		// A configured meter with no reading in a signed period counts
		// zero: the signed evidence covered the whole period.
		plan = append(plan, plannedLine{meter: meter, product: product, value: values[meter], existing: existing})
	}
	for _, line := range plan {
		path := "/finance/agreements/" + strconv.FormatInt(agreement.ID, 10) + "/additions"
		switch {
		case line.existing == nil:
			body := map[string]any{
				"product":       map[string]string{"identifier": line.product},
				"quantity":      line.value,
				"billCustomer":  "Billable",
				"effectiveDate": p.PeriodStart.UTC().Format("2006-01-02T15:04:05Z"),
			}
			status, err := c.do(ctx, http.MethodPost, path, nil, body, nil, true)
			if err != nil {
				return out, err
			}
			out.Status = status
		case line.existing.Quantity != float64(line.value):
			patch := []map[string]any{{"op": "replace", "path": "quantity", "value": line.value}}
			status, err := c.do(ctx, http.MethodPatch, path+"/"+strconv.FormatInt(line.existing.ID, 10), nil, patch, nil, true)
			if err != nil {
				return out, err
			}
			out.Status = status
		default:
			// Already this period's figure: a retry of a write whose answer
			// was lost, or an unchanged figure.
			if out.Status == 0 {
				out.Status = http.StatusOK
			}
		}
		out.Set = append(out.Set, line.meter)
	}
	return out, nil
}

// company resolves the mapped company: a numeric ID names the record, any
// other value its identifier. Only the record that exactly matches is used.
func (c *Client) company(ctx context.Context, external string) (companyRef, error) {
	external = strings.TrimSpace(external)
	fields := url.Values{"fields": {"id,identifier,name,deletedFlag"}}
	var co companyRef
	if id, err := strconv.ParseInt(external, 10, 64); err == nil && id > 0 {
		status, err := c.do(ctx, http.MethodGet, "/company/companies/"+strconv.FormatInt(id, 10), fields, nil, &co, false)
		if status == http.StatusNotFound {
			return co, fmt.Errorf("%w: ConnectWise has no company %d", psa.ErrBeforeWrite, id)
		}
		if err != nil {
			return co, err
		}
		if co.ID != id {
			return co, fmt.Errorf("%w: ConnectWise answered company %d for company %d", psa.ErrBeforeWrite, co.ID, id)
		}
	} else {
		if !conditionValue.MatchString(external) {
			return co, fmt.Errorf("%w: the company identifier cannot be used in a conditions query", psa.ErrBeforeWrite)
		}
		var list []companyRef
		q := url.Values{"conditions": {`identifier="` + external + `"`}, "fields": fields["fields"], "pageSize": {"2"}}
		if _, err := c.do(ctx, http.MethodGet, "/company/companies", q, nil, &list, false); err != nil {
			return co, err
		}
		matched := 0
		for _, candidate := range list {
			if strings.EqualFold(candidate.Identifier, external) {
				co = candidate
				matched++
			}
		}
		if matched != 1 {
			return co, fmt.Errorf("%w: ConnectWise has %d companies with identifier %q", psa.ErrBeforeWrite, matched, external)
		}
	}
	if co.DeletedFlag {
		return co, fmt.Errorf("%w: ConnectWise company %d is deleted", psa.ErrBeforeWrite, co.ID)
	}
	return co, nil
}

// agreement finds the company's one active agreement of the configured type.
func (c *Client) agreement(ctx context.Context, co companyRef) (agreementRef, error) {
	var list []agreementRef
	q := url.Values{
		"conditions": {fmt.Sprintf(`company/id=%d and type/name="%s" and cancelledFlag=false`, co.ID, c.cfg.AgreementType)},
		"fields":     {"id,name,agreementStatus,cancelledFlag,company"},
		"pageSize":   {"25"},
	}
	if _, err := c.do(ctx, http.MethodGet, "/finance/agreements", q, nil, &list, false); err != nil {
		return agreementRef{}, err
	}
	var active []agreementRef
	for _, a := range list {
		if a.Company.ID == co.ID && !a.CancelledFlag && strings.EqualFold(a.AgreementStatus, "Active") {
			active = append(active, a)
		}
	}
	if len(active) != 1 {
		return agreementRef{}, fmt.Errorf("%w: company %d has %d active %q agreements, want exactly one", psa.ErrBeforeWrite, co.ID, len(active), c.cfg.AgreementType)
	}
	return active[0], nil
}

// addition finds the agreement's one uncancelled addition of a product.
func (c *Client) addition(ctx context.Context, agreementID int64, product string) (*addition, error) {
	var list []addition
	q := url.Values{
		"conditions": {`product/identifier="` + product + `" and cancelledDate=null`},
		"fields":     {"id,product,quantity,cancelledDate"},
		"pageSize":   {"2"},
	}
	path := "/finance/agreements/" + strconv.FormatInt(agreementID, 10) + "/additions"
	if _, err := c.do(ctx, http.MethodGet, path, q, nil, &list, false); err != nil {
		return nil, err
	}
	var live []addition
	for _, a := range list {
		if a.CancelledDate == nil && strings.EqualFold(a.Product.Identifier, product) {
			live = append(live, a)
		}
	}
	switch len(live) {
	case 0:
		return nil, nil
	case 1:
		return &live[0], nil
	default:
		return nil, fmt.Errorf("%w: agreement %d has %d uncancelled additions of product %q, want at most one", psa.ErrBeforeWrite, agreementID, len(live), product)
	}
}

// do sends one request. A lookup failure is always before any write; a
// write's 4xx other than 408 and 429 is the system's definitive refusal.
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
	req.Header.Set("Accept", "application/vnd.connectwise.com+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("clientId", c.cfg.ClientID)
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		if !write {
			return 0, fmt.Errorf("%w: %s %s: %v", psa.ErrBeforeWrite, method, path, transportCause(err))
		}
		return 0, fmt.Errorf("connectwise: %s %s: %v", method, path, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("connectwise: %s %s answered %d%s", method, path, resp.StatusCode, c.errorDetail(raw))
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
		return resp.StatusCode, fmt.Errorf("connectwise: read %s %s: %v", method, path, readErr)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("connectwise: decode %s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// authorize sets Basic companyId+publicKey:privateKey. The assembled bytes
// are wiped once the header string exists.
func (c *Client) authorize(req *http.Request) {
	plain := make([]byte, 0, len(c.cfg.CompanyID)+2+len(c.creds.PublicKey)+len(c.creds.PrivateKey))
	plain = append(plain, c.cfg.CompanyID...)
	plain = append(plain, '+')
	plain = append(plain, c.creds.PublicKey...)
	plain = append(plain, ':')
	plain = append(plain, c.creds.PrivateKey...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plain)))
	base64.StdEncoding.Encode(encoded, plain)
	req.Header.Set("Authorization", secrettext.Prefixed("Basic ", encoded))
	secret.Wipe(plain)
	secret.Wipe(encoded)
}

// errorDetail renders the documented error body's code and message, bounded,
// printable, and with any echo of the API keys removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Errors  []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	if body.Code != "" {
		parts = append(parts, body.Code)
	}
	if body.Message != "" {
		parts = append(parts, body.Message)
	}
	for i, e := range body.Errors {
		if i == 3 {
			break
		}
		parts = append(parts, strings.TrimSpace(e.Code+" "+e.Message))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + c.clean(strings.Join(parts, "; ")) + ")"
}

func (c *Client) clean(s string) string {
	raw := []byte(s)
	for _, key := range [][]byte{c.creds.PublicKey, c.creds.PrivateKey} {
		if len(key) > 0 {
			raw = bytes.ReplaceAll(raw, key, []byte("[redacted]"))
		}
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, string(raw))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// transportCause keeps a transport error's cause without the request URL.
func transportCause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// maxTicketSummary is the length of a ticket summary the client sends.
const maxTicketSummary = 100

type ticketRef struct {
	ID           int64  `json:"id"`
	ExternalXRef string `json:"externalXRef"`
	ClosedFlag   bool   `json:"closedFlag"`
	Company      struct {
		ID int64 `json:"id"`
	} `json:"company"`
}

// OpenTicket opens the subject's ticket under the mapped company, or finds
// the one a previous attempt opened (the same external reference under the
// same company), and returns its ID.
func (c *Client) OpenTicket(ctx context.Context, t psa.TicketOpen) (string, error) {
	if c.cfg.Tickets == nil {
		return "", fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	if !conditionValue.MatchString(t.Reference) {
		return "", fmt.Errorf("%w: the ticket reference cannot be used in a conditions query", psa.ErrBeforeWrite)
	}
	company, err := c.company(ctx, t.ExternalCompanyID)
	if err != nil {
		return "", err
	}
	var list []ticketRef
	q := url.Values{
		"conditions": {fmt.Sprintf(`externalXRef="%s" and company/id=%d`, t.Reference, company.ID)},
		"fields":     {"id,externalXRef,closedFlag,company"},
		"pageSize":   {"2"},
	}
	if _, err := c.do(ctx, http.MethodGet, "/service/tickets", q, nil, &list, false); err != nil {
		return "", err
	}
	var found []ticketRef
	for _, ticket := range list {
		if ticket.ExternalXRef == t.Reference && ticket.Company.ID == company.ID {
			found = append(found, ticket)
		}
	}
	switch len(found) {
	case 1:
		return strconv.FormatInt(found[0].ID, 10), nil
	case 0:
	default:
		return "", fmt.Errorf("%w: company %d has %d tickets with reference %s", psa.ErrBeforeWrite, company.ID, len(found), t.Reference)
	}
	body := map[string]any{
		"summary":            truncateRunes(t.Summary, maxTicketSummary),
		"board":              map[string]string{"name": c.cfg.Tickets.Board},
		"company":            map[string]int64{"id": company.ID},
		"initialDescription": t.Description,
		"externalXRef":       t.Reference,
	}
	if c.cfg.Tickets.NewStatus != "" {
		body["status"] = map[string]string{"name": c.cfg.Tickets.NewStatus}
	}
	var created ticketRef
	if _, err := c.do(ctx, http.MethodPost, "/service/tickets", nil, body, &created, true); err != nil {
		return "", err
	}
	if created.ID <= 0 {
		return "", errors.New("connectwise: the created ticket carries no ID")
	}
	return strconv.FormatInt(created.ID, 10), nil
}

type ticketNote struct {
	ID   int64  `json:"id"`
	Text string `json:"text"`
}

// AddNote adds a note to an open ticket, unless a note already carries its
// reference.
func (c *Client) AddNote(ctx context.Context, n psa.TicketNote) error {
	id, err := ticketID(n.TicketID)
	if err != nil {
		return err
	}
	return c.addNote(ctx, id, n.Reference, n.Text, false)
}

func (c *Client) addNote(ctx context.Context, id int64, reference, text string, resolution bool) error {
	marker := psa.NoteMarker(reference)
	path := "/service/tickets/" + strconv.FormatInt(id, 10) + "/notes"
	var notes []ticketNote
	if _, err := c.do(ctx, http.MethodGet, path, url.Values{"fields": {"id,text"}, "pageSize": {"1000"}}, nil, &notes, false); err != nil {
		return err
	}
	for _, note := range notes {
		if strings.Contains(note.Text, marker) {
			return nil
		}
	}
	body := map[string]any{"text": strings.TrimSpace(text) + "\n\n" + marker, "detailDescriptionFlag": true, "resolutionFlag": resolution}
	_, err := c.do(ctx, http.MethodPost, path, nil, body, nil, true)
	return err
}

// CloseTicket notes the resolution and moves the ticket to the closed
// status. A ticket already closed, or deleted at the PSA, is left alone.
func (c *Client) CloseTicket(ctx context.Context, cl psa.TicketClose) error {
	if c.cfg.Tickets == nil {
		return fmt.Errorf("%w: this target opens no tickets", psa.ErrBeforeWrite)
	}
	id, err := ticketID(cl.TicketID)
	if err != nil {
		return err
	}
	var ticket ticketRef
	status, err := c.do(ctx, http.MethodGet, "/service/tickets/"+strconv.FormatInt(id, 10), url.Values{"fields": {"id,closedFlag,company,externalXRef"}}, nil, &ticket, false)
	if status == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if ticket.ClosedFlag {
		return nil
	}
	if err := c.addNote(ctx, id, cl.Reference, cl.Resolution, true); err != nil {
		return err
	}
	patch := []map[string]any{{"op": "replace", "path": "status", "value": map[string]string{"name": c.cfg.Tickets.ClosedStatus}}}
	_, err = c.do(ctx, http.MethodPatch, "/service/tickets/"+strconv.FormatInt(id, 10), nil, patch, nil, true)
	return err
}

func ticketID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: %q is not a ConnectWise ticket ID", psa.ErrBeforeWrite, raw)
	}
	return id, nil
}

// truncateRunes bounds s to n runes.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
