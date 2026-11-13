// SPDX-License-Identifier: BUSL-1.1

// Package pax8 is the Pax8 Usage API client of the Provider billing sync
// (MSP-8), written from Pax8's public developer reference: usage lines are
// uploaded with POST /v2/usage/lines?subscriptionId=…&billingPeriod=yyyy-MM
// as an array (at most 50) of {productId, quantity, summaryKey,
// summaryDisplayName, unitOfMeasurement}, and lines posted the same day with
// the same subscription and summary key overwrite each other. The bearer
// token comes from an OAuth2 client-credentials exchange (the token URL and
// audience are configuration: Pax8 issues them at vendor onboarding).
//
// A customer's company in a Pax8 target is its Pax8 subscription ID. Each
// period posts one line per configured product, its quantity the period's
// figure and its summary key stable per meter, so a retry the same day
// overwrites rather than adds.
package pax8

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/psa"
)

// Product is the Pax8 product and unit a meter's line carries.
type Product struct {
	ProductID         string
	UnitOfMeasurement string
}

// Config is one Pax8 vendor integration.
type Config struct {
	// BaseURL is the API root, https://api.pax8.com.
	BaseURL string
	// TokenURL and Audience are the OAuth2 client-credentials exchange Pax8
	// issues at vendor onboarding.
	TokenURL string
	Audience string
	// ClientID is the vendor application's client ID.
	ClientID string
	// Products maps a meter to its Pax8 product and unit.
	Products map[string]Product
}

// Credentials are the vendor application's client secret, borrowed for one
// call.
type Credentials struct {
	ClientSecret []byte
}

// Client speaks to the Pax8 Usage API.
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
}

const maxResponse = 1 << 20

// UUIDPattern is a Pax8 subscription or product ID.
var UUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	for _, raw := range []string{cfg.BaseURL, cfg.TokenURL} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("pax8: the target needs absolute API and token URLs")
		}
	}
	if httpClient == nil || strings.TrimSpace(cfg.ClientID) == "" || len(creds.ClientSecret) == 0 {
		return nil, errors.New("pax8: the target needs its client ID and client secret")
	}
	for meter, p := range cfg.Products {
		if !UUIDPattern.MatchString(p.ProductID) || strings.TrimSpace(p.UnitOfMeasurement) == "" {
			return nil, fmt.Errorf("pax8: the product of %s needs a product ID and a unit of measurement", meter)
		}
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

// signIn exchanges the client credentials for an access token, kept only
// for this client's lifetime (one delivery).
func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	head, err := json.Marshal(map[string]string{"grant_type": "client_credentials", "client_id": c.cfg.ClientID, "audience": c.cfg.Audience})
	if err != nil {
		return fmt.Errorf("%w: pax8: encode the token request: %v", psa.ErrBeforeWrite, err)
	}
	secretJSON := appendJSONString(nil, c.creds.ClientSecret)
	body := append(append(append(head[:len(head)-1:len(head)-1], []byte(`,"client_secret":`)...), secretJSON...), '}')
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: pax8: build the token request: %v", psa.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	for i := range body {
		body[i] = 0
	}
	for i := range secretJSON {
		secretJSON[i] = 0
	}
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("%w: pax8: sign in: %v", psa.ErrBeforeWrite, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: pax8: sign in answered %d%s", psa.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(raw, &token) != nil || token.AccessToken == "" {
		return fmt.Errorf("%w: pax8: sign in returned no access token", psa.ErrBeforeWrite)
	}
	c.bearer = "Bearer " + token.AccessToken
	return nil
}

// appendJSONString writes src as a JSON string onto dst byte by byte, so
// the secret never becomes a Go string that cannot be wiped.
func appendJSONString(dst, src []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for _, b := range src {
		switch {
		case b == '"' || b == '\\':
			dst = append(dst, '\\', b)
		case b < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[b>>4], hex[b&15])
		default:
			dst = append(dst, b)
		}
	}
	return append(dst, '"')
}

// PushUsage posts the period's lines for the customer's subscription.
func (c *Client) PushUsage(ctx context.Context, p psa.UsagePeriod) (psa.UsageOutcome, error) {
	var out psa.UsageOutcome
	subscription := strings.TrimSpace(p.ExternalCompanyID)
	if !UUIDPattern.MatchString(subscription) {
		return out, fmt.Errorf("%w: a Pax8 subscription ID is a UUID, not %q", psa.ErrBeforeWrite, subscription)
	}
	values := map[string]int64{}
	for _, l := range p.Lines {
		values[l.Meter] = l.Value
	}
	meters := make([]string, 0, len(c.cfg.Products))
	for meter := range c.cfg.Products {
		meters = append(meters, meter)
	}
	sort.Strings(meters)
	if len(meters) == 0 || len(meters) > 50 {
		return out, fmt.Errorf("%w: a Pax8 usage upload carries 1-50 lines", psa.ErrBeforeWrite)
	}
	lines := make([]map[string]any, 0, len(meters))
	for _, meter := range meters {
		prod := c.cfg.Products[meter]
		lines = append(lines, map[string]any{
			"productId":          prod.ProductID,
			"quantity":           values[meter],
			"summaryKey":         "trstctl-" + meter,
			"summaryDisplayName": "trstctl " + strings.ReplaceAll(meter, "_", " "),
			"unitOfMeasurement":  prod.UnitOfMeasurement,
		})
		out.Set = append(out.Set, meter)
	}
	if err := c.signIn(ctx); err != nil {
		return psa.UsageOutcome{}, err
	}
	q := url.Values{"subscriptionId": {subscription}, "billingPeriod": {p.PeriodStart.UTC().Format("2006-01")}, "overwriteSameDayUsage": {"true"}}
	raw, err := json.Marshal(lines)
	if err != nil {
		return psa.UsageOutcome{}, fmt.Errorf("%w: pax8: encode usage lines: %v", psa.ErrBeforeWrite, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/v2/usage/lines?"+q.Encode(), bytes.NewReader(raw))
	if err != nil {
		return psa.UsageOutcome{}, fmt.Errorf("%w: pax8: build the upload: %v", psa.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.bearer)
	resp, err := c.http.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return psa.UsageOutcome{}, fmt.Errorf("pax8: POST /v2/usage/lines: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		out.Status = resp.StatusCode
		return out, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return psa.UsageOutcome{}, fmt.Errorf("%w: pax8: POST /v2/usage/lines answered %d%s", psa.ErrBeforeWrite, resp.StatusCode, c.errorDetail(body))
	case resp.StatusCode >= 400 && resp.StatusCode <= 499 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests:
		return psa.UsageOutcome{}, fmt.Errorf("%w: pax8: POST /v2/usage/lines answered %d%s", psa.ErrRefused, resp.StatusCode, c.errorDetail(body))
	default:
		return psa.UsageOutcome{}, fmt.Errorf("pax8: POST /v2/usage/lines answered %d%s", resp.StatusCode, c.errorDetail(body))
	}
}

// errorDetail renders a JSON error's message or error field, bounded,
// printable, and with any echo of the secret removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
		Details string `json:"details"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.Error, body.Message, body.Details} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.ClientSecret, []byte("[redacted]"))
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

// OpenTicket, AddNote and CloseTicket: the Pax8 Usage API carries usage only.
func (c *Client) OpenTicket(context.Context, psa.TicketOpen) (string, error) {
	return "", fmt.Errorf("%w: a Pax8 target opens no tickets", psa.ErrBeforeWrite)
}

// AddNote is not offered by the Pax8 Usage API.
func (c *Client) AddNote(context.Context, psa.TicketNote) error {
	return fmt.Errorf("%w: a Pax8 target opens no tickets", psa.ErrBeforeWrite)
}

// CloseTicket is not offered by the Pax8 Usage API.
func (c *Client) CloseTicket(context.Context, psa.TicketClose) error {
	return fmt.Errorf("%w: a Pax8 target opens no tickets", psa.ErrBeforeWrite)
}
