// SPDX-License-Identifier: BUSL-1.1

// Package gradient is the Gradient Synthesize client of the Provider
// billing sync (MSP-7), written from Gradient's public vendor API
// reference: the GRADIENT-TOKEN header and POST
// /api/vendor-api/service/{serviceId}/count {unitCount, accountId}. Gradient
// forwards a vendor's counts to whichever PSA the MSP connected there, so it
// covers the PSAs the direct connectors do not.
//
// A count is absolute (the account's units of a service), so a retry after a
// lost answer posts the same number and never adds to it. Gradient answers
// 404 when the MSP has not mapped the account or the service yet: nothing was
// counted, and the period is refused rather than guessed.
package gradient

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
	"trstctl.com/trstctl/internal/secrettext"
)

// Config is one Gradient vendor integration.
type Config struct {
	// BaseURL is the API root, https://app.usegradient.com.
	BaseURL string
	// Services maps a meter to the Gradient service (SKU) whose count
	// carries it.
	Services map[string]string
}

// Credentials are the GRADIENT-TOKEN value the MSP's Gradient account
// issues for this vendor, borrowed for one call.
type Credentials struct {
	Token []byte
}

// Client speaks to Gradient's vendor API.
type Client struct {
	cfg   Config
	http  *http.Client
	creds Credentials
}

const maxResponse = 1 << 16

// ServiceIDPattern is a Gradient service ID as it sits in the URL path.
var ServiceIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("gradient: the target needs an absolute API base URL")
	}
	if httpClient == nil || len(creds.Token) == 0 {
		return nil, errors.New("gradient: the target needs its GRADIENT-TOKEN")
	}
	for meter, service := range cfg.Services {
		if !ServiceIDPattern.MatchString(service) {
			return nil, fmt.Errorf("gradient: the service of %s is not a Gradient service ID", meter)
		}
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

// PushUsage posts each configured service's count for the customer's
// account. A 404 on the first count (the account or service is not mapped
// in Gradient yet) refuses the period with nothing counted.
func (c *Client) PushUsage(ctx context.Context, p psa.UsagePeriod) (psa.UsageOutcome, error) {
	var out psa.UsageOutcome
	account := strings.TrimSpace(p.ExternalCompanyID)
	if account == "" || len(account) > 128 || strings.ContainsFunc(account, unicode.IsControl) {
		return out, fmt.Errorf("%w: a Gradient account ID is 1-128 printable characters", psa.ErrBeforeWrite)
	}
	values := map[string]int64{}
	for _, l := range p.Lines {
		values[l.Meter] = l.Value
	}
	meters := make([]string, 0, len(c.cfg.Services))
	for meter := range c.cfg.Services {
		meters = append(meters, meter)
	}
	sort.Strings(meters)
	for i, meter := range meters {
		status, err := c.count(ctx, c.cfg.Services[meter], account, values[meter], i == 0)
		if err != nil {
			return out, err
		}
		out.Set = append(out.Set, meter)
		out.Status = status
	}
	return out, nil
}

// count posts one service's absolute unit count for one account.
func (c *Client) count(ctx context.Context, service, account string, units int64, first bool) (int, error) {
	raw, err := json.Marshal(map[string]any{"unitCount": units, "accountId": account})
	if err != nil {
		return 0, fmt.Errorf("%w: gradient: encode a count: %v", psa.ErrBeforeWrite, err)
	}
	path := "/api/vendor-api/service/" + url.PathEscape(service) + "/count"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, fmt.Errorf("%w: gradient: build a count: %v", psa.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("GRADIENT-TOKEN", secrettext.Prefixed("", c.creds.Token))
	resp, err := c.http.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return 0, fmt.Errorf("gradient: POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return resp.StatusCode, nil
	case resp.StatusCode == http.StatusNotFound && first:
		return resp.StatusCode, fmt.Errorf("%w: gradient: service %s has no account map for account %q yet (map it in Gradient)%s",
			psa.ErrBeforeWrite, service, account, c.errorDetail(body))
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		if first {
			return resp.StatusCode, fmt.Errorf("%w: gradient: POST %s answered %d%s", psa.ErrBeforeWrite, path, resp.StatusCode, c.errorDetail(body))
		}
		return resp.StatusCode, fmt.Errorf("%w: gradient: POST %s answered %d%s", psa.ErrRefused, path, resp.StatusCode, c.errorDetail(body))
	case resp.StatusCode >= 400 && resp.StatusCode <= 499 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests:
		return resp.StatusCode, fmt.Errorf("%w: gradient: POST %s answered %d%s", psa.ErrRefused, path, resp.StatusCode, c.errorDetail(body))
	default:
		return resp.StatusCode, fmt.Errorf("gradient: POST %s answered %d%s", path, resp.StatusCode, c.errorDetail(body))
	}
}

// errorDetail renders the documented {statusCode, message} body, bounded,
// printable, and with any echo of the token removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) != nil || strings.TrimSpace(body.Message) == "" {
		return ""
	}
	text := bytes.ReplaceAll([]byte(body.Message), c.creds.Token, []byte("[redacted]"))
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

// OpenTicket, AddNote and CloseTicket: Gradient carries usage only.
func (c *Client) OpenTicket(context.Context, psa.TicketOpen) (string, error) {
	return "", fmt.Errorf("%w: a Gradient target opens no tickets", psa.ErrBeforeWrite)
}

// AddNote is not offered by Gradient.
func (c *Client) AddNote(context.Context, psa.TicketNote) error {
	return fmt.Errorf("%w: a Gradient target opens no tickets", psa.ErrBeforeWrite)
}

// CloseTicket is not offered by Gradient.
func (c *Client) CloseTicket(context.Context, psa.TicketClose) error {
	return fmt.Errorf("%w: a Gradient target opens no tickets", psa.ErrBeforeWrite)
}
