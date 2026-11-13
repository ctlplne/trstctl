// SPDX-License-Identifier: BUSL-1.1

// Package hudu is the Hudu client of the Provider plane (MSP-15), written
// from the calls Hudu's published API clients make against /api/v1: the
// x-api-key header, assets of one asset layout listed by company, layout and
// name (GET /api/v1/assets), created under a company (POST
// /api/v1/companies/{company}/assets) and replaced (PUT
// /api/v1/companies/{company}/assets/{id}), each body an {"asset": ...}
// object whose custom_fields is a list holding one object keyed by the
// layout's field labels in lowercase with underscores.
package hudu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/docsys"
	"trstctl.com/trstctl/internal/secrettext"
)

// Fields are the layout's field keys (labels in lowercase with
// underscores) a record fills; Inventory is required, the rest optional.
type Fields struct {
	Inventory  string
	NextExpiry string
	Count      string
	Link       string
}

// Config is one Hudu instance.
type Config struct {
	// BaseURL is the instance, e.g. https://msp.huducloud.com.
	BaseURL string
	// AssetLayoutID is the asset layout of the records.
	AssetLayoutID int64
	Fields        Fields
}

// Credentials are the API key, borrowed for one call.
type Credentials struct {
	APIKey []byte
}

// Client speaks to one Hudu instance.
type Client struct {
	cfg   Config
	http  *http.Client
	creds Credentials
}

const maxResponse = 1 << 22

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("hudu: the target needs an absolute instance URL")
	}
	if httpClient == nil || len(creds.APIKey) == 0 || cfg.AssetLayoutID <= 0 || cfg.Fields.Inventory == "" {
		return nil, errors.New("hudu: the target needs its API key, asset layout and the inventory field")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

func companyID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: a Hudu company ID is a number, not %q", docsys.ErrBeforeWrite, raw)
	}
	return id, nil
}

type asset struct {
	ID            int64  `json:"id"`
	CompanyID     int64  `json:"company_id"`
	AssetLayoutID int64  `json:"asset_layout_id"`
	Name          string `json:"name"`
	Archived      bool   `json:"archived"`
}

// Find returns the record of this layout named title under the company.
func (c *Client) Find(ctx context.Context, company, title string) (string, bool, error) {
	cid, err := companyID(company)
	if err != nil {
		return "", false, err
	}
	q := url.Values{"company_id": {strconv.FormatInt(cid, 10)}, "asset_layout_id": {strconv.FormatInt(c.cfg.AssetLayoutID, 10)},
		"name": {title}, "page": {"1"}, "page_size": {"25"}}
	var out struct {
		Assets []asset `json:"assets"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/api/v1/assets", q, nil, &out, false); err != nil {
		return "", false, err
	}
	for _, a := range out.Assets {
		if a.CompanyID == cid && a.AssetLayoutID == c.cfg.AssetLayoutID && a.Name == title && !a.Archived && a.ID > 0 {
			return strconv.FormatInt(a.ID, 10), true, nil
		}
	}
	return "", false, nil
}

func (c *Client) body(content docsys.Content) map[string]any {
	fields := map[string]any{c.cfg.Fields.Inventory: content.HTML}
	if c.cfg.Fields.NextExpiry != "" {
		next := ""
		if content.NextExpiry != nil {
			next = content.NextExpiry.UTC().Format("2006-01-02")
		}
		fields[c.cfg.Fields.NextExpiry] = next
	}
	if c.cfg.Fields.Count != "" {
		fields[c.cfg.Fields.Count] = content.Count
	}
	if c.cfg.Fields.Link != "" {
		fields[c.cfg.Fields.Link] = content.Link
	}
	return map[string]any{"asset": map[string]any{"name": content.Title, "asset_layout_id": c.cfg.AssetLayoutID, "custom_fields": []any{fields}}}
}

// Create writes a new record under the company.
func (c *Client) Create(ctx context.Context, company string, content docsys.Content) (string, error) {
	cid, err := companyID(company)
	if err != nil {
		return "", err
	}
	var out struct {
		Asset asset `json:"asset"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/api/v1/companies/"+strconv.FormatInt(cid, 10)+"/assets", nil, c.body(content), &out, true); err != nil {
		return "", err
	}
	if out.Asset.ID <= 0 {
		return "", errors.New("hudu: the created asset came back without an ID")
	}
	return strconv.FormatInt(out.Asset.ID, 10), nil
}

// Update replaces the record's name and fields.
func (c *Client) Update(ctx context.Context, company, recordID string, content docsys.Content) error {
	cid, err := companyID(company)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(recordID), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("%w: a Hudu asset ID is a number, not %q", docsys.ErrBeforeWrite, recordID)
	}
	status, err := c.do(ctx, http.MethodPut, "/api/v1/companies/"+strconv.FormatInt(cid, 10)+"/assets/"+strconv.FormatInt(id, 10), nil,
		c.body(content), nil, true)
	if status == http.StatusNotFound {
		return fmt.Errorf("%w: asset %d", docsys.ErrRecordGone, id)
	}
	return err
}

// do sends one API request. A lookup failure is always before anything was
// written; a write's 4xx other than 408 and 429 is the definitive refusal.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, write bool) (int, error) {
	target := c.cfg.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("%w: encode %s %s: %v", docsys.ErrBeforeWrite, method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, fmt.Errorf("%w: build %s %s: %v", docsys.ErrBeforeWrite, method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-api-key", secrettext.Prefixed("", c.creds.APIKey))
	label := method + " " + path
	resp, err := c.http.Do(req)
	if err != nil {
		if !write {
			return 0, fmt.Errorf("%w: hudu: %s: %v", docsys.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("hudu: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("hudu: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data))
		retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		switch {
		case !write || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return resp.StatusCode, fmt.Errorf("%w: %s", docsys.ErrBeforeWrite, cause)
		case !retryable:
			return resp.StatusCode, fmt.Errorf("%w: %s", docsys.ErrRefused, cause)
		default:
			return resp.StatusCode, errors.New(cause)
		}
	}
	if readErr != nil {
		return resp.StatusCode, fmt.Errorf("hudu: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("hudu: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the error or message the API answers, bounded,
// printable, with any echo of the API key removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.Error, body.Message} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.APIKey, []byte("[redacted]"))
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
