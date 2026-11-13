// SPDX-License-Identifier: BUSL-1.1

// Package itglue is the IT Glue client of the Provider plane (MSP-14),
// written from IT Glue's public API reference (api.itglue.com/developer): the
// x-api-key header, JSON:API bodies (application/vnd.api+json), and flexible
// assets of one flexible-asset type, listed by organization and name (GET
// /flexible_assets with filter[flexible-asset-type-id],
// filter[organization-id] and filter[name]), created (POST /flexible_assets)
// and replaced (PATCH /flexible_assets/{id}, which clears any trait it does
// not send). Traits are keyed by their name-keys.
package itglue

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

// Traits are the name-keys of the flexible-asset type's fields a record
// fills; Title and Inventory are required, the rest optional.
type Traits struct {
	Title      string
	Inventory  string
	NextExpiry string
	Count      string
	Link       string
}

// Config is one IT Glue account.
type Config struct {
	// BaseURL is the regional API host: https://api.itglue.com,
	// https://api.eu.itglue.com or https://api.au.itglue.com.
	BaseURL string
	// FlexibleAssetTypeID is the flexible-asset type the records use.
	FlexibleAssetTypeID int64
	Traits              Traits
}

// Credentials are the API key, borrowed for one call.
type Credentials struct {
	APIKey []byte
}

// Client speaks to one IT Glue account.
type Client struct {
	cfg   Config
	http  *http.Client
	creds Credentials
}

const (
	maxResponse = 1 << 22
	mediaType   = "application/vnd.api+json"
)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("itglue: the target needs an absolute API URL")
	}
	if httpClient == nil || len(creds.APIKey) == 0 || cfg.FlexibleAssetTypeID <= 0 || cfg.Traits.Title == "" || cfg.Traits.Inventory == "" {
		return nil, errors.New("itglue: the target needs its API key, flexible-asset type and the title and inventory traits")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

func orgID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: an IT Glue organization ID is a number, not %q", docsys.ErrBeforeWrite, raw)
	}
	return id, nil
}

type asset struct {
	ID         string `json:"id"`
	Attributes struct {
		OrganizationID int64  `json:"organization-id"`
		Name           string `json:"name"`
	} `json:"attributes"`
}

// Find returns the record of this type titled title under the organization.
func (c *Client) Find(ctx context.Context, organization, title string) (string, bool, error) {
	org, err := orgID(organization)
	if err != nil {
		return "", false, err
	}
	q := url.Values{"filter[flexible-asset-type-id]": {strconv.FormatInt(c.cfg.FlexibleAssetTypeID, 10)},
		"filter[organization-id]": {strconv.FormatInt(org, 10)}, "filter[name]": {title}, "page[size]": {"50"}}
	var out struct {
		Data []asset `json:"data"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/flexible_assets", q, nil, &out, false); err != nil {
		return "", false, err
	}
	for _, a := range out.Data {
		if a.Attributes.OrganizationID == org && a.ID != "" {
			return a.ID, true, nil
		}
	}
	return "", false, nil
}

func (c *Client) traits(content docsys.Content) map[string]any {
	t := map[string]any{c.cfg.Traits.Title: content.Title, c.cfg.Traits.Inventory: content.HTML}
	if c.cfg.Traits.NextExpiry != "" {
		if content.NextExpiry != nil {
			t[c.cfg.Traits.NextExpiry] = content.NextExpiry.UTC().Format("2006-01-02")
		} else {
			t[c.cfg.Traits.NextExpiry] = nil
		}
	}
	if c.cfg.Traits.Count != "" {
		t[c.cfg.Traits.Count] = content.Count
	}
	if c.cfg.Traits.Link != "" {
		t[c.cfg.Traits.Link] = content.Link
	}
	return t
}

// Create writes a new record under the organization.
func (c *Client) Create(ctx context.Context, organization string, content docsys.Content) (string, error) {
	org, err := orgID(organization)
	if err != nil {
		return "", err
	}
	body := map[string]any{"data": map[string]any{"type": "flexible-assets", "attributes": map[string]any{
		"organization-id": org, "flexible-asset-type-id": c.cfg.FlexibleAssetTypeID, "traits": c.traits(content)}}}
	var out struct {
		Data asset `json:"data"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/flexible_assets", nil, body, &out, true); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", errors.New("itglue: the created flexible asset came back without an ID")
	}
	return out.Data.ID, nil
}

// Update replaces the record's traits.
func (c *Client) Update(ctx context.Context, organization, recordID string, content docsys.Content) error {
	if _, err := orgID(organization); err != nil {
		return err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(recordID), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("%w: an IT Glue flexible asset ID is a number, not %q", docsys.ErrBeforeWrite, recordID)
	}
	body := map[string]any{"data": map[string]any{"type": "flexible-assets", "attributes": map[string]any{"traits": c.traits(content)}}}
	status, err := c.do(ctx, http.MethodPatch, "/flexible_assets/"+strconv.FormatInt(id, 10), nil, body, nil, true)
	if status == http.StatusNotFound {
		return fmt.Errorf("%w: flexible asset %d", docsys.ErrRecordGone, id)
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
	req.Header.Set("Accept", mediaType)
	if body != nil {
		req.Header.Set("Content-Type", mediaType)
	}
	req.Header.Set("x-api-key", secrettext.Prefixed("", c.creds.APIKey))
	label := method + " " + path
	resp, err := c.http.Do(req)
	if err != nil {
		if !write {
			return 0, fmt.Errorf("%w: itglue: %s: %v", docsys.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("itglue: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("itglue: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data))
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
		return resp.StatusCode, fmt.Errorf("itglue: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("itglue: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders JSON:API errors (title and detail), bounded,
// printable, with any echo of the API key removed.
func (c *Client) errorDetail(raw []byte) string {
	var body struct {
		Errors []struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, e := range body.Errors {
		if text := strings.TrimSpace(strings.TrimSpace(e.Title) + " " + strings.TrimSpace(e.Detail)); text != "" {
			parts = append(parts, text)
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
