// SPDX-License-Identifier: BUSL-1.1

// Package ninjaone is the NinjaOne RMM client of the Provider plane (MSP-9),
// written from NinjaOne's public API v2 OpenAPI description and its published
// client: an OAuth2 client-credentials token at /ws/oauth/token (scopes
// monitoring, management, control), the devices of an organization
// (/v2/organization/{id}/devices, paged by pageSize and after), one device
// (/v2/device/{id}), running an automation-library script on a device
// (POST /v2/device/{id}/script/run, answered 204) and the device's custom
// fields (PATCH /v2/device/{id}/custom-fields).
package ninjaone

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

	"trstctl.com/trstctl/internal/rmm"
)

// Config is one NinjaOne instance.
type Config struct {
	// BaseURL is the regional host, e.g. https://app.ninjarmm.com.
	BaseURL string
	// ClientID is the API client's ID.
	ClientID string
	// Scripts are the automation-library script IDs of each action.
	Scripts map[rmm.Action]int64
	// RunAs is the script credential role ("system" when empty).
	RunAs string
	// HealthField is the device custom field the agent's health is written
	// to; empty reports nothing.
	HealthField string
}

// Credentials are the API client's secret, borrowed for one call.
type Credentials struct {
	ClientSecret []byte
}

// Client speaks to one NinjaOne instance; it signs in once per client and
// keeps the token only for its own lifetime (one delivery).
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
}

const (
	maxResponse = 1 << 21
	pageSize    = 500
	maxPages    = 20
)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("ninjaone: the target needs an absolute instance URL")
	}
	if httpClient == nil || strings.TrimSpace(cfg.ClientID) == "" || len(creds.ClientSecret) == 0 {
		return nil, errors.New("ninjaone: the target needs its client ID and client secret")
	}
	if cfg.RunAs == "" {
		cfg.RunAs = "system"
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "scope": {"monitoring management control"}}
	body := rmm.AppendFormEscaped([]byte(form.Encode()+"&client_secret="), c.creds.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/ws/oauth/token", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: ninjaone: build the token request: %v", rmm.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	for i := range body {
		body[i] = 0
	}
	if err != nil {
		return fmt.Errorf("%w: ninjaone: sign in: %v", rmm.ErrBeforeWrite, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: ninjaone: sign in answered %d%s", rmm.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(raw, &token) != nil || token.AccessToken == "" {
		return fmt.Errorf("%w: ninjaone: sign in returned no access token", rmm.ErrBeforeWrite)
	}
	c.bearer = "Bearer " + token.AccessToken
	return nil
}

type device struct {
	ID             int64  `json:"id"`
	OrganizationID int64  `json:"organizationId"`
	SystemName     string `json:"systemName"`
	DNSName        string `json:"dnsName"`
	DisplayName    string `json:"displayName"`
	Offline        bool   `json:"offline"`
}

func (d device) public() rmm.Device {
	name := d.SystemName
	if name == "" {
		name = d.DNSName
	}
	if name == "" {
		name = d.DisplayName
	}
	return rmm.Device{ID: strconv.FormatInt(d.ID, 10), OrgID: strconv.FormatInt(d.OrganizationID, 10), Name: name, Online: !d.Offline}
}

func numericID(kind, raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: a NinjaOne %s ID is a number, not %q", rmm.ErrBeforeWrite, kind, raw)
	}
	return id, nil
}

// ListDevices lists an organization's devices, following the after cursor.
func (c *Client) ListDevices(ctx context.Context, orgID string) ([]rmm.Device, error) {
	org, err := numericID("organization", orgID)
	if err != nil {
		return nil, err
	}
	var out []rmm.Device
	after := int64(0)
	for page := 0; page < maxPages; page++ {
		q := url.Values{"pageSize": {strconv.Itoa(pageSize)}}
		if after > 0 {
			q.Set("after", strconv.FormatInt(after, 10))
		}
		var list []device
		if _, err := c.do(ctx, http.MethodGet, "/v2/organization/"+strconv.FormatInt(org, 10)+"/devices", q, nil, &list, false); err != nil {
			return nil, err
		}
		for _, d := range list {
			if d.OrganizationID == org {
				out = append(out, d.public())
			}
			if d.ID > after {
				after = d.ID
			}
		}
		if len(list) < pageSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: ninjaone: organization %d lists more than %d devices", rmm.ErrBeforeWrite, org, pageSize*maxPages)
}

// Device reads one device.
func (c *Client) Device(ctx context.Context, deviceID string) (rmm.Device, bool, error) {
	id, err := numericID("device", deviceID)
	if err != nil {
		return rmm.Device{}, false, err
	}
	var d device
	status, err := c.do(ctx, http.MethodGet, "/v2/device/"+strconv.FormatInt(id, 10), nil, nil, &d, false)
	if status == http.StatusNotFound {
		return rmm.Device{}, false, nil
	}
	if err != nil {
		return rmm.Device{}, false, err
	}
	if d.ID != id {
		return rmm.Device{}, false, fmt.Errorf("%w: NinjaOne answered device %d for device %d", rmm.ErrBeforeWrite, d.ID, id)
	}
	return d.public(), true, nil
}

// RunAction runs the action's automation-library script on the device. An
// install passes the server, server name, identity and one-time token as
// the script's parameters; the request body carrying the token is assembled
// from bytes and wiped once sent. NinjaOne answers 204 with no job ID.
func (c *Client) RunAction(ctx context.Context, deviceID string, action rmm.Action, install *rmm.InstallParams) (string, error) {
	id, err := numericID("device", deviceID)
	if err != nil {
		return "", err
	}
	script, ok := c.cfg.Scripts[action]
	if !ok || script <= 0 {
		return "", fmt.Errorf("%w: ninjaone: no script is configured for %s", rmm.ErrBeforeWrite, action)
	}
	params := []byte{}
	if action == rmm.ActionInstall {
		if install == nil || len(install.Token) == 0 {
			return "", fmt.Errorf("%w: ninjaone: an install needs its enrollment token", rmm.ErrBeforeWrite)
		}
		params = append(params, "-Server "+strconv.Quote(install.Server)+" -ServerName "+strconv.Quote(install.ServerName)+
			" -Identity "+strconv.Quote(install.Identity)+" -Token \""...)
		params = append(params, install.Token...)
		params = append(params, '"')
	}
	head, err := json.Marshal(map[string]any{"type": "SCRIPT", "id": script, "runAs": c.cfg.RunAs})
	if err != nil {
		return "", fmt.Errorf("%w: ninjaone: encode the script run: %v", rmm.ErrBeforeWrite, err)
	}
	body := append(head[:len(head)-1:len(head)-1], []byte(`,"parameters":`)...)
	body = rmm.AppendJSONString(body, params)
	body = append(body, '}')
	defer func() {
		for i := range params {
			params[i] = 0
		}
		for i := range body {
			body[i] = 0
		}
	}()
	var token []byte
	if install != nil {
		token = install.Token
	}
	_, err = c.do(ctx, http.MethodPost, "/v2/device/"+strconv.FormatInt(id, 10)+"/script/run", nil, json.RawMessage(body), nil, true, token)
	return "", err
}

// ReportHealth writes the health summary to the configured custom field.
func (c *Client) ReportHealth(ctx context.Context, deviceID, summary string) error {
	if c.cfg.HealthField == "" {
		return nil
	}
	id, err := numericID("device", deviceID)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, "/v2/device/"+strconv.FormatInt(id, 10)+"/custom-fields", nil,
		map[string]string{c.cfg.HealthField: summary}, nil, true)
	return err
}

// do sends one API request. A lookup failure is always before anything
// ran; a write's 4xx other than 408 and 429 is the RMM's definitive refusal.
// redact names request secrets (an install's token) an error must not echo.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, write bool, redact ...[]byte) (int, error) {
	if err := c.signIn(ctx); err != nil {
		return 0, err
	}
	target := c.cfg.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	var raw []byte
	if body != nil {
		var err error
		if pre, ok := body.(json.RawMessage); ok {
			raw = pre
		} else if raw, err = json.Marshal(body); err != nil {
			return 0, fmt.Errorf("%w: encode %s %s: %v", rmm.ErrBeforeWrite, method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, fmt.Errorf("%w: build %s %s: %v", rmm.ErrBeforeWrite, method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", c.bearer)
	label := method + " " + path
	resp, err := c.http.Do(req)
	if err != nil {
		if !write {
			return 0, fmt.Errorf("%w: ninjaone: %s: %v", rmm.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("ninjaone: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("ninjaone: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data, redact...))
		retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		switch {
		case !write:
			return resp.StatusCode, fmt.Errorf("%w: %s", rmm.ErrBeforeWrite, cause)
		case !retryable:
			return resp.StatusCode, fmt.Errorf("%w: %s", rmm.ErrRefused, cause)
		default:
			return resp.StatusCode, errors.New(cause)
		}
	}
	if readErr != nil {
		return resp.StatusCode, fmt.Errorf("ninjaone: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("ninjaone: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the {resultCode, errorMessage} body the published
// client reads, bounded, printable, with any echo of the secret or of a
// request secret removed.
func (c *Client) errorDetail(raw []byte, redact ...[]byte) string {
	var body struct {
		ResultCode   string `json:"resultCode"`
		ErrorMessage string `json:"errorMessage"`
		Error        string `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.ResultCode, body.ErrorMessage, body.Error} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.ClientSecret, []byte("[redacted]"))
	for _, secret := range redact {
		if len(secret) > 0 {
			text = bytes.ReplaceAll(text, secret, []byte("[redacted]"))
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
