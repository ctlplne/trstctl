// SPDX-License-Identifier: BUSL-1.1

// Package ncentral is the N-able N-central client of the Provider plane
// (MSP-12), written from N-central's public REST API reference
// (developer.n-able.com): an access token from POST /api/auth/authenticate
// with the API user's JWT, a customer's devices
// (/api/org-units/{orgUnitId}/devices, paged by pageNumber and pageSize), one
// device (/api/devices/{deviceId}, wrapped in data), a script run as a direct
// scheduled task (POST /api/scheduled-tasks/direct) and a device custom
// property (PUT /api/devices/{deviceId}/custom-properties/{propertyId}).
package ncentral

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
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/secrettext"
)

// Config is one N-central server.
type Config struct {
	// BaseURL is the N-central server, e.g. https://ncentral.example.com.
	BaseURL string
	// Scripts are the script repository item IDs each action runs (each
	// with its API toggle on).
	Scripts map[rmm.Action]int64
	// CredentialType is the scheduled task's credential ("LocalSystem"
	// when empty).
	CredentialType string
	// HealthPropertyID is the device custom property the agent's health is
	// written to; 0 reports nothing.
	HealthPropertyID int64
}

// Credentials are the API user's JWT, borrowed for one call.
type Credentials struct {
	UserJWT []byte
}

// Client speaks to one N-central server; it authenticates once per client
// and keeps the access token only for its own lifetime (one delivery).
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
	// customers caches device → customer for the task a script runs as.
	customers map[int64]int64
	// now names each task uniquely (N-central refuses a duplicate name).
	now func() time.Time
}

const (
	maxResponse = 1 << 21
	pageSize    = 500
	maxPages    = 40
)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("ncentral: the target needs an absolute server URL")
	}
	if httpClient == nil || len(creds.UserJWT) == 0 {
		return nil, errors.New("ncentral: the target needs the API user's JWT")
	}
	if cfg.CredentialType == "" {
		cfg.CredentialType = "LocalSystem"
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds, customers: map[int64]int64{}, now: time.Now}, nil
}

func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/auth/authenticate", nil)
	if err != nil {
		return fmt.Errorf("%w: ncentral: build the authenticate request: %v", rmm.ErrBeforeWrite, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.creds.UserJWT))
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: ncentral: authenticate: %v", rmm.ErrBeforeWrite, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: ncentral: authenticate answered %d%s", rmm.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	var out struct {
		Tokens struct {
			Access struct {
				Token string `json:"token"`
			} `json:"access"`
		} `json:"tokens"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Tokens.Access.Token == "" {
		return fmt.Errorf("%w: ncentral: authenticate returned no access token", rmm.ErrBeforeWrite)
	}
	c.bearer = "Bearer " + out.Tokens.Access.Token
	return nil
}

type device struct {
	DeviceID       int64  `json:"deviceId"`
	CustomerID     int64  `json:"customerId"`
	OrgUnitID      int64  `json:"orgUnitId"`
	LongName       string `json:"longName"`
	DiscoveredName string `json:"discoveredName"`
	IsProbe        bool   `json:"isProbe"`
}

func (d device) public() rmm.Device {
	name := d.LongName
	if name == "" {
		name = d.DiscoveredName
	}
	return rmm.Device{ID: strconv.FormatInt(d.DeviceID, 10), OrgID: strconv.FormatInt(d.CustomerID, 10), Name: name}
}

func numericID(kind, raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: an N-central %s ID is a number, not %q", rmm.ErrBeforeWrite, kind, raw)
	}
	return id, nil
}

// ListDevices lists a customer's devices through its org unit, page by page.
func (c *Client) ListDevices(ctx context.Context, customerID string) ([]rmm.Device, error) {
	customer, err := numericID("customer", customerID)
	if err != nil {
		return nil, err
	}
	var out []rmm.Device
	for page := 1; page <= maxPages; page++ {
		var list struct {
			Data       []device `json:"data"`
			TotalPages int      `json:"totalPages"`
		}
		q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(pageSize)}}
		if _, err := c.do(ctx, http.MethodGet, "/api/org-units/"+strconv.FormatInt(customer, 10)+"/devices", q, nil, &list, false); err != nil {
			return nil, err
		}
		for _, d := range list.Data {
			if d.CustomerID == customer && !d.IsProbe {
				c.customers[d.DeviceID] = d.CustomerID
				out = append(out, d.public())
			}
		}
		if page >= list.TotalPages || len(list.Data) == 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: ncentral: customer %d lists more than %d devices", rmm.ErrBeforeWrite, customer, pageSize*maxPages)
}

// Device reads one device.
func (c *Client) Device(ctx context.Context, deviceID string) (rmm.Device, bool, error) {
	id, err := numericID("device", deviceID)
	if err != nil {
		return rmm.Device{}, false, err
	}
	var out struct {
		Data device `json:"data"`
	}
	status, err := c.do(ctx, http.MethodGet, "/api/devices/"+strconv.FormatInt(id, 10), nil, nil, &out, false)
	if status == http.StatusNotFound {
		return rmm.Device{}, false, nil
	}
	if err != nil {
		return rmm.Device{}, false, err
	}
	if out.Data.DeviceID != id {
		return rmm.Device{}, false, fmt.Errorf("%w: N-central answered device %d for device %d", rmm.ErrBeforeWrite, out.Data.DeviceID, id)
	}
	c.customers[id] = out.Data.CustomerID
	return out.Data.public(), true, nil
}

// The script parameters an install's task receives.
const (
	ParamServer     = "TrstctlServer"
	ParamServerName = "TrstctlServerName"
	ParamIdentity   = "TrstctlIdentity"
	ParamToken      = "TrstctlToken"
)

// RunAction runs the action's script on the device as a direct scheduled
// task and returns the task ID. An install passes the server, server name,
// identity and one-time token as the script's parameters; the request body
// carrying the token is assembled from bytes and wiped once sent.
func (c *Client) RunAction(ctx context.Context, deviceID string, action rmm.Action, install *rmm.InstallParams) (string, error) {
	id, err := numericID("device", deviceID)
	if err != nil {
		return "", err
	}
	script, ok := c.cfg.Scripts[action]
	if !ok || script <= 0 {
		return "", fmt.Errorf("%w: ncentral: no script is configured for %s", rmm.ErrBeforeWrite, action)
	}
	customer, known := c.customers[id]
	if !known {
		if _, found, err := c.Device(ctx, deviceID); err != nil {
			return "", err
		} else if !found {
			return "", fmt.Errorf("%w: ncentral: device %d is gone", rmm.ErrBeforeWrite, id)
		}
		customer = c.customers[id]
	}
	head, err := json.Marshal(struct {
		Name       string `json:"name"`
		ItemID     int64  `json:"itemId"`
		TaskType   string `json:"taskType"`
		CustomerID int64  `json:"customerId"`
		DeviceID   int64  `json:"deviceId"`
		Credential struct {
			Type string `json:"type"`
		} `json:"credential"`
	}{Name: "trstctl agent " + string(action) + " " + strconv.FormatInt(id, 10) + " " + strconv.FormatInt(c.now().UnixNano(), 36),
		ItemID: script, TaskType: "Script", CustomerID: customer, DeviceID: id,
		Credential: struct {
			Type string `json:"type"`
		}{Type: c.cfg.CredentialType}})
	if err != nil {
		return "", fmt.Errorf("%w: ncentral: encode the task: %v", rmm.ErrBeforeWrite, err)
	}
	var token []byte
	body := append(head[:len(head)-1:len(head)-1], []byte(`,"parameters":[`)...)
	if action == rmm.ActionInstall {
		if install == nil || len(install.Token) == 0 {
			return "", fmt.Errorf("%w: ncentral: an install needs its enrollment token", rmm.ErrBeforeWrite)
		}
		token = install.Token
		for i, p := range []struct{ name, value string }{{ParamServer, install.Server}, {ParamServerName, install.ServerName}, {ParamIdentity, install.Identity}} {
			if i > 0 {
				body = append(body, ',')
			}
			param, err := json.Marshal(struct {
				Name        string `json:"name"`
				Value       string `json:"value"`
				Description string `json:"description"`
				Type        string `json:"type"`
			}{p.name, p.value, "trstctl agent enrollment", "string"})
			if err != nil {
				return "", fmt.Errorf("%w: ncentral: encode the task: %v", rmm.ErrBeforeWrite, err)
			}
			body = append(body, param...)
		}
		body = append(body, []byte(`,{"name":"`+ParamToken+`","value":`)...)
		body = rmm.AppendJSONString(body, install.Token)
		body = append(body, []byte(`,"description":"trstctl agent enrollment","type":"string"}`)...)
	}
	body = append(body, []byte(`]}`)...)
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	var out struct {
		Data struct {
			TaskID int64 `json:"taskId"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/api/scheduled-tasks/direct", nil, json.RawMessage(body), &out, true, token); err != nil {
		return "", err
	}
	if out.Data.TaskID <= 0 {
		return "", nil
	}
	return strconv.FormatInt(out.Data.TaskID, 10), nil
}

// ReportHealth writes the health summary to the configured device custom
// property.
func (c *Client) ReportHealth(ctx context.Context, deviceID, summary string) error {
	if c.cfg.HealthPropertyID <= 0 {
		return nil
	}
	id, err := numericID("device", deviceID)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPut, "/api/devices/"+strconv.FormatInt(id, 10)+"/custom-properties/"+strconv.FormatInt(c.cfg.HealthPropertyID, 10),
		nil, map[string]string{"value": summary}, nil, true)
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
	if body != nil {
		raw, ok := body.(json.RawMessage)
		if !ok {
			var err error
			if raw, err = json.Marshal(body); err != nil {
				return 0, fmt.Errorf("%w: encode %s %s: %v", rmm.ErrBeforeWrite, method, path, err)
			}
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
			return 0, fmt.Errorf("%w: ncentral: %s: %v", rmm.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("ncentral: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("ncentral: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data, redact...))
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
		return resp.StatusCode, fmt.Errorf("ncentral: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("ncentral: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the {status, message, errors[]} ErrorResponse,
// bounded, printable, with any echo of the JWT or a request secret removed.
func (c *Client) errorDetail(raw []byte, redact ...[]byte) string {
	var body struct {
		Message string `json:"message"`
		Errors  []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	if strings.TrimSpace(body.Message) != "" {
		parts = append(parts, body.Message)
	}
	for _, e := range body.Errors {
		if strings.TrimSpace(e.Message) != "" {
			parts = append(parts, strings.TrimSpace(e.Field+" "+e.Message))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.UserJWT, []byte("[redacted]"))
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
