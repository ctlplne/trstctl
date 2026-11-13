// SPDX-License-Identifier: BUSL-1.1

// Package kaseya is the Kaseya VSA 9 client of the Provider plane (MSP-13),
// written from VSA's public REST API help pages and its published
// PowerShell module: a session token from GET /api/v1.0/auth with Basic
// credentials of the user name and a personal access token, the agents
// (/api/v1.0/assetmgmt/agents, paged by $top and $skip in the
// {TotalRecords, Result, ResponseCode, Status, Error} envelope), one agent,
// running an agent procedure now (PUT
// /api/v1.0/automation/agentprocs/{agentId}/{procId}/runnow, no body, 204)
// and an agent's custom field (PUT
// /api/v1.0/assetmgmt/assets/{agentId}/customfields/{field} with
// [{"key":"FieldValue","value":...}]). A procedure run now takes no
// parameters, so an install's enrollment line is written to the agent's
// enrollment custom field first and the install procedure reads it.
package kaseya

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
	"strconv"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/secrettext"
)

// Config is one VSA server.
type Config struct {
	// BaseURL is the VSA server, e.g. https://vsa.example.com.
	BaseURL string
	// Username is the VSA user the personal access token belongs to.
	Username string
	// Procedures are the agent procedure IDs each action runs.
	Procedures map[rmm.Action]int64
	// EnrollmentField is the agent custom field an install's enrollment
	// line is written to before the install procedure runs.
	EnrollmentField string
	// HealthField is the agent custom field the agent's health is written
	// to; empty reports nothing.
	HealthField string
}

// Credentials are the user's personal access token, borrowed for one call.
type Credentials struct {
	AccessToken []byte
}

// Client speaks to one VSA server; it signs in once per client and keeps
// the session token only for its own lifetime (one delivery).
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
}

const (
	maxResponse = 1 << 21
	pageSize    = 100
	maxPages    = 100
)

// idPattern is a VSA agent, organization or procedure ID.
var idPattern = regexp.MustCompile(`^[0-9]{1,20}$`)

// fieldPattern is a VSA custom field name.
var fieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("kaseya: the target needs an absolute server URL")
	}
	if httpClient == nil || strings.TrimSpace(cfg.Username) == "" || strings.ContainsAny(cfg.Username, ":\r\n") || len(creds.AccessToken) == 0 {
		return nil, errors.New("kaseya: the target needs its user name and personal access token")
	}
	for _, field := range []string{cfg.EnrollmentField, cfg.HealthField} {
		if field != "" && !fieldPattern.MatchString(field) {
			return nil, fmt.Errorf("kaseya: %q is not a custom field name", field)
		}
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	pair := append([]byte(c.cfg.Username+":"), c.creds.AccessToken...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(pair)))
	base64.StdEncoding.Encode(encoded, pair)
	header := secrettext.Prefixed("Basic ", encoded)
	for i := range pair {
		pair[i] = 0
	}
	for i := range encoded {
		encoded[i] = 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/v1.0/auth", nil)
	if err != nil {
		return fmt.Errorf("%w: kaseya: build the sign-in request: %v", rmm.ErrBeforeWrite, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", header)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: kaseya: sign in: %v", rmm.ErrBeforeWrite, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	var out struct {
		Result struct {
			Token string `json:"Token"`
		} `json:"Result"`
		ResponseCode int `json:"ResponseCode"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.ResponseCode != 0 || out.Result.Token == "" {
		return fmt.Errorf("%w: kaseya: sign in answered %d%s", rmm.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	c.bearer = "Bearer " + out.Result.Token
	return nil
}

type agent struct {
	AgentID      json.Number `json:"AgentId"`
	AgentName    string      `json:"AgentName"`
	ComputerName string      `json:"ComputerName"`
	OrgID        json.Number `json:"OrgId"`
	Online       json.Number `json:"Online"`
}

func (a agent) public() rmm.Device {
	name := a.ComputerName
	if name == "" {
		name, _, _ = strings.Cut(a.AgentName, ".")
	}
	online, _ := a.Online.Int64()
	return rmm.Device{ID: a.AgentID.String(), OrgID: a.OrgID.String(), Name: name, Online: online > 0}
}

func checkID(kind, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !idPattern.MatchString(v) {
		return "", fmt.Errorf("%w: a VSA %s ID is a number, not %q", rmm.ErrBeforeWrite, kind, raw)
	}
	return v, nil
}

// ListDevices lists an organization's agents, page by page.
func (c *Client) ListDevices(ctx context.Context, orgID string) ([]rmm.Device, error) {
	org, err := checkID("organization", orgID)
	if err != nil {
		return nil, err
	}
	var out []rmm.Device
	for page := 0; page < maxPages; page++ {
		var list struct {
			TotalRecords int     `json:"TotalRecords"`
			Result       []agent `json:"Result"`
		}
		q := url.Values{"$top": {strconv.Itoa(pageSize)}, "$skip": {strconv.Itoa(page * pageSize)}, "$orderby": {"AgentId"}}
		if _, err := c.do(ctx, http.MethodGet, "/api/v1.0/assetmgmt/agents", q, nil, &list, false); err != nil {
			return nil, err
		}
		for _, a := range list.Result {
			if a.OrgID.String() == org && idPattern.MatchString(a.AgentID.String()) {
				out = append(out, a.public())
			}
		}
		if len(list.Result) < pageSize || (page+1)*pageSize >= list.TotalRecords {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: kaseya: the server lists more than %d agents", rmm.ErrBeforeWrite, pageSize*maxPages)
}

// Device reads one agent.
func (c *Client) Device(ctx context.Context, deviceID string) (rmm.Device, bool, error) {
	id, err := checkID("agent", deviceID)
	if err != nil {
		return rmm.Device{}, false, err
	}
	var out struct {
		Result agent `json:"Result"`
	}
	status, err := c.do(ctx, http.MethodGet, "/api/v1.0/assetmgmt/agents/"+id, nil, nil, &out, false)
	if status == http.StatusNotFound {
		return rmm.Device{}, false, nil
	}
	if err != nil {
		return rmm.Device{}, false, err
	}
	if out.Result.AgentID.String() != id {
		return rmm.Device{}, false, fmt.Errorf("%w: VSA answered agent %q for agent %s", rmm.ErrBeforeWrite, out.Result.AgentID.String(), id)
	}
	return out.Result.public(), true, nil
}

// RunAction runs the action's agent procedure now. An install first writes
// the enrollment line (server, server name, identity and one-time token) to
// the agent's enrollment custom field, assembled from bytes and wiped once
// sent; the procedure reads it.
func (c *Client) RunAction(ctx context.Context, deviceID string, action rmm.Action, install *rmm.InstallParams) (string, error) {
	id, err := checkID("agent", deviceID)
	if err != nil {
		return "", err
	}
	proc, ok := c.cfg.Procedures[action]
	if !ok || proc <= 0 {
		return "", fmt.Errorf("%w: kaseya: no agent procedure is configured for %s", rmm.ErrBeforeWrite, action)
	}
	var token []byte
	if action == rmm.ActionInstall {
		if install == nil || len(install.Token) == 0 {
			return "", fmt.Errorf("%w: kaseya: an install needs its enrollment token", rmm.ErrBeforeWrite)
		}
		if c.cfg.EnrollmentField == "" {
			return "", fmt.Errorf("%w: kaseya: an install needs the enrollment custom field", rmm.ErrBeforeWrite)
		}
		token = install.Token
		line := []byte("-Server " + strconv.Quote(install.Server) + " -ServerName " + strconv.Quote(install.ServerName) +
			" -Identity " + strconv.Quote(install.Identity) + " -Token \"")
		line = append(line, install.Token...)
		line = append(line, '"')
		body := []byte(`[{"key":"FieldValue","value":`)
		body = rmm.AppendJSONString(body, line)
		body = append(body, []byte(`}]`)...)
		_, err := c.do(ctx, http.MethodPut, "/api/v1.0/assetmgmt/assets/"+id+"/customfields/"+c.cfg.EnrollmentField, nil, json.RawMessage(body), nil, true, token)
		for i := range line {
			line[i] = 0
		}
		for i := range body {
			body[i] = 0
		}
		if err != nil {
			return "", err
		}
	}
	if _, err := c.do(ctx, http.MethodPut, "/api/v1.0/automation/agentprocs/"+id+"/"+strconv.FormatInt(proc, 10)+"/runnow", nil, nil, nil, true, token); err != nil {
		return "", err
	}
	return "", nil
}

// ReportHealth writes the health summary to the configured custom field.
func (c *Client) ReportHealth(ctx context.Context, deviceID, summary string) error {
	if c.cfg.HealthField == "" {
		return nil
	}
	id, err := checkID("agent", deviceID)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPut, "/api/v1.0/assetmgmt/assets/"+id+"/customfields/"+c.cfg.HealthField, nil,
		[]map[string]string{{"key": "FieldValue", "value": summary}}, nil, true)
	return err
}

// do sends one API request. A lookup failure is always before anything
// ran; a write's 4xx other than 408 and 429 is the RMM's definitive refusal,
// and so is an answer whose ResponseCode is not 0. redact names request
// secrets (an install's token) an error must not echo.
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
			return 0, fmt.Errorf("%w: kaseya: %s: %v", rmm.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("kaseya: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	var envelope struct {
		ResponseCode *int `json:"ResponseCode"`
	}
	refusedInEnvelope := resp.StatusCode >= 200 && resp.StatusCode <= 299 && len(data) > 0 &&
		json.Unmarshal(data, &envelope) == nil && envelope.ResponseCode != nil && *envelope.ResponseCode != 0
	if resp.StatusCode < 200 || resp.StatusCode > 299 || refusedInEnvelope {
		cause := fmt.Sprintf("kaseya: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data, redact...))
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
		return resp.StatusCode, fmt.Errorf("kaseya: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("kaseya: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the envelope's Status and Error, bounded, printable,
// with any echo of the access token or a request secret removed.
func (c *Client) errorDetail(raw []byte, redact ...[]byte) string {
	var body struct {
		Status string `json:"Status"`
		Error  string `json:"Error"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.Status, body.Error} {
		if strings.TrimSpace(p) != "" && p != "None" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.AccessToken, []byte("[redacted]"))
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
