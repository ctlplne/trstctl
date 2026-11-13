// SPDX-License-Identifier: BUSL-1.1

// Package datto is the Datto RMM client of the Provider plane (MSP-10),
// written from Datto RMM's public API v2 OpenAPI description and its
// published clients: an OAuth2 password-grant token at /auth/oauth/token (the
// public client "public-client", the API key as the user name and the API
// secret as the password), a site's devices (/api/v2/site/{siteUid}/devices,
// paged by page and max), one device (/api/v2/device/{deviceUid}), a quick
// job running a component on a device (PUT /api/v2/device/{deviceUid}/quickjob)
// and the device's user-defined fields (POST /api/v2/device/{deviceUid}/udf).
package datto

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
)

// Config is one Datto RMM platform.
type Config struct {
	// BaseURL is the platform's API host, e.g.
	// https://pinotage-api.centrastage.net.
	BaseURL string
	// Components are the component UIDs each action runs as a quick job.
	Components map[rmm.Action]string
	// HealthUDF is the user-defined field (1-30) the agent's health is
	// written to; 0 reports nothing.
	HealthUDF int
}

// Credentials are the API user's key and secret, borrowed for one call.
type Credentials struct {
	APIKey    []byte
	APISecret []byte
}

// Client speaks to one Datto RMM platform; it signs in once per client and
// keeps the token only for its own lifetime (one delivery).
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
}

const (
	maxResponse = 1 << 21
	pageSize    = 250
	maxPages    = 40
)

// uidPattern is a Datto site, device or component UID.
var uidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("datto: the target needs an absolute platform URL")
	}
	if httpClient == nil || len(creds.APIKey) == 0 || len(creds.APISecret) == 0 {
		return nil, errors.New("datto: the target needs its API key and API secret")
	}
	if cfg.HealthUDF < 0 || cfg.HealthUDF > 30 {
		return nil, errors.New("datto: the health field is a user-defined field from 1 to 30")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	body := rmm.AppendFormEscaped([]byte("grant_type=password&username="), c.creds.APIKey)
	body = append(body, []byte("&password=")...)
	body = rmm.AppendFormEscaped(body, c.creds.APISecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/auth/oauth/token", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: datto: build the token request: %v", rmm.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// The published public OAuth client every API user signs in through.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("public-client:public")))
	resp, err := c.http.Do(req)
	for i := range body {
		body[i] = 0
	}
	if err != nil {
		return fmt.Errorf("%w: datto: sign in: %v", rmm.ErrBeforeWrite, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: datto: sign in answered %d%s", rmm.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(raw, &token) != nil || token.AccessToken == "" {
		return fmt.Errorf("%w: datto: sign in returned no access token", rmm.ErrBeforeWrite)
	}
	c.bearer = "Bearer " + token.AccessToken
	return nil
}

type device struct {
	ID       int64  `json:"id"`
	UID      string `json:"uid"`
	SiteUID  string `json:"siteUid"`
	Hostname string `json:"hostname"`
	Online   bool   `json:"online"`
	Deleted  bool   `json:"deleted"`
}

func (d device) public() rmm.Device {
	return rmm.Device{ID: d.UID, OrgID: d.SiteUID, Name: d.Hostname, Online: d.Online}
}

func uid(kind, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !uidPattern.MatchString(v) {
		return "", fmt.Errorf("%w: a Datto RMM %s UID is a UUID, not %q", rmm.ErrBeforeWrite, kind, raw)
	}
	return strings.ToLower(v), nil
}

// ListDevices lists a site's devices, page by page.
func (c *Client) ListDevices(ctx context.Context, siteUID string) ([]rmm.Device, error) {
	site, err := uid("site", siteUID)
	if err != nil {
		return nil, err
	}
	var out []rmm.Device
	for page := 0; page < maxPages; page++ {
		var list struct {
			PageDetails struct {
				NextPageURL *string `json:"nextPageUrl"`
			} `json:"pageDetails"`
			Devices []device `json:"devices"`
		}
		q := url.Values{"max": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
		if _, err := c.do(ctx, http.MethodGet, "/api/v2/site/"+site+"/devices", q, nil, &list, false); err != nil {
			return nil, err
		}
		for _, d := range list.Devices {
			if strings.EqualFold(d.SiteUID, site) && !d.Deleted && uidPattern.MatchString(d.UID) {
				d.SiteUID, d.UID = site, strings.ToLower(d.UID)
				out = append(out, d.public())
			}
		}
		if list.PageDetails.NextPageURL == nil || *list.PageDetails.NextPageURL == "" || len(list.Devices) == 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: datto: site %s lists more than %d devices", rmm.ErrBeforeWrite, site, pageSize*maxPages)
}

// Device reads one device.
func (c *Client) Device(ctx context.Context, deviceID string) (rmm.Device, bool, error) {
	id, err := uid("device", deviceID)
	if err != nil {
		return rmm.Device{}, false, err
	}
	var d device
	status, err := c.do(ctx, http.MethodGet, "/api/v2/device/"+id, nil, nil, &d, false)
	if status == http.StatusNotFound {
		return rmm.Device{}, false, nil
	}
	if err != nil {
		return rmm.Device{}, false, err
	}
	if !strings.EqualFold(d.UID, id) {
		return rmm.Device{}, false, fmt.Errorf("%w: Datto RMM answered device %q for device %s", rmm.ErrBeforeWrite, d.UID, id)
	}
	if d.Deleted {
		return rmm.Device{}, false, nil
	}
	d.UID, d.SiteUID = id, strings.ToLower(d.SiteUID)
	return d.public(), true, nil
}

// The component variables an install's quick job receives.
const (
	VarServer     = "TrstctlServer"
	VarServerName = "TrstctlServerName"
	VarIdentity   = "TrstctlIdentity"
	VarToken      = "TrstctlToken"
)

// RunAction runs the action's component on the device as a quick job and
// returns the job's UID. An install passes the server, server name, identity
// and one-time token as the component's variables; the request body carrying
// the token is assembled from bytes and wiped once sent.
func (c *Client) RunAction(ctx context.Context, deviceID string, action rmm.Action, install *rmm.InstallParams) (string, error) {
	id, err := uid("device", deviceID)
	if err != nil {
		return "", err
	}
	component, ok := c.cfg.Components[action]
	if !ok || !uidPattern.MatchString(component) {
		return "", fmt.Errorf("%w: datto: no component is configured for %s", rmm.ErrBeforeWrite, action)
	}
	var token []byte
	head, err := json.Marshal(struct {
		JobName string `json:"jobName"`
	}{JobName: "trstctl agent " + string(action)})
	if err != nil {
		return "", fmt.Errorf("%w: datto: encode the quick job: %v", rmm.ErrBeforeWrite, err)
	}
	componentJSON, err := json.Marshal(component)
	if err != nil {
		return "", fmt.Errorf("%w: datto: encode the quick job: %v", rmm.ErrBeforeWrite, err)
	}
	body := append(head[:len(head)-1:len(head)-1], []byte(`,"jobComponent":{"componentUid":`)...)
	body = append(body, componentJSON...)
	body = append(body, []byte(`,"variables":[`)...)
	if action == rmm.ActionInstall {
		if install == nil || len(install.Token) == 0 {
			return "", fmt.Errorf("%w: datto: an install needs its enrollment token", rmm.ErrBeforeWrite)
		}
		token = install.Token
		for i, v := range []struct{ name, value string }{{VarServer, install.Server}, {VarServerName, install.ServerName}, {VarIdentity, install.Identity}} {
			if i > 0 {
				body = append(body, ',')
			}
			pair, err := json.Marshal(struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}{v.name, v.value})
			if err != nil {
				return "", fmt.Errorf("%w: datto: encode the quick job: %v", rmm.ErrBeforeWrite, err)
			}
			body = append(body, pair...)
		}
		body = append(body, []byte(`,{"name":"`+VarToken+`","value":`)...)
		body = rmm.AppendJSONString(body, install.Token)
		body = append(body, '}')
	}
	body = append(body, []byte(`]}}`)...)
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	var out struct {
		Job struct {
			UID string `json:"uid"`
		} `json:"job"`
	}
	if _, err := c.do(ctx, http.MethodPut, "/api/v2/device/"+id+"/quickjob", nil, json.RawMessage(body), &out, true, token); err != nil {
		return "", err
	}
	return out.Job.UID, nil
}

// ReportHealth writes the health summary to the configured user-defined
// field.
func (c *Client) ReportHealth(ctx context.Context, deviceID, summary string) error {
	if c.cfg.HealthUDF == 0 {
		return nil
	}
	id, err := uid("device", deviceID)
	if err != nil {
		return err
	}
	if len(summary) > 255 {
		summary = summary[:255]
	}
	_, err = c.do(ctx, http.MethodPost, "/api/v2/device/"+id+"/udf", nil,
		map[string]string{"udf" + strconv.Itoa(c.cfg.HealthUDF): summary}, nil, true)
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
			return 0, fmt.Errorf("%w: datto: %s: %v", rmm.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("datto: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("datto: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data, redact...))
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
		return resp.StatusCode, fmt.Errorf("datto: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("datto: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the {status, error, message} body the API answers,
// bounded, printable, with any echo of the secret or a request secret
// removed.
func (c *Client) errorDetail(raw []byte, redact ...[]byte) string {
	var body struct {
		Error            string `json:"error"`
		Message          string `json:"message"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.Error, body.Message, body.ErrorDescription} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.APISecret, []byte("[redacted]"))
	text = bytes.ReplaceAll(text, c.creds.APIKey, []byte("[redacted]"))
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
