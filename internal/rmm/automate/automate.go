// SPDX-License-Identifier: BUSL-1.1

// Package automate is the ConnectWise Automate client of the Provider plane
// (MSP-11), written from the calls Automate's published PowerShell module
// (AutomateAPI) makes against /cwa/api/v1: an access token from POST
// /cwa/api/v1/apitoken with the integrator user's name and password and the
// integration's clientID header, a client's computers (GET
// /cwa/api/v1/computers with a condition, paged by page and pageSize), and a
// shell line run on one computer (POST
// /cwa/api/v1/Computers/{id}/CommandExecute). Automate documents its other
// calls, among them writing an extra data field, only on a signed-in
// instance, so this client writes no health back: ReportHealth does nothing
// until a live instance settles that call.
package automate

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
	"strconv"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/rmm"
)

// Config is one Automate server.
type Config struct {
	// BaseURL is the Automate server, e.g. https://automate.example.com.
	BaseURL string
	// Username is the integrator user.
	Username string
	// ClientID is the integration's client ID, sent as the clientID header.
	ClientID string
	// CommandID is the Automate command that executes a shell line.
	CommandID int64
	// Commands are the shell lines each action runs, in Automate's
	// "<shell>!!! <arguments>" form; an install's enrollment arguments are
	// appended.
	Commands map[rmm.Action]string
}

// Credentials are the integrator user's password, borrowed for one call.
type Credentials struct {
	Password []byte
}

// Client speaks to one Automate server; it signs in once per client and
// keeps the access token only for its own lifetime (one delivery).
type Client struct {
	cfg    Config
	http   *http.Client
	creds  Credentials
	bearer string
}

const (
	maxResponse = 1 << 21
	pageSize    = 500
	maxPages    = 40
)

var (
	idPattern       = regexp.MustCompile(`^[0-9]{1,10}$`)
	clientIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// New returns a client, or an error when the target is incomplete.
func New(cfg Config, httpClient *http.Client, creds Credentials) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("automate: the target needs an absolute server URL")
	}
	if httpClient == nil || strings.TrimSpace(cfg.Username) == "" || len(creds.Password) == 0 || !clientIDPattern.MatchString(cfg.ClientID) {
		return nil, errors.New("automate: the target needs its integrator user, password and client ID")
	}
	if cfg.CommandID <= 0 {
		return nil, errors.New("automate: the target needs the command that executes a shell line")
	}
	cfg.BaseURL = base
	return &Client{cfg: cfg, http: httpClient, creds: creds}, nil
}

func (c *Client) signIn(ctx context.Context) error {
	if c.bearer != "" {
		return nil
	}
	user, err := json.Marshal(c.cfg.Username)
	if err != nil {
		return fmt.Errorf("%w: automate: encode the sign-in: %v", rmm.ErrBeforeWrite, err)
	}
	body := append([]byte(`{"UserName":`), user...)
	body = append(body, []byte(`,"Password":`)...)
	body = rmm.AppendJSONString(body, c.creds.Password)
	body = append(body, '}')
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/cwa/api/v1/apitoken", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: automate: build the sign-in request: %v", rmm.ErrBeforeWrite, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("clientID", c.cfg.ClientID)
	resp, err := c.http.Do(req)
	for i := range body {
		body[i] = 0
	}
	if err != nil {
		return fmt.Errorf("%w: automate: sign in: %v", rmm.ErrBeforeWrite, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: automate: sign in answered %d%s", rmm.ErrBeforeWrite, resp.StatusCode, c.errorDetail(raw))
	}
	var token struct {
		AccessToken         string `json:"AccessToken"`
		IsTwoFactorRequired bool   `json:"IsTwoFactorRequired"`
	}
	if json.Unmarshal(raw, &token) != nil {
		return fmt.Errorf("%w: automate: sign in returned no access token", rmm.ErrBeforeWrite)
	}
	if token.IsTwoFactorRequired {
		return fmt.Errorf("%w: automate: the integrator user requires two-factor sign-in; use an integrator user without it", rmm.ErrBeforeWrite)
	}
	if token.AccessToken == "" {
		return fmt.Errorf("%w: automate: sign in returned no access token", rmm.ErrBeforeWrite)
	}
	c.bearer = "Bearer " + token.AccessToken
	return nil
}

type computer struct {
	ID           int64  `json:"Id"`
	ComputerName string `json:"ComputerName"`
	Status       string `json:"Status"`
	Client       struct {
		ID int64 `json:"Id"`
	} `json:"Client"`
}

func (d computer) public() rmm.Device {
	return rmm.Device{ID: strconv.FormatInt(d.ID, 10), OrgID: strconv.FormatInt(d.Client.ID, 10), Name: d.ComputerName,
		Online: strings.EqualFold(d.Status, "Online")}
}

func checkID(kind, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if !idPattern.MatchString(v) {
		return "", fmt.Errorf("%w: an Automate %s ID is a number, not %q", rmm.ErrBeforeWrite, kind, raw)
	}
	return v, nil
}

func (c *Client) computers(ctx context.Context, condition string) ([]computer, error) {
	var out []computer
	for page := 1; page <= maxPages; page++ {
		var list []computer
		q := url.Values{"condition": {condition}, "pageSize": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
		if _, err := c.do(ctx, http.MethodGet, "/cwa/api/v1/computers", q, nil, &list, false); err != nil {
			return nil, err
		}
		out = append(out, list...)
		if len(list) < pageSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: automate: %q matches more than %d computers", rmm.ErrBeforeWrite, condition, pageSize*maxPages)
}

// ListDevices lists a client's computers.
func (c *Client) ListDevices(ctx context.Context, clientID string) ([]rmm.Device, error) {
	id, err := checkID("client", clientID)
	if err != nil {
		return nil, err
	}
	list, err := c.computers(ctx, "Client.Id = "+id)
	if err != nil {
		return nil, err
	}
	var out []rmm.Device
	for _, d := range list {
		if strconv.FormatInt(d.Client.ID, 10) == id && d.ID > 0 {
			out = append(out, d.public())
		}
	}
	return out, nil
}

// Device reads one computer through the computers list.
func (c *Client) Device(ctx context.Context, deviceID string) (rmm.Device, bool, error) {
	id, err := checkID("computer", deviceID)
	if err != nil {
		return rmm.Device{}, false, err
	}
	list, err := c.computers(ctx, "Id = "+id)
	if err != nil {
		return rmm.Device{}, false, err
	}
	for _, d := range list {
		if strconv.FormatInt(d.ID, 10) == id {
			return d.public(), true, nil
		}
	}
	return rmm.Device{}, false, nil
}

// RunAction runs the action's shell line on the computer through the
// execute command and returns Automate's command ID. An install appends
// -Server, -ServerName, -Identity and -Token; the request body carrying the
// token is assembled from bytes and wiped once sent.
func (c *Client) RunAction(ctx context.Context, deviceID string, action rmm.Action, install *rmm.InstallParams) (string, error) {
	id, err := checkID("computer", deviceID)
	if err != nil {
		return "", err
	}
	command := strings.TrimSpace(c.cfg.Commands[action])
	if command == "" || !strings.Contains(command, "!!! ") {
		return "", fmt.Errorf("%w: automate: no shell line is configured for %s", rmm.ErrBeforeWrite, action)
	}
	var token []byte
	line := []byte(command)
	if action == rmm.ActionInstall {
		if install == nil || len(install.Token) == 0 {
			return "", fmt.Errorf("%w: automate: an install needs its enrollment token", rmm.ErrBeforeWrite)
		}
		token = install.Token
		line = append(line, []byte(" -Server "+strconv.Quote(install.Server)+" -ServerName "+strconv.Quote(install.ServerName)+
			" -Identity "+strconv.Quote(install.Identity)+" -Token \"")...)
		line = append(line, install.Token...)
		line = append(line, '"')
	}
	body := []byte(`{"ComputerId":` + id + `,"Command":{"Id":` + strconv.FormatInt(c.cfg.CommandID, 10) + `},"Parameters":[`)
	body = rmm.AppendJSONString(body, line)
	body = append(body, []byte(`]}`)...)
	defer func() {
		for i := range line {
			line[i] = 0
		}
		for i := range body {
			body[i] = 0
		}
	}()
	var out struct {
		ID int64 `json:"Id"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/cwa/api/v1/Computers/"+id+"/CommandExecute", nil, json.RawMessage(body), &out, true, token); err != nil {
		return "", err
	}
	if out.ID <= 0 {
		return "", nil
	}
	return strconv.FormatInt(out.ID, 10), nil
}

// ReportHealth writes nothing: Automate documents its extra-data-field write
// only on a signed-in instance, so health is not written back yet.
func (c *Client) ReportHealth(context.Context, string, string) error { return nil }

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
	req.Header.Set("clientID", c.cfg.ClientID)
	label := method + " " + path
	resp, err := c.http.Do(req)
	if err != nil {
		if !write {
			return 0, fmt.Errorf("%w: automate: %s: %v", rmm.ErrBeforeWrite, label, transportCause(err))
		}
		return 0, fmt.Errorf("automate: %s: %v", label, transportCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cause := fmt.Sprintf("automate: %s answered %d%s", label, resp.StatusCode, c.errorDetail(data, redact...))
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
		return resp.StatusCode, fmt.Errorf("automate: read %s: %v", label, readErr)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("automate: decode %s: %v", label, err)
		}
	}
	return resp.StatusCode, nil
}

// errorDetail renders the error's message (top level, or under error),
// bounded, printable, with any echo of the password or a request secret
// removed.
func (c *Client) errorDetail(raw []byte, redact ...[]byte) string {
	var body struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	parts := []string{}
	for _, p := range []string{body.Message, body.Error.Message} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	text := bytes.ReplaceAll([]byte(strings.Join(parts, "; ")), c.creds.Password, []byte("[redacted]"))
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
