// SPDX-License-Identifier: BUSL-1.1

// Package oauthrevoke acts at an identity or SaaS provider on an abusive OAuth
// grant that discovery found (A170, A171): it revokes the grant a user gave an
// application, and it blocks the application so no one can grant it again.
// Discovery only reads metadata exports; this package is the one place that
// changes provider state, and it reports exactly what the provider confirmed.
//
// Each provider speaks its admin REST API with an operator's token, through
// the caller's egress-guarded client:
//
//   - Okta: DELETE /api/v1/users/{user}/clients/{client}/grants and .../tokens
//     revoke the grants and the refresh tokens one user gave one client; POST
//     /api/v1/apps/{app}/lifecycle/deactivate blocks the application.
//   - Microsoft Graph: the delegated permission grants for the client's
//     service principal and the user are listed and deleted; PATCH of the
//     service principal with accountEnabled false blocks sign-in to it.
//   - Google Workspace: DELETE /admin/directory/v1/users/{user}/tokens/{client}
//     revokes the user's grant. Workspace exposes app access control only in
//     its admin console, so blocking there is refused with that reason rather
//     than reported as done.
package oauthrevoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// Status is what the provider confirmed.
type Status string

const (
	// Confirmed: the provider accepted the change.
	Confirmed Status = "confirmed"
	// AlreadyAbsent: the provider reports nothing left to revoke.
	AlreadyAbsent Status = "already_absent"
)

// ErrUnsupported marks an action the provider's API cannot perform.
var ErrUnsupported = errors.New("oauthrevoke: the provider's API cannot perform this action")

// Grant names one user's grant to one application.
type Grant struct {
	Principal string // the user (provider id or login)
	AppID     string // the OAuth client / application id
}

// Result is what the provider confirmed.
type Result struct {
	Status Status
	// Removed counts the grants (or tokens) the provider removed, where it says.
	Removed int
	Detail  string
}

// Provider acts at one provider.
type Provider interface {
	RevokeGrant(ctx context.Context, g Grant) (Result, error)
	BlockApp(ctx context.Context, appID string) (Result, error)
}

// Doer is the egress-guarded HTTP client seam.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Connection is one provider admin connection: its API base URL and token.
type Connection struct {
	Provider string // okta, microsoft, google
	BaseURL  string
	Token    []byte
	Doer     Doer
}

// New builds the provider a connection names. The token is copied into
// locked memory; Close wipes it.
func New(c Connection) (Provider, func(), error) {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if u, err := url.Parse(base); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, func() {}, errors.New("oauthrevoke: base_url must be an http(s) URL")
	}
	if c.Doer == nil || len(c.Token) == 0 {
		return nil, func() {}, errors.New("oauthrevoke: an egress client and a token are required")
	}
	token, err := secret.NewFrom(c.Token)
	if err != nil {
		return nil, func() {}, fmt.Errorf("oauthrevoke: protect token: %w", err)
	}
	api := client{base: base, token: token, doer: c.Doer}
	switch NormalizeProvider(c.Provider) {
	case "okta":
		api.scheme = "SSWS "
		return okta{api}, token.Destroy, nil
	case "microsoft":
		api.scheme = "Bearer "
		return graph{api}, token.Destroy, nil
	case "google":
		api.scheme = "Bearer "
		return google{api}, token.Destroy, nil
	default:
		token.Destroy()
		return nil, func() {}, fmt.Errorf("oauthrevoke: provider %q is not served; use okta, microsoft or google", c.Provider)
	}
}

// NormalizeProvider maps the provider names discovery exports use onto the
// three served ones.
func NormalizeProvider(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "okta":
		return "okta"
	case "microsoft", "entra", "azuread", "azure-ad", "microsoft365", "m365", "graph":
		return "microsoft"
	case "google", "google-workspace", "workspace", "gsuite":
		return "google"
	default:
		return ""
	}
}

// CanBlock reports whether a provider's API can block an application.
func CanBlock(provider string) bool {
	switch NormalizeProvider(provider) {
	case "okta", "microsoft":
		return true
	default:
		return false
	}
}

type client struct {
	base   string
	scheme string
	token  *secret.Buffer
	doer   Doer
}

// do sends one request and returns the status and a bounded body. A non-2xx
// answer other than the ones the caller handles is reported by status only:
// provider error bodies can echo request detail.
func (c client) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", secrettext.Prefixed(c.scheme, c.token.Bytes()))
	resp, err := c.doer.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// StatusError is a provider answer the action cannot treat as done.
type StatusError struct {
	Op   string
	Code int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("oauthrevoke: %s: provider answered status %d (response body redacted)", e.Op, e.Code)
}

func statusError(op string, status int) error { return &StatusError{Op: op, Code: status} }

// Retryable reports whether an error may clear on its own: the provider was
// unreachable, throttled the call or failed on its side. Any other answer —
// an unauthorized token, a refused request — fails the same way every time.
func Retryable(err error) bool {
	var status *StatusError
	if errors.As(err, &status) {
		return status.Code == http.StatusTooManyRequests || status.Code >= 500
	}
	return err != nil && !errors.Is(err, ErrUnsupported)
}

type okta struct{ client }

func (o okta) RevokeGrant(ctx context.Context, g Grant) (Result, error) {
	user, app := url.PathEscape(g.Principal), url.PathEscape(g.AppID)
	removed := 0
	for _, kind := range []string{"grants", "tokens"} {
		status, _, err := o.do(ctx, http.MethodDelete, "/api/v1/users/"+user+"/clients/"+app+"/"+kind, nil)
		switch {
		case err != nil:
			return Result{}, fmt.Errorf("oauthrevoke: okta revoke %s: %w", kind, err)
		case status == http.StatusNoContent || status == http.StatusOK:
			removed++
		case status == http.StatusNotFound:
		default:
			return Result{}, statusError("okta revoke "+kind, status)
		}
	}
	if removed == 0 {
		return Result{Status: AlreadyAbsent, Detail: "Okta has no grant or token from this user to this client"}, nil
	}
	return Result{Status: Confirmed, Removed: removed, Detail: "Okta revoked the user's grants and refresh tokens for the client"}, nil
}

func (o okta) BlockApp(ctx context.Context, appID string) (Result, error) {
	status, _, err := o.do(ctx, http.MethodPost, "/api/v1/apps/"+url.PathEscape(appID)+"/lifecycle/deactivate", nil)
	switch {
	case err != nil:
		return Result{}, fmt.Errorf("oauthrevoke: okta deactivate app: %w", err)
	case status == http.StatusOK || status == http.StatusNoContent:
		return Result{Status: Confirmed, Detail: "Okta deactivated the application; no user can sign in to it or grant it access"}, nil
	case status == http.StatusNotFound:
		return Result{Status: AlreadyAbsent, Detail: "Okta has no such application"}, nil
	default:
		return Result{}, statusError("okta deactivate app", status)
	}
}

type graph struct{ client }

func (m graph) RevokeGrant(ctx context.Context, g Grant) (Result, error) {
	filter := url.QueryEscape("clientId eq '" + odataQuote(g.AppID) + "' and principalId eq '" + odataQuote(g.Principal) + "'")
	status, raw, err := m.do(ctx, http.MethodGet, "/v1.0/oauth2PermissionGrants?$filter="+filter, nil)
	if err != nil {
		return Result{}, fmt.Errorf("oauthrevoke: graph list grants: %w", err)
	}
	if status != http.StatusOK {
		return Result{}, statusError("graph list grants", status)
	}
	var listed struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		return Result{}, fmt.Errorf("oauthrevoke: graph list grants: decode: %w", err)
	}
	removed := 0
	for _, grant := range listed.Value {
		status, _, err := m.do(ctx, http.MethodDelete, "/v1.0/oauth2PermissionGrants/"+url.PathEscape(grant.ID), nil)
		switch {
		case err != nil:
			return Result{}, fmt.Errorf("oauthrevoke: graph delete grant: %w", err)
		case status == http.StatusNoContent || status == http.StatusOK:
			removed++
		case status == http.StatusNotFound:
		default:
			return Result{}, statusError("graph delete grant", status)
		}
	}
	if removed == 0 {
		return Result{Status: AlreadyAbsent, Detail: "Microsoft Graph lists no delegated grant from this user to this application"}, nil
	}
	return Result{Status: Confirmed, Removed: removed, Detail: fmt.Sprintf("Microsoft Graph deleted %d delegated permission grant(s)", removed)}, nil
}

func (m graph) BlockApp(ctx context.Context, appID string) (Result, error) {
	status, _, err := m.do(ctx, http.MethodPatch, "/v1.0/servicePrincipals/"+url.PathEscape(appID), map[string]any{"accountEnabled": false})
	switch {
	case err != nil:
		return Result{}, fmt.Errorf("oauthrevoke: graph disable service principal: %w", err)
	case status == http.StatusNoContent || status == http.StatusOK:
		return Result{Status: Confirmed, Detail: "Microsoft Graph disabled the service principal; no user can sign in to the application"}, nil
	case status == http.StatusNotFound:
		return Result{Status: AlreadyAbsent, Detail: "Microsoft Graph has no such service principal"}, nil
	default:
		return Result{}, statusError("graph disable service principal", status)
	}
}

// odataQuote escapes a value for an OData string literal.
func odataQuote(value string) string { return strings.ReplaceAll(value, "'", "''") }

type google struct{ client }

func (g google) RevokeGrant(ctx context.Context, grant Grant) (Result, error) {
	status, _, err := g.do(ctx, http.MethodDelete, "/admin/directory/v1/users/"+url.PathEscape(grant.Principal)+"/tokens/"+url.PathEscape(grant.AppID), nil)
	switch {
	case err != nil:
		return Result{}, fmt.Errorf("oauthrevoke: google revoke token: %w", err)
	case status == http.StatusNoContent || status == http.StatusOK:
		return Result{Status: Confirmed, Removed: 1, Detail: "Google Workspace revoked the user's grant to the client"}, nil
	case status == http.StatusNotFound:
		return Result{Status: AlreadyAbsent, Detail: "Google Workspace has no grant from this user to this client"}, nil
	default:
		return Result{}, statusError("google revoke token", status)
	}
}

func (google) BlockApp(context.Context, string) (Result, error) {
	return Result{}, fmt.Errorf("%w: Google Workspace exposes app access control only in its admin console", ErrUnsupported)
}
