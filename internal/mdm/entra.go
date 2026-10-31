// SPDX-License-Identifier: BUSL-1.1

package mdm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// A156: the built-in OAuth 2.0 client-credentials exchange for Microsoft Graph.
// An Intune poll schedule can name an Entra app registration (directory
// tenant and client ID) and a secret:// reference to its client secret
// instead of a bearer the operator rotates by hand. The relay redeems the
// secret per attempt and exchanges it here for an access token that lives
// only in memory for that job.

const (
	// DefaultEntraAuthority is the public-cloud Microsoft identity platform.
	DefaultEntraAuthority = "https://login.microsoftonline.com"
	// GraphApplicationScope requests the app's granted Graph application
	// permissions.
	GraphApplicationScope = "https://graph.microsoft.com/.default"

	maxTokenResponseBytes = 64 << 10
)

var (
	// ErrClientCredentialsRefused is a client ID or secret the identity
	// platform refused (OAuth invalid_client).
	ErrClientCredentialsRefused = errors.New("mdm: the identity platform refused the client ID or client secret")
	// ErrClientNotAuthorized is an app without the Graph application
	// permission this read needs (unauthorized_client, invalid_scope,
	// invalid_grant).
	ErrClientNotAuthorized = errors.New("mdm: the app registration is not authorized for Microsoft Graph application access")
	// ErrTokenExchangeFailed is any other failed or malformed exchange.
	ErrTokenExchangeFailed = errors.New("mdm: the client-credentials token exchange failed")

	guidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	domainPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)+$`)
)

// ClientCredentials names an Entra app registration. The client secret is
// never part of it; it travels as a secret:// reference the relay redeems.
type ClientCredentials struct {
	Authority         string `json:"authority,omitempty"`
	DirectoryTenantID string `json:"directory_tenant_id"`
	ClientID          string `json:"client_id"`
}

// Normalize trims the fields and fills the default authority.
func (c ClientCredentials) Normalize() ClientCredentials {
	c.Authority = strings.TrimRight(strings.TrimSpace(c.Authority), "/")
	if c.Authority == "" {
		c.Authority = DefaultEntraAuthority
	}
	c.DirectoryTenantID = strings.TrimSpace(c.DirectoryTenantID)
	c.ClientID = strings.TrimSpace(c.ClientID)
	return c
}

// Validate checks a normalized app registration.
func (c ClientCredentials) Validate() error {
	if !guidPattern.MatchString(c.DirectoryTenantID) && !domainPattern.MatchString(c.DirectoryTenantID) {
		return errors.New("mdm: directory_tenant_id must be the directory's GUID or a verified domain name")
	}
	if !guidPattern.MatchString(c.ClientID) {
		return errors.New("mdm: client_id must be the app registration's application (client) GUID")
	}
	u, err := url.Parse(c.Authority)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("mdm: authority must be an absolute identity-platform origin such as https://login.microsoftonline.com")
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Only a loopback stand-in may be plain HTTP: a client secret never
		// crosses a network in clear text.
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return errors.New("mdm: authority must use https")
		}
	default:
		return errors.New("mdm: authority must use https")
	}
	return nil
}

// TokenEndpoint is the app's OAuth 2.0 v2.0 token endpoint.
func (c ClientCredentials) TokenEndpoint() (string, error) {
	n := c.Normalize()
	if err := n.Validate(); err != nil {
		return "", err
	}
	return n.Authority + "/" + url.PathEscape(n.DirectoryTenantID) + "/oauth2/v2.0/token", nil
}

// ExchangeClientCredentials redeems clientSecret for a Microsoft Graph access
// token (OAuth 2.0 client-credentials grant). The returned token is the
// caller's to wipe; the request body that carried the secret is wiped here.
// Errors never contain the secret or the token.
func ExchangeClientCredentials(ctx context.Context, client *http.Client, c ClientCredentials, clientSecret []byte) ([]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: no http client", ErrTokenExchangeFailed)
	}
	if len(clientSecret) == 0 {
		return nil, ErrClientCredentialsRefused
	}
	endpoint, err := c.TokenEndpoint()
	if err != nil {
		return nil, err
	}
	n := c.Normalize()
	body := make([]byte, 0, 256+3*len(clientSecret))
	body = append(body, "grant_type=client_credentials&client_id="...)
	body = append(body, url.QueryEscape(n.ClientID)...)
	body = append(body, "&scope="...)
	body = append(body, url.QueryEscape(GraphApplicationScope)...)
	body = append(body, "&client_secret="...)
	body = appendFormEscaped(body, clientSecret)
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrTokenExchangeFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: the token endpoint is unreachable from this relay", ErrTokenExchangeFailed)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := secret.ReadBounded(resp.Body, maxTokenResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable token response", ErrTokenExchangeFailed)
	}
	defer secret.Wipe(raw)
	if resp.StatusCode != http.StatusOK {
		var refusal struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &refusal)
		switch refusal.Error {
		case "invalid_client":
			return nil, ErrClientCredentialsRefused
		case "unauthorized_client", "invalid_scope", "invalid_grant":
			return nil, ErrClientNotAuthorized
		}
		return nil, fmt.Errorf("%w: status %d", ErrTokenExchangeFailed, resp.StatusCode)
	}
	var grant struct {
		TokenType   string                 `json:"token_type"`
		AccessToken secretjson.StringBytes `json:"access_token"`
	}
	// Closure: the field is nil until decoded, so a bare defer would wipe nothing.
	defer func() { secret.Wipe(grant.AccessToken) }()
	if err := json.Unmarshal(raw, &grant); err != nil || !strings.EqualFold(grant.TokenType, "Bearer") || len(grant.AccessToken) == 0 {
		return nil, fmt.Errorf("%w: the response is not a bearer token grant", ErrTokenExchangeFailed)
	}
	return append([]byte(nil), grant.AccessToken...), nil
}

// appendFormEscaped percent-encodes b for an application/x-www-form-urlencoded
// value without building an intermediate string.
func appendFormEscaped(dst, b []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			dst = append(dst, c)
		default:
			dst = append(dst, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return dst
}
