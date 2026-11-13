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
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// A156-L1: Jamf Pro API clients. A Jamf poll schedule can name a Jamf Pro API
// client (its client ID) and a secret:// reference to its client secret
// instead of a bearer the operator rotates by hand, as an Intune schedule names
// an Entra app registration (A156). The relay redeems the secret per attempt
// and exchanges it at the same Jamf Pro server's OAuth token endpoint for an
// access token that lives only in memory for that job, for the inventory read
// and for a device check-in alike.

// JamfTokenPath is Jamf Pro's OAuth 2.0 client-credentials token endpoint,
// under the server's base URL.
const JamfTokenPath = "/api/oauth/token" // #nosec G101 -- an endpoint path, not a credential (CWE-798)

// ErrJamfClientRefused is an API client ID or secret Jamf Pro refused, or an
// API client it has disabled.
var ErrJamfClientRefused = errors.New("mdm: Jamf Pro refused the API client ID or client secret")

// JamfAPIClient names a Jamf Pro API client. The client secret is never part
// of it; it travels as a secret:// reference the relay redeems.
type JamfAPIClient struct {
	ClientID string `json:"client_id"`
}

// Normalize trims the client ID.
func (c JamfAPIClient) Normalize() JamfAPIClient {
	c.ClientID = strings.TrimSpace(c.ClientID)
	return c
}

// Validate checks a normalized API client.
func (c JamfAPIClient) Validate() error {
	if !guidPattern.MatchString(c.ClientID) {
		return errors.New("mdm: jamf_api_client.client_id must be the Jamf Pro API client's client ID (a GUID)")
	}
	return nil
}

// JamfTokenEndpoint is the token endpoint of the Jamf Pro server at base. A
// client secret crosses the network to it, so it must be https; only a
// loopback stand-in may be plain http.
func JamfTokenEndpoint(base string) (string, error) {
	u, err := parseAbsolute(base)
	if err != nil {
		return "", err
	}
	if u.User != nil {
		return "", errors.New("mdm: the Jamf Pro base URL must not carry credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return "", errors.New("mdm: a Jamf Pro API client needs an https base URL")
		}
	default:
		return "", errors.New("mdm: a Jamf Pro API client needs an https base URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + JamfTokenPath
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// ExchangeJamfClientCredentials redeems clientSecret at the Jamf Pro server at
// base for an access token (OAuth 2.0 client-credentials grant). The returned
// token is the caller's to wipe; the request body that carried the secret is
// wiped here. Errors never contain the secret or the token.
func ExchangeJamfClientCredentials(ctx context.Context, client *http.Client, base string, c JamfAPIClient, clientSecret []byte) ([]byte, error) {
	grant, err := ExchangeJamfClientCredentialsGrant(ctx, client, base, c, clientSecret)
	return grant.Token, err
}

// ExchangeJamfClientCredentialsGrant is ExchangeJamfClientCredentials with
// the token's lifetime (A156-L2).
func ExchangeJamfClientCredentialsGrant(ctx context.Context, client *http.Client, base string, c JamfAPIClient, clientSecret []byte) (Grant, error) {
	if client == nil {
		return Grant{}, fmt.Errorf("%w: no http client", ErrTokenExchangeFailed)
	}
	if len(clientSecret) == 0 {
		return Grant{}, ErrJamfClientRefused
	}
	n := c.Normalize()
	if err := n.Validate(); err != nil {
		return Grant{}, err
	}
	endpoint, err := JamfTokenEndpoint(base)
	if err != nil {
		return Grant{}, err
	}
	body := make([]byte, 0, 128+3*len(clientSecret))
	body = append(body, "grant_type=client_credentials&client_id="...)
	body = append(body, url.QueryEscape(n.ClientID)...)
	body = append(body, "&client_secret="...)
	body = appendFormEscaped(body, clientSecret)
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Grant{}, fmt.Errorf("%w: build request", ErrTokenExchangeFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: the Jamf Pro token endpoint is unreachable from this relay", ErrTokenExchangeFailed)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := secret.ReadBounded(resp.Body, maxTokenResponseBytes)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: unreadable token response", ErrTokenExchangeFailed)
	}
	defer secret.Wipe(raw)
	switch {
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
		// Jamf Pro answers a wrong client ID or secret, and a disabled API
		// client, with invalid_client.
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &refusal) != nil || refusal.Error == "" || refusal.Error == "invalid_client" {
			return Grant{}, ErrJamfClientRefused
		}
		return Grant{}, fmt.Errorf("%w: status %d", ErrTokenExchangeFailed, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return Grant{}, fmt.Errorf("%w: status %d", ErrTokenExchangeFailed, resp.StatusCode)
	}
	var grant struct {
		TokenType   string                 `json:"token_type"`
		AccessToken secretjson.StringBytes `json:"access_token"`
		ExpiresIn   int64                  `json:"expires_in"`
	}
	// Closure: the field is nil until decoded, so a bare defer would wipe nothing.
	defer func() { secret.Wipe(grant.AccessToken) }()
	if err := json.Unmarshal(raw, &grant); err != nil || !strings.EqualFold(grant.TokenType, "Bearer") || len(grant.AccessToken) == 0 {
		return Grant{}, fmt.Errorf("%w: the response is not a bearer token grant", ErrTokenExchangeFailed)
	}
	return Grant{Token: append([]byte(nil), grant.AccessToken...), Lifetime: grantLifetime(grant.ExpiresIn)}, nil
}
