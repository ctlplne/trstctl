// SPDX-License-Identifier: BUSL-1.1

// Package oauthclient is the agent's side of MCP authorization with a trstctl
// agent identity. When an MCP server answers 401, it follows the server's
// protected resource metadata (RFC 9728) to the customer's authorization server
// (RFC 8414 or OpenID discovery), takes a client credentials grant there
// authenticated with a private_key_jwt client assertion (RFC 7523) signed by the
// key behind the agent's trstctl certificate, and can exchange that token through
// the authorization server's own token exchange (RFC 8693) for one carrying the
// MCP server's scope. trstctl is not the authorization server: it publishes the
// agent's current public keys, which the authorization server reads to check the
// assertion.
package oauthclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const (
	jwtBearerAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- an RFC 7523 assertion type URN, not a credential (CWE-798)
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"        // #nosec G101 -- an RFC 8693 grant type URN, not a credential (CWE-798)
	accessTokenType    = "urn:ietf:params:oauth:token-type:access_token"          // #nosec G101 -- an RFC 8693 token type URN, not a credential (CWE-798)
	privateKeyJWT      = "private_key_jwt"
	assertionLifetime  = time.Minute
)

// Step is one recorded step of the authorization flow.
type Step struct {
	Step   string `json:"step"`
	Detail string `json:"detail"`
}

// Handler implements the MCP Go SDK's auth.OAuthHandler.
type Handler struct {
	// ClientID is the agent's client at the authorization server.
	ClientID string
	// Key signs the client assertions: the private key of the agent's trstctl
	// certificate. The assertion names it by its SPKI SHA-256, the key ID trstctl
	// publishes it under.
	Key crypto.Signer
	// HTTPClient reaches the MCP server's metadata and the authorization server.
	HTTPClient *http.Client
	// Exchange trades the client credentials token for one carrying the MCP
	// server's scope through the authorization server's token exchange.
	Exchange bool
	// Record receives each step.
	Record func(Step)

	mu    sync.Mutex
	token *oauth2.Token
}

var _ auth.OAuthHandler = (*Handler)(nil)

// TokenSource returns the current token, or nil before Authorize ran.
func (h *Handler) TokenSource(context.Context) (oauth2.TokenSource, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.token == nil {
		return nil, nil
	}
	return oauth2.StaticTokenSource(h.token), nil
}

// Authorize runs the flow after the MCP server refused a request.
func (h *Handler) Authorize(ctx context.Context, req *http.Request, resp *http.Response) error {
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	challenges, err := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		return fmt.Errorf("oauthclient: read the server's challenge: %w", err)
	}
	metadataURL, scope := challengeParams(challenges)
	if metadataURL == "" {
		return errors.New("oauthclient: the MCP server's challenge names no resource_metadata")
	}
	prm, err := oauthex.GetProtectedResourceMetadata(ctx, metadataURL, canonicalResource(req.URL), h.HTTPClient)
	if err != nil || prm == nil || len(prm.AuthorizationServers) == 0 {
		return fmt.Errorf("oauthclient: protected resource metadata: %v", err)
	}
	h.record("protected-resource-metadata", prm.Resource+" names "+prm.AuthorizationServers[0])
	if scope == "" {
		scope = strings.Join(prm.ScopesSupported, " ")
	}
	asm, err := auth.GetAuthServerMetadata(ctx, prm.AuthorizationServers[0], h.HTTPClient)
	if err != nil || asm == nil || asm.TokenEndpoint == "" {
		return fmt.Errorf("oauthclient: authorization server metadata: %v", err)
	}
	if !slices.Contains(asm.TokenEndpointAuthMethodsSupported, privateKeyJWT) {
		return errors.New("oauthclient: the authorization server does not accept private_key_jwt")
	}
	h.record("authorization-server", asm.Issuer)

	grant := url.Values{"grant_type": {"client_credentials"}, "resource": {prm.Resource}}
	if !h.Exchange {
		grant.Set("scope", scope)
	}
	token, err := h.tokenRequest(ctx, asm, grant)
	if err != nil {
		return err
	}
	h.record("client-credentials", "token for "+h.ClientID+" authenticated with private_key_jwt")
	if h.Exchange {
		token, err = h.tokenRequest(ctx, asm, url.Values{
			"grant_type":           {tokenExchangeGrant},
			"subject_token":        {token.AccessToken},
			"subject_token_type":   {accessTokenType},
			"requested_token_type": {accessTokenType},
			"scope":                {scope},
			"resource":             {prm.Resource},
		})
		if err != nil {
			return err
		}
		h.record("token-exchange", "token with scope "+scope)
	}
	h.mu.Lock()
	h.token = token
	h.mu.Unlock()
	return nil
}

// tokenRequest posts one token request, authenticated with a fresh assertion.
func (h *Handler) tokenRequest(ctx context.Context, asm *oauthex.AuthServerMeta, form url.Values) (*oauth2.Token, error) {
	if err := httpsOrLoopback(asm.TokenEndpoint); err != nil {
		return nil, err
	}
	assertion, err := h.assertion(asm.Issuer)
	if err != nil {
		return nil, err
	}
	form.Set("client_id", h.ClientID)
	form.Set("client_assertion_type", jwtBearerAssertion)
	form.Set("client_assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, asm.TokenEndpoint, strings.NewReader(form.Encode())) // #nosec G704 -- the token endpoint of the authorization server the MCP server's metadata names, checked https or loopback (CWE-918)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.HTTPClient.Do(req) // #nosec G704 -- see the request above (CWE-918)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		h.record("token-refused", strings.TrimSpace(out.Error+" "+out.Description))
		return nil, fmt.Errorf("oauthclient: the authorization server refused the token request: %s", strings.TrimSpace(out.Error+" "+out.Description))
	}
	return &oauth2.Token{
		AccessToken: out.AccessToken, TokenType: out.TokenType,
		Expiry: time.Now().Add(time.Duration(out.ExpiresIn) * time.Second),
	}, nil
}

// assertion builds an RFC 7523 client assertion: iss and sub are the client ID, aud
// the authorization server's issuer, a unique jti, and a one-minute lifetime.
func (h *Handler) assertion(audience string) (string, error) {
	pub, ok := h.Key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().BitSize != 256 {
		return "", errors.New("oauthclient: the agent key must be ECDSA P-256 (ES256)")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	kid := sha256.Sum256(spki)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": hex.EncodeToString(kid[:])})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": h.ClientID, "sub": h.ClientID, "aud": audience, "jti": hex.EncodeToString(jti),
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	signingInput := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signingInput))
	der, err := h.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return "", errors.New("oauthclient: the key returned a malformed signature")
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return signingInput + "." + b64(raw), nil
}

// httpsOrLoopback refuses a token endpoint that would carry the client assertion
// in clear text anywhere but this machine.
func httpsOrLoopback(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("oauthclient: token endpoint: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("oauthclient: the token endpoint %s is neither https nor loopback", endpoint)
}

func (h *Handler) record(step, detail string) {
	if h.Record != nil {
		h.Record(Step{Step: step, Detail: detail})
	}
}

func challengeParams(challenges []oauthex.Challenge) (metadataURL, scope string) {
	for _, c := range challenges {
		if c.Scheme == "bearer" {
			return c.Params["resource_metadata"], c.Params["scope"]
		}
	}
	return "", ""
}

// canonicalResource is the MCP server's URI without query, fragment or trailing slash.
func canonicalResource(u *url.URL) string {
	c := *u
	c.RawQuery, c.Fragment = "", ""
	return strings.TrimSuffix(c.String(), "/")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
