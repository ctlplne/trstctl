// SPDX-License-Identifier: MPL-2.0

package azurekv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

// TokenProvider supplies the Entra ID (AAD) bearer token the connector presents
// to Key Vault. It is the auth seam: the platform can inject a token from its
// secret store (StaticToken), use the built-in OAuth2 client-credentials
// provider (ClientCredentials), or wrap the Azure SDK's azidentity. Acquiring a
// token is identity-plane work (like sourcing a credential), separate from the
// capability-gated deployment call.
type TokenProvider interface {
	Token(ctx context.Context) ([]byte, error)
}

// staticToken is a fixed bearer token.
type staticToken struct{ token []byte }

// StaticToken returns a TokenProvider that always yields tok. Use it when the
// platform already holds a valid token, or in tests.
func StaticToken(tok []byte) TokenProvider { return &staticToken{token: secrettext.Clone(tok)} }

func (s *staticToken) Token(context.Context) ([]byte, error) { return secrettext.Clone(s.token), nil }

func (s *staticToken) Destroy() {
	secret.Wipe(s.token)
	s.token = nil
}

// DefaultScope is the OAuth2 scope for the Azure Key Vault data plane.
const DefaultScope = "https://vault.azure.net/.default"

// ClientCredentials is a TokenProvider that obtains a token via the OAuth2
// client-credentials grant against an Entra ID token endpoint, caching it until
// shortly before expiry so repeated deploys do not re-hit the endpoint.
type ClientCredentials struct {
	tokenURL     string
	clientID     string
	clientSecret []byte
	scope        string
	client       *http.Client
	now          func() time.Time

	mu     sync.Mutex
	cached []byte
	exp    time.Time
}

var _ TokenProvider = (*ClientCredentials)(nil)

// CredentialOption configures a ClientCredentials provider.
type CredentialOption func(*ClientCredentials)

// WithHTTPClient sets the HTTP client used to reach the token endpoint.
func WithHTTPClient(client *http.Client) CredentialOption {
	return func(p *ClientCredentials) {
		if client != nil {
			p.client = client
		}
	}
}

// WithScope overrides the OAuth2 scope (for sovereign clouds).
func WithScope(scope string) CredentialOption {
	return func(p *ClientCredentials) {
		if scope != "" {
			p.scope = scope
		}
	}
}

// NewClientCredentials builds a client-credentials token provider. tokenURL is
// the Entra ID token endpoint
// (https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token).
func NewClientCredentials(tokenURL, clientID string, clientSecret []byte, opts ...CredentialOption) *ClientCredentials {
	p := &ClientCredentials{
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: secrettext.Clone(clientSecret),
		scope:        DefaultScope,
		client:       http.DefaultClient,
		now:          time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Destroy wipes the client secret and any cached access token.
func (p *ClientCredentials) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	secret.Wipe(p.clientSecret)
	secret.Wipe(p.cached)
	p.clientSecret = nil
	p.cached = nil
	p.exp = time.Time{}
}

// Token returns a cached token if still valid, otherwise acquires a new one.
func (p *ClientCredentials) Token(ctx context.Context) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cached) > 0 && p.now().Before(p.exp) {
		return secrettext.Clone(p.cached), nil
	}

	form := make([]byte, 0, len(p.clientID)+len(p.clientSecret)+len(p.scope)+64)
	form = appendFormPair(form, "grant_type", []byte("client_credentials"))
	form = appendFormPair(form, "client_id", []byte(p.clientID))
	form = appendFormPair(form, "client_secret", p.clientSecret)
	form = appendFormPair(form, "scope", []byte(p.scope))
	defer secret.Wipe(form)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, bytes.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, fmt.Errorf("token endpoint: status %d (response body redacted)", resp.StatusCode)
	}

	var tr struct {
		AccessToken secretjson.StringBytes `json:"access_token"`
		ExpiresIn   int                    `json:"expires_in"`
	}
	data, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: read failed (details redacted)")
	}
	defer secret.Wipe(data)
	err = json.Unmarshal(data, &tr)
	defer secret.Wipe(tr.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: decode failed (details redacted)")
	}
	if len(tr.AccessToken) == 0 {
		return nil, fmt.Errorf("token endpoint: empty access_token")
	}

	ttl := tr.ExpiresIn
	if ttl > 60 {
		ttl -= 60 // refresh a minute before expiry
	}
	secret.Wipe(p.cached)
	p.cached = secrettext.Clone(tr.AccessToken)
	p.exp = p.now().Add(time.Duration(ttl) * time.Second)
	return secrettext.Clone(p.cached), nil
}

func appendFormPair(dst []byte, key string, value []byte) []byte {
	if len(dst) > 0 {
		dst = append(dst, '&')
	}
	dst = appendFormEncoded(dst, []byte(key))
	dst = append(dst, '=')
	return appendFormEncoded(dst, value)
}

func appendFormEncoded(dst, value []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, b := range value {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-', b == '_', b == '.', b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hex[b>>4], hex[b&0x0f])
		}
	}
	return dst
}
