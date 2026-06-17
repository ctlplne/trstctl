package azurekv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenProvider supplies the Entra ID (AAD) bearer token the connector presents
// to Key Vault. It is the auth seam: the platform can inject a token from its
// secret store (StaticToken), use the built-in OAuth2 client-credentials
// provider (ClientCredentials), or wrap the Azure SDK's azidentity. Acquiring a
// token is identity-plane work (like sourcing a credential), separate from the
// capability-gated deployment call.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// staticToken is a fixed bearer token.
type staticToken string

// StaticToken returns a TokenProvider that always yields tok. Use it when the
// platform already holds a valid token, or in tests.
func StaticToken(tok string) TokenProvider { return staticToken(tok) }

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// DefaultScope is the OAuth2 scope for the Azure Key Vault data plane.
const DefaultScope = "https://vault.azure.net/.default"

// ClientCredentials is a TokenProvider that obtains a token via the OAuth2
// client-credentials grant against an Entra ID token endpoint, caching it until
// shortly before expiry so repeated deploys do not re-hit the endpoint.
type ClientCredentials struct {
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	client       *http.Client
	now          func() time.Time

	mu     sync.Mutex
	cached string
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
func NewClientCredentials(tokenURL, clientID, clientSecret string, opts ...CredentialOption) *ClientCredentials {
	p := &ClientCredentials{
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        DefaultScope,
		client:       http.DefaultClient,
		now:          time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Token returns a cached token if still valid, otherwise acquires a new one.
func (p *ClientCredentials) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached != "" && p.now().Before(p.exp) {
		return p.cached, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("scope", p.scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return "", fmt.Errorf("token endpoint: status %d: read response: %w", resp.StatusCode, err)
		}
		return "", fmt.Errorf("token endpoint: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("token endpoint: decode: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint: empty access_token")
	}

	ttl := tr.ExpiresIn
	if ttl > 60 {
		ttl -= 60 // refresh a minute before expiry
	}
	p.cached = tr.AccessToken
	p.exp = p.now().Add(time.Duration(ttl) * time.Second)
	return p.cached, nil
}
