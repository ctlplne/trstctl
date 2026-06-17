package gcpcm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TokenProvider supplies the Google OAuth2 bearer token the connector presents to
// Certificate Manager. It is the auth seam: the platform can inject a token from
// its secret store (StaticToken), use the metadata server on GCE/GKE/Cloud Run
// (MetadataToken), or wrap the GCP SDK / a service-account JWT-bearer exchange.
// Acquiring a token is identity-plane work, separate from the capability-gated
// deployment call.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// staticToken is a fixed bearer token.
type staticToken string

// StaticToken returns a TokenProvider that always yields tok.
func StaticToken(tok string) TokenProvider { return staticToken(tok) }

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

const (
	defaultMetadataBase = "http://metadata.google.internal"
	defaultServiceAcct  = "default"
)

// MetadataToken obtains an access token from the GCE/GKE metadata server — the
// canonical, crypto-free GCP credential path for workloads running on Google
// compute — caching it until shortly before expiry.
type MetadataToken struct {
	base    string
	account string
	client  *http.Client
	now     func() time.Time

	mu     sync.Mutex
	cached string
	exp    time.Time
}

var _ TokenProvider = (*MetadataToken)(nil)

// MetadataOption configures a MetadataToken provider.
type MetadataOption func(*MetadataToken)

// WithMetadataBase overrides the metadata server base URL (tests).
func WithMetadataBase(base string) MetadataOption {
	return func(m *MetadataToken) {
		if base != "" {
			m.base = strings.TrimRight(base, "/")
		}
	}
}

// WithServiceAccount selects the service account whose token to fetch (default
// "default").
func WithServiceAccount(account string) MetadataOption {
	return func(m *MetadataToken) {
		if account != "" {
			m.account = account
		}
	}
}

// WithMetadataClient sets the HTTP client used to reach the metadata server.
func WithMetadataClient(client *http.Client) MetadataOption {
	return func(m *MetadataToken) {
		if client != nil {
			m.client = client
		}
	}
}

// NewMetadataToken builds a metadata-server token provider.
func NewMetadataToken(opts ...MetadataOption) *MetadataToken {
	m := &MetadataToken{
		base:    defaultMetadataBase,
		account: defaultServiceAcct,
		client:  http.DefaultClient,
		now:     time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Token returns a cached token if still valid, otherwise fetches a new one from
// the metadata server.
func (m *MetadataToken) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cached != "" && m.now().Before(m.exp) {
		return m.cached, nil
	}

	endpoint := m.base + "/computeMetadata/v1/instance/service-accounts/" + m.account + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google") // required; guards against DNS-rebinding to the metadata IP

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return "", fmt.Errorf("metadata server: status %d: read response: %w", resp.StatusCode, err)
		}
		return "", fmt.Errorf("metadata server: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("metadata server: decode: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("metadata server: empty access_token")
	}

	ttl := tr.ExpiresIn
	if ttl > 60 {
		ttl -= 60
	}
	m.cached = tr.AccessToken
	m.exp = m.now().Add(time.Duration(ttl) * time.Second)
	return m.cached, nil
}
