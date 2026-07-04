// SPDX-License-Identifier: MPL-2.0

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

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

// TokenProvider supplies the Google OAuth2 bearer token the connector presents to
// Certificate Manager. It is the auth seam: the platform can inject a token from
// its secret store (StaticToken), use the metadata server on GCE/GKE/Cloud Run
// (MetadataToken), or wrap the GCP SDK / a service-account JWT-bearer exchange.
// Acquiring a token is identity-plane work, separate from the capability-gated
// deployment call.
type TokenProvider interface {
	Token(ctx context.Context) ([]byte, error)
}

// staticToken is a fixed bearer token.
type staticToken []byte

// StaticToken returns a TokenProvider that always yields tok.
func StaticToken(tok []byte) TokenProvider { return staticToken(secrettext.Clone(tok)) }

func (s staticToken) Token(context.Context) ([]byte, error) { return secrettext.Clone(s), nil }

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
	cached []byte
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
func (m *MetadataToken) Token(ctx context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cached) > 0 && m.now().Before(m.exp) {
		return secrettext.Clone(m.cached), nil
	}

	endpoint := m.base + "/computeMetadata/v1/instance/service-accounts/" + m.account + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google") // required; guards against DNS-rebinding to the metadata IP

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metadata server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return nil, fmt.Errorf("metadata server: status %d: read response: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("metadata server: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var tr struct {
		AccessToken secretjson.StringBytes `json:"access_token"`
		ExpiresIn   int                    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("metadata server: decode: %w", err)
	}
	if len(tr.AccessToken) == 0 {
		return nil, fmt.Errorf("metadata server: empty access_token")
	}

	ttl := tr.ExpiresIn
	if ttl > 60 {
		ttl -= 60
	}
	secret.Wipe(m.cached)
	m.cached = secrettext.Clone(tr.AccessToken)
	secret.Wipe(tr.AccessToken)
	m.exp = m.now().Add(time.Duration(ttl) * time.Second)
	return secrettext.Clone(m.cached), nil
}
