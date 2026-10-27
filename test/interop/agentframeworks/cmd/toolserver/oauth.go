// SPDX-License-Identifier: BUSL-1.1

package main

// oauth.go: the tool server as an OAuth resource server under MCP authorization
// (specification revision 2026-07-28). It publishes protected resource metadata
// (RFC 9728) naming the customer's authorization server, answers a request
// without a usable token with a 401 challenge pointing at that metadata, and
// accepts only access tokens that server issued for this resource: signature
// against the server's key set, issuer, expiry, audience equal to this server's
// canonical URI, the required scope, and an allowed client.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"trstctl.com/trstctl/internal/crypto"
)

type oauthConfig struct {
	// Resource is this server's canonical URI, e.g. https://tools.example.com/mcp.
	Resource string `json:"resource"`
	// Issuer is the authorization server's issuer and JWKSURL its key set.
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_url"`
	// CAFile is the CA trusted for the authorization server's TLS certificate.
	CAFile string `json:"ca_file"`
	// Scopes are required on every token.
	Scopes []string `json:"scopes"`
	// AllowedClients are the client IDs (the token's azp) this server serves.
	AllowedClients []string `json:"allowed_clients"`
}

type oauthAuditRecord struct {
	Time    time.Time `json:"time"`
	Client  string    `json:"client"`
	Tool    string    `json:"tool"`
	Scopes  []string  `json:"scopes"`
	Allowed bool      `json:"allowed"`
}

// oauthHandler serves the tools to callers holding a token for this server.
func oauthHandler(cfg config, audit io.Writer) (http.Handler, error) {
	var mu sync.Mutex
	server := newToolServer(func(tool string) func(context.Context, *mcp.CallToolRequest) error {
		return func(_ context.Context, req *mcp.CallToolRequest) error {
			rec := oauthAuditRecord{Time: time.Now().UTC(), Tool: tool}
			if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
				rec.Client, rec.Scopes, rec.Allowed = req.Extra.TokenInfo.UserID, req.Extra.TokenInfo.Scopes, true
			}
			line, _ := json.Marshal(rec)
			mu.Lock()
			_, _ = audit.Write(append(line, '\n'))
			mu.Unlock()
			if !rec.Allowed {
				return errors.New("refused by the relying service: the call carried no verified token")
			}
			return nil
		}
	})
	return withOAuth(cfg.OAuth, "/mcp", mcpHTTPHandler(server))
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// withOAuth serves the metadata and puts the MCP endpoint behind bearer tokens.
func withOAuth(cfg oauthConfig, mcpPath string, next http.Handler) (http.Handler, error) {
	u, err := url.Parse(cfg.Resource)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("oauth: the resource must be an https URI")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 G703 -- operator-named CA file (CWE-22)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("oauth: the CA file holds no certificate")
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	}
	keys := &keySet{url: cfg.JWKSURL, client: client}
	verifier := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		claimsJSON, err := keys.verify(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
		}
		var claims struct {
			Issuer   string   `json:"iss"`
			Audience audience `json:"aud"`
			Expiry   int64    `json:"exp"`
			Scope    string   `json:"scope"`
			Client   string   `json:"azp"`
		}
		if err := json.Unmarshal(claimsJSON, &claims); err != nil {
			return nil, fmt.Errorf("%w: unreadable claims", auth.ErrInvalidToken)
		}
		switch {
		case claims.Issuer != cfg.Issuer:
			return nil, fmt.Errorf("%w: issued by %s", auth.ErrInvalidToken, claims.Issuer)
		case !slices.Contains([]string(claims.Audience), cfg.Resource):
			return nil, fmt.Errorf("%w: not issued for this server", auth.ErrInvalidToken)
		case len(cfg.AllowedClients) > 0 && !slices.Contains(cfg.AllowedClients, claims.Client):
			return nil, fmt.Errorf("%w: client %s is not served here", auth.ErrInvalidToken, claims.Client)
		}
		return &auth.TokenInfo{Scopes: strings.Fields(claims.Scope), Expiration: time.Unix(claims.Expiry, 0), UserID: claims.Client}, nil
	}
	metadataPath := "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.Path, "/")
	mux := http.NewServeMux()
	mux.Handle(metadataPath, auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               cfg.Resource,
		AuthorizationServers:   []string{cfg.Issuer},
		ScopesSupported:        cfg.Scopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "trstctl reference tools",
	}))
	mux.Handle(mcpPath, auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: u.Scheme + "://" + u.Host + metadataPath,
		Scopes:              cfg.Scopes,
	})(next))
	return mux, nil
}

// keySet caches the authorization server's keys and refetches, at most every ten
// seconds, when a token names a key it does not hold.
type keySet struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	jwks   crypto.JWKS
	loaded time.Time
}

func (k *keySet) verify(ctx context.Context, token string) ([]byte, error) {
	jwks, err := k.get(ctx, false)
	if err != nil {
		return nil, err
	}
	if claims, err := crypto.VerifyJWT(token, jwks); err == nil {
		return claims, nil
	}
	if jwks, err = k.get(ctx, true); err != nil {
		return nil, err
	}
	return crypto.VerifyJWT(token, jwks)
}

func (k *keySet) get(ctx context.Context, refresh bool) (crypto.JWKS, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.jwks.Keys) > 0 && (!refresh || time.Since(k.loaded) < 10*time.Second) {
		return k.jwks, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return crypto.JWKS{}, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return crypto.JWKS{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return crypto.JWKS{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return crypto.JWKS{}, fmt.Errorf("the authorization server's key set answered %d", resp.StatusCode)
	}
	jwks, err := crypto.ParseJWKS(body)
	if err != nil {
		return crypto.JWKS{}, err
	}
	k.jwks, k.loaded = jwks, time.Now()
	return jwks, nil
}
