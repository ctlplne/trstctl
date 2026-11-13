// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// AzureFederatedTokenSource yields Entra access tokens for a workload identity
// instead of a static bearer token (A169). At each exchange it reads the
// projected federated token — a Kubernetes service-account token, a CI OIDC
// token — from a file the platform rotates, exchanges it through the Entra v2
// token endpoint as a client assertion, and keeps the result in locked memory
// until shortly before it expires. trstctl creates no assertion of its own and
// holds no Entra certificate or key.
type AzureFederatedTokenSource struct {
	cfg    AzureFederatedTokenSourceConfig
	minter *Minter
	key    string
	// rotation forgets the cached token when the federated token file is
	// rotated (A169-L3).
	rotation tokenFileRotation
}

// AzureFederatedTokenSourceConfig names the Entra application and the token
// file. AuthorityHost defaults to https://login.microsoftonline.com.
type AzureFederatedTokenSourceConfig struct {
	TenantID           string
	ClientID           string
	FederatedTokenFile string
	AuthorityHost      string
	Scope              string
	Doer               cloudhttp.Doer
	// RefreshBefore is how long before expiry a cached token is replaced;
	// zero means five minutes.
	RefreshBefore time.Duration
}

// NewAzureFederatedTokenSource validates the configuration; it exchanges
// nothing until the first Token call.
func NewAzureFederatedTokenSource(cfg AzureFederatedTokenSourceConfig) (*AzureFederatedTokenSource, error) {
	cfg.TenantID, cfg.ClientID = strings.TrimSpace(cfg.TenantID), strings.TrimSpace(cfg.ClientID)
	cfg.FederatedTokenFile, cfg.Scope = strings.TrimSpace(cfg.FederatedTokenFile), strings.TrimSpace(cfg.Scope)
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.FederatedTokenFile == "" || cfg.Scope == "" {
		return nil, errors.New("cloudauth: Azure workload identity needs tenant id, client id, federated token file and scope")
	}
	if cfg.Doer == nil {
		return nil, errors.New("cloudauth: reviewed Azure HTTP client is required")
	}
	host := strings.TrimRight(strings.TrimSpace(cfg.AuthorityHost), "/")
	if host == "" {
		host = "https://login.microsoftonline.com"
	}
	if u, err := url.Parse(host); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("cloudauth: Azure authority host must be an http(s) URL")
	}
	cfg.AuthorityHost = host
	refresh := cfg.RefreshBefore
	if refresh <= 0 {
		refresh = 5 * time.Minute
	}
	return &AzureFederatedTokenSource{cfg: cfg, minter: NewMinter(refresh),
		key: "azure-workload\x00" + cfg.TenantID + "\x00" + cfg.ClientID + "\x00" + cfg.Scope}, nil
}

// Token returns a current access token. The bytes are valid until wipe is
// called; the caller wipes them once the request is authorized.
func (s *AzureFederatedTokenSource) Token(ctx context.Context) ([]byte, func(), error) {
	if s.rotation.rotated(s.cfg.FederatedTokenFile) {
		s.minter.Forget(s.key)
	}
	cred, _, err := s.minter.Mint(ctx, s.key, func(ctx context.Context) (Material, error) {
		assertion, err := os.ReadFile(s.cfg.FederatedTokenFile) // #nosec G304 -- operator-configured projected token path (CWE-22)
		if err != nil {
			return Material{}, fmt.Errorf("cloudauth: read the federated token file: %w", err)
		}
		defer secret.Wipe(assertion)
		trimmed := bytes.TrimSpace(assertion)
		if len(trimmed) == 0 {
			return Material{}, errors.New("cloudauth: the federated token file is empty")
		}
		material, err := ExchangeAzureFederatedCredential(ctx, s.cfg.Doer, AzureExchangeRequest{
			Endpoint: s.cfg.AuthorityHost + "/" + url.PathEscape(s.cfg.TenantID) + "/oauth2/v2.0/token",
			ClientID: s.cfg.ClientID, Scope: s.cfg.Scope, SubjectToken: trimmed,
		})
		if err == nil {
			s.rotation.minted(trimmed)
		}
		return material, err
	})
	if err != nil {
		return nil, func() {}, err
	}
	if cred.Primary == nil {
		cred.Destroy()
		return nil, func() {}, errors.New("cloudauth: Azure exchange returned no access token")
	}
	return cred.Primary.Bytes(), cred.Destroy, nil
}

// Close drops the cached token.
func (s *AzureFederatedTokenSource) Close() {
	if s != nil && s.minter != nil {
		s.minter.Close()
	}
}
