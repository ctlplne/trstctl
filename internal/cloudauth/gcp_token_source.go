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

// GCPWorkloadIdentityTokenSource yields Google Cloud access tokens for a
// workload identity instead of a static bearer token (A169-L1, the GCP
// counterpart of A169's Azure source). At each exchange it reads the
// platform's projected OIDC token — a Kubernetes service-account token, a CI
// OIDC token — from a file the platform rotates, exchanges it at GCP Security
// Token Service for a federated access token (RFC 8693), optionally narrows
// that to a service account's access token through IAM Credentials, and keeps
// the result in locked memory until shortly before it expires. trstctl creates
// no assertion of its own and holds no service-account key.
type GCPWorkloadIdentityTokenSource struct {
	cfg    GCPWorkloadIdentityTokenSourceConfig
	minter *Minter
	key    string
	// rotation forgets the cached token when the subject token file is
	// rotated (A169-L3).
	rotation tokenFileRotation
}

// GCPWorkloadIdentityTokenSourceConfig names the workload identity pool
// provider (Audience, //iam.googleapis.com/projects/N/locations/global/
// workloadIdentityPools/POOL/providers/PROVIDER) and the token file.
// STSEndpoint defaults to https://sts.googleapis.com/v1/token. ServiceAccount,
// when set, is impersonated through ImpersonationEndpoint, which defaults to
// IAM Credentials' generateAccessToken for that account.
type GCPWorkloadIdentityTokenSourceConfig struct {
	Audience              string
	SubjectTokenFile      string
	STSEndpoint           string
	ServiceAccount        string
	ImpersonationEndpoint string
	Doer                  cloudhttp.Doer
	// ImpersonationDoer reaches IAM Credentials; nil means Doer.
	ImpersonationDoer cloudhttp.Doer
	// RefreshBefore is how long before expiry a cached token is replaced;
	// zero means five minutes.
	RefreshBefore time.Duration
}

// DefaultGCPSTSEndpoint is Google Cloud's Security Token Service.
const DefaultGCPSTSEndpoint = "https://sts.googleapis.com/v1/token"

// GCPImpersonationEndpoint is IAM Credentials' generateAccessToken for one
// service account.
func GCPImpersonationEndpoint(serviceAccount string) string {
	return "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(strings.TrimSpace(serviceAccount)) + ":generateAccessToken"
}

// NewGCPWorkloadIdentityTokenSource validates the configuration; it exchanges
// nothing until the first Token call.
func NewGCPWorkloadIdentityTokenSource(cfg GCPWorkloadIdentityTokenSourceConfig) (*GCPWorkloadIdentityTokenSource, error) {
	cfg.Audience, cfg.SubjectTokenFile = strings.TrimSpace(cfg.Audience), strings.TrimSpace(cfg.SubjectTokenFile)
	cfg.ServiceAccount = strings.TrimSpace(cfg.ServiceAccount)
	if cfg.Audience == "" || cfg.SubjectTokenFile == "" {
		return nil, errors.New("cloudauth: GCP workload identity needs an audience (the pool provider) and a subject token file")
	}
	if cfg.Doer == nil {
		return nil, errors.New("cloudauth: reviewed GCP HTTP client is required")
	}
	if cfg.ServiceAccount != "" && (!strings.Contains(cfg.ServiceAccount, "@") || strings.ContainsAny(cfg.ServiceAccount, "/?# ")) {
		return nil, errors.New("cloudauth: GCP service account must be an email address")
	}
	sts := strings.TrimSpace(cfg.STSEndpoint)
	if sts == "" {
		sts = DefaultGCPSTSEndpoint
	}
	impersonation := strings.TrimSpace(cfg.ImpersonationEndpoint)
	if cfg.ServiceAccount != "" && impersonation == "" {
		impersonation = GCPImpersonationEndpoint(cfg.ServiceAccount)
	}
	if cfg.ServiceAccount == "" && impersonation != "" {
		return nil, errors.New("cloudauth: a GCP impersonation endpoint needs a service account")
	}
	for _, endpoint := range []string{sts, impersonation} {
		if endpoint == "" {
			continue
		}
		if u, err := url.Parse(endpoint); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("cloudauth: GCP STS and impersonation endpoints must be http(s) URLs")
		}
	}
	cfg.STSEndpoint, cfg.ImpersonationEndpoint = sts, impersonation
	refresh := cfg.RefreshBefore
	if refresh <= 0 {
		refresh = 5 * time.Minute
	}
	return &GCPWorkloadIdentityTokenSource{cfg: cfg, minter: NewMinter(refresh),
		key: "gcp-workload\x00" + cfg.Audience + "\x00" + cfg.ServiceAccount}, nil
}

// Token returns a current access token. The bytes are valid until wipe is
// called; the caller wipes them once the request is authorized.
func (s *GCPWorkloadIdentityTokenSource) Token(ctx context.Context) ([]byte, func(), error) {
	if s.rotation.rotated(s.cfg.SubjectTokenFile) {
		s.minter.Forget(s.key)
	}
	cred, _, err := s.minter.Mint(ctx, s.key, func(ctx context.Context) (Material, error) {
		subject, err := os.ReadFile(s.cfg.SubjectTokenFile) // #nosec G304 -- operator-configured projected token path (CWE-22)
		if err != nil {
			return Material{}, fmt.Errorf("cloudauth: read the subject token file: %w", err)
		}
		defer secret.Wipe(subject)
		trimmed := bytes.TrimSpace(subject)
		if len(trimmed) == 0 {
			return Material{}, errors.New("cloudauth: the subject token file is empty")
		}
		material, err := ExchangeGCPWorkloadIdentity(ctx, s.cfg.Doer, GCPExchangeRequest{
			STSEndpoint: s.cfg.STSEndpoint, Audience: s.cfg.Audience, SubjectToken: trimmed,
			ServiceAccount: s.cfg.ServiceAccount, ImpersonationEndpoint: s.cfg.ImpersonationEndpoint,
			ImpersonationDoer: s.cfg.ImpersonationDoer,
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
		return nil, func() {}, errors.New("cloudauth: GCP exchange returned no access token")
	}
	return cred.Primary.Bytes(), cred.Destroy, nil
}

// Close drops the cached token.
func (s *GCPWorkloadIdentityTokenSource) Close() {
	if s != nil && s.minter != nil {
		s.minter.Close()
	}
}
