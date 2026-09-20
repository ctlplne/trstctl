// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

const defaultCodeSigningHTTPTimeout = 10 * time.Second

// CodeSigning configures the shipped F50 service. Every named key and keyless
// trust source is tenant-bound at composition time; the isolated signer owns all
// private key operations.
type CodeSigning struct {
	Enabled            bool                    `json:"enabled,omitempty"`
	Keys               []CodeSigningKey        `json:"keys,omitempty"`
	GitHubOIDCTenants  []CodeSigningGitHubOIDC `json:"github_oidc_tenants,omitempty"`
	EphemeralAlgorithm string                  `json:"ephemeral_algorithm,omitempty"`
	Rekor              CodeSigningRekor        `json:"rekor,omitempty"`
}

// CodeSigningKey binds one user-facing key id to one signer-local handle under
// exactly one tenant. CreateIfMissing provisions a purpose-constrained key inside
// trstctl-signer; it never exports private material to the control plane.
type CodeSigningKey struct {
	TenantID           string `json:"tenant_id"`
	ID                 string `json:"id"`
	Handle             string `json:"handle,omitempty"`
	Algorithm          string `json:"algorithm,omitempty"`
	CreateIfMissing    bool   `json:"create_if_missing,omitempty"`
	RequireDualControl bool   `json:"require_dual_control,omitempty"`
}

// CodeSigningGitHubOIDC is one tenant's offline GitHub Actions OIDC trust source.
// JWKS is file/inline public material, so token verification does not fetch keys on
// the signing request hot path.
type CodeSigningGitHubOIDC struct {
	TenantID      string   `json:"tenant_id"`
	Issuer        string   `json:"issuer,omitempty"`
	Audience      string   `json:"audience"`
	JWKSFile      string   `json:"jwks_file,omitempty"`
	JWKSJSON      string   `json:"jwks_json,omitempty"`
	AllowedOwners []string `json:"allowed_owners,omitempty"`
}

// CodeSigningRekor configures asynchronous Rekor v1 HashedRekord publication.
// Endpoint defaults to Sigstore's public service but may name an operator-run
// Rekor instance. Private ranges require exact CIDR allowlisting.
type CodeSigningRekor struct {
	Endpoint          string   `json:"endpoint,omitempty"`
	Timeout           string   `json:"timeout,omitempty"`
	LogPublicKeyFile  string   `json:"log_public_key_file"`
	AllowPrivateCIDRs []string `json:"allow_private_cidrs,omitempty"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http,omitempty"`
}

func (c CodeSigningRekor) TimeoutDuration() (time.Duration, error) {
	if strings.TrimSpace(c.Timeout) == "" {
		return defaultCodeSigningHTTPTimeout, nil
	}
	return time.ParseDuration(c.Timeout)
}

// applyCodeSigningEnv overlays scalar deployment switches. Tenant key and trust
// lists remain structured-config-only because flattening them into parallel env
// variables would make tenant/key associations ambiguous.
func applyCodeSigningEnv(getenv func(string) string, c *CodeSigning) {
	if c == nil {
		return
	}
	setBool(getenv, "TRSTCTL_CODE_SIGNING_ENABLED", &c.Enabled)
	setString(getenv, "TRSTCTL_CODE_SIGNING_EPHEMERAL_ALGORITHM", &c.EphemeralAlgorithm)
	setString(getenv, "TRSTCTL_CODE_SIGNING_REKOR_ENDPOINT", &c.Rekor.Endpoint)
	setString(getenv, "TRSTCTL_CODE_SIGNING_REKOR_TIMEOUT", &c.Rekor.Timeout)
	setString(getenv, "TRSTCTL_CODE_SIGNING_REKOR_LOG_PUBLIC_KEY_FILE", &c.Rekor.LogPublicKeyFile)
	setCSV(getenv, "TRSTCTL_CODE_SIGNING_REKOR_ALLOW_PRIVATE_CIDRS", &c.Rekor.AllowPrivateCIDRs)
	setBool(getenv, "TRSTCTL_CODE_SIGNING_REKOR_ALLOW_INSECURE_HTTP", &c.Rekor.AllowInsecureHTTP)
}

func validateCodeSigning(c CodeSigning) []error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if len(c.Keys) == 0 && len(c.GitHubOIDCTenants) == 0 {
		errs = append(errs, errors.New("code_signing requires at least one tenant key or GitHub OIDC trust source when enabled"))
	}
	seenIDs := map[string]bool{}
	seenHandles := map[string]bool{}
	for i, key := range c.Keys {
		where := fmt.Sprintf("code_signing.keys[%d]", i)
		if strings.TrimSpace(key.TenantID) == "" {
			errs = append(errs, fmt.Errorf("%s.tenant_id is required", where))
		}
		if strings.TrimSpace(key.ID) == "" {
			errs = append(errs, fmt.Errorf("%s.id is required", where))
		}
		identity := strings.TrimSpace(key.TenantID) + "\x00" + strings.TrimSpace(key.ID)
		if seenIDs[identity] {
			errs = append(errs, fmt.Errorf("%s duplicates tenant/key id", where))
		}
		seenIDs[identity] = true
		if handle := strings.TrimSpace(key.Handle); handle != "" {
			if seenHandles[handle] {
				errs = append(errs, fmt.Errorf("%s.handle %q is shared by multiple tenant keys", where, handle))
			}
			seenHandles[handle] = true
		}
		switch strings.TrimSpace(key.Algorithm) {
		case "", "ecdsa-p256", "rsa-2048", "rsa-3072", "rsa-4096":
		default:
			errs = append(errs, fmt.Errorf("%s.algorithm %q is invalid for SHA-256 code signing", where, key.Algorithm))
		}
	}
	seenTenants := map[string]bool{}
	for i, source := range c.GitHubOIDCTenants {
		where := fmt.Sprintf("code_signing.github_oidc_tenants[%d]", i)
		tenant := strings.TrimSpace(source.TenantID)
		if tenant == "" {
			errs = append(errs, fmt.Errorf("%s.tenant_id is required", where))
		} else if seenTenants[tenant] {
			errs = append(errs, fmt.Errorf("%s duplicates tenant %q", where, tenant))
		}
		seenTenants[tenant] = true
		if strings.TrimSpace(source.Audience) == "" {
			errs = append(errs, fmt.Errorf("%s.audience is required", where))
		}
		if (strings.TrimSpace(source.JWKSFile) == "") == (strings.TrimSpace(source.JWKSJSON) == "") {
			errs = append(errs, fmt.Errorf("%s requires exactly one of jwks_file or jwks_json", where))
		}
	}
	switch strings.TrimSpace(c.EphemeralAlgorithm) {
	case "", "ecdsa-p256":
	default:
		errs = append(errs, fmt.Errorf("code_signing.ephemeral_algorithm %q is invalid (keyless supports ecdsa-p256)", c.EphemeralAlgorithm))
	}
	errs = append(errs, validateCodeSigningRekor(c.Rekor)...)
	return errs
}

func validateCodeSigningRekor(c CodeSigningRekor) []error {
	var errs []error
	if strings.TrimSpace(c.LogPublicKeyFile) == "" {
		errs = append(errs, errors.New("code_signing.rekor.log_public_key_file is required to verify signed entry timestamps"))
	}
	timeout, err := c.TimeoutDuration()
	if err != nil {
		errs = append(errs, fmt.Errorf("code_signing.rekor.timeout %q is invalid: %w", c.Timeout, err))
	} else if timeout <= 0 {
		errs = append(errs, errors.New("code_signing.rekor.timeout must be positive"))
	}
	for _, raw := range c.AllowPrivateCIDRs {
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			errs = append(errs, fmt.Errorf("code_signing.rekor.allow_private_cidrs entry %q is invalid: %w", raw, err))
		}
	}
	if strings.TrimSpace(c.Endpoint) == "" {
		return errs
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" {
		return append(errs, fmt.Errorf("code_signing.rekor.endpoint %q must be an absolute URL", c.Endpoint))
	}
	if u.Scheme == "https" {
		return errs
	}
	ip := net.ParseIP(u.Hostname())
	loopback := strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())
	if u.Scheme != "http" || !c.AllowInsecureHTTP || !loopback {
		errs = append(errs, errors.New("code_signing.rekor.endpoint must use https; explicit insecure http is allowed only for loopback development/emulators"))
	}
	return errs
}
