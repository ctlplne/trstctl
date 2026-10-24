// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"time"
)

// A115: key inventory cannot say whether a host is under the SSH CA; its sshd
// configuration can. Each host agent that inventories SSH reports its sshd
// trust posture (TrustedUserCAKeys fingerprints, RevokedKeys digest and KRL
// version, HostCertificate details, AuthorizedKeysFile), and the fleet view
// judges it against this tenant's SSH CA and served revocation list.

// SSHHostTrust is one host's sshd configuration as judged against the tenant.
type SSHHostTrust struct {
	AgentID    string `json:"agent_id"`
	Agent      string `json:"agent"`
	SSHDConfig string `json:"sshd_config"`
	// ConfigRead is "read", "missing", or "unreadable".
	ConfigRead string `json:"config_read"`
	// UserCA is "tenant_ca" (sshd accepts user certificates from this tenant's
	// SSH CA and no other), "tenant_ca_and_other", "other_ca", "none" (no
	// TrustedUserCAKeys, or an empty file), or the CA file's read failure
	// ("missing", "unreadable", "relative_path").
	UserCA                string   `json:"user_ca"`
	TrustedCAFingerprints []string `json:"trusted_ca_fingerprints"`
	// HostCertificate is the best certificate the host presents: "tenant_ca",
	// "expiring" (tenant CA, under a third of its validity left), "expired",
	// "not_yet_valid", "other_ca", "unverified" (the signature does not
	// verify), "not_host", "none", or a read failure.
	HostCertificate  string               `json:"host_certificate"`
	HostCertificates []SSHHostCertificate `json:"host_certificates"`
	// RevocationList is "served" (the RevokedKeys file is this control
	// plane's served KRL), "not_served" (another KRL), "key_list" (a plain
	// key list), "missing" (configured but absent: sshd then refuses every
	// key), "none" (revocations are not enforced), or "invalid"/"unreadable".
	RevocationList    string  `json:"revocation_list"`
	KRLVersion        *uint64 `json:"krl_version,omitempty"`
	RevokedKeysSHA256 string  `json:"revoked_keys_sha256,omitempty"`
	// StandingKeys is "off" when AuthorizedKeysFile is none (only
	// certificates log in) and "on" otherwise.
	StandingKeys       string   `json:"standing_keys"`
	AuthorizedKeysFile []string `json:"authorized_keys_file"`
	// MatchBlocks counts Match blocks, whose settings can override these
	// global ones for the connections they match.
	MatchBlocks   int       `json:"match_blocks"`
	FirstObserved time.Time `json:"first_observed"`
	LastObserved  time.Time `json:"last_observed"`
}

// SSHHostCertificate is one HostCertificate a host's sshd presents.
type SSHHostCertificate struct {
	Path string `json:"path"`
	// Judgment is how the certificate stands against the tenant CA, as in
	// SSHHostTrust.HostCertificate.
	Judgment          string   `json:"judgment"`
	CAFingerprint     string   `json:"ca_fingerprint,omitempty"`
	SignatureVerified bool     `json:"signature_verified"`
	KeyFingerprint    string   `json:"key_fingerprint,omitempty"`
	KeyID             string   `json:"key_id,omitempty"`
	Serial            uint64   `json:"serial,omitempty"`
	Principals        []string `json:"principals"`
	ValidAfter        string   `json:"valid_after,omitempty"`
	// ValidBefore is RFC 3339, or "forever".
	ValidBefore string `json:"valid_before,omitempty"`
}

// SSHHostTrustSummary counts hosts by the judgments that matter most.
type SSHHostTrustSummary struct {
	Hosts               int    `json:"hosts"`
	TenantCAConfigured  bool   `json:"tenant_ca_configured"`
	TenantCAFingerprint string `json:"tenant_ca_fingerprint,omitempty"`
	ServedKRLSHA256     string `json:"served_krl_sha256,omitempty"`
	TrustsTenantCA      int    `json:"trusts_tenant_ca"`
	TrustsOtherCAOnly   int    `json:"trusts_other_ca_only"`
	NoUserCA            int    `json:"no_user_ca"`
	TenantHostCert      int    `json:"tenant_host_certificate"`
	EnforcesServedKRL   int    `json:"enforces_served_krl"`
	StandingKeysOn      int    `json:"standing_keys_on"`
}

// SSHHostTrustView is the judged posture of every reporting host.
type SSHHostTrustView struct {
	Hosts   []SSHHostTrust      `json:"hosts"`
	Summary SSHHostTrustSummary `json:"summary"`
}

// SSHHostTrustProvider is the server-side seam that judges reported postures.
type SSHHostTrustProvider func(ctx context.Context, tenantID string) (SSHHostTrustView, error)
