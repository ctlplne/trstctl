// SPDX-License-Identifier: BUSL-1.1

package offline

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// OfflinePolicy is the public, deployment-bound authority installed in an
// isolated recovery signer before an outage. The custodian keys authenticate
// approvals; they are not CA keys and never authorize a generic Sign call.
type OfflinePolicy struct {
	TenantID              string             `json:"tenant_id"`
	DeploymentID          string             `json:"deployment_id"`
	Epoch                 uint64             `json:"epoch"`
	Threshold             int                `json:"threshold"`
	MaxTTLSeconds         int64              `json:"max_ttl_seconds"`
	PermittedDNSSuffixes  []string           `json:"permitted_dns_suffixes,omitempty"`
	PermittedIPCIDRs      []string           `json:"permitted_ip_cidrs,omitempty"`
	PermittedEmailDomains []string           `json:"permitted_email_domains,omitempty"`
	PermittedURIPrefixes  []string           `json:"permitted_uri_prefixes,omitempty"`
	Custodians            []OfflineCustodian `json:"custodians"`
}

type OfflineCustodian struct {
	ID           string `json:"id"`
	PublicKeyDER []byte `json:"public_key_der"`
}

// OfflineRequest is the exact operation every custodian reviews and signs. Its
// CSR is signed by the workload key; CanonicalBytes commits to those exact bytes.
type OfflineRequest struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	DeploymentID string    `json:"deployment_id"`
	Epoch        uint64    `json:"epoch"`
	CAKeySHA256  string    `json:"ca_public_key_sha256"`
	Requester    string    `json:"requester"`
	Subject      string    `json:"subject"`
	CSRDER       []byte    `json:"csr_der"`
	Reason       string    `json:"reason"`
	TTLSeconds   int64     `json:"ttl_seconds"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type OfflineApproval struct {
	CustodianID string `json:"custodian_id"`
	Signature   []byte `json:"signature"`
}

// CanonicalBytes has one encoding across machines and languages. It is domain
// separated from every other use of the custodian's key and includes the exact
// CSR hash, tenant, deployment, policy epoch, requester, TTL and expiry.
func (r OfflineRequest) CanonicalBytes() ([]byte, error) {
	if r.ExpiresAt.IsZero() {
		return nil, errors.New("breakglass: offline request expiry is required")
	}
	return json.Marshal(struct {
		Domain       string `json:"domain"`
		ID           string `json:"id"`
		TenantID     string `json:"tenant_id"`
		DeploymentID string `json:"deployment_id"`
		Epoch        uint64 `json:"epoch"`
		CAKeySHA256  string `json:"ca_public_key_sha256"`
		Requester    string `json:"requester"`
		Subject      string `json:"subject"`
		CSRSHA256    string `json:"csr_sha256"`
		Reason       string `json:"reason"`
		TTLSeconds   int64  `json:"ttl_seconds"`
		ExpiresAt    int64  `json:"expires_at_unix_nano"`
	}{"trstctl.breakglass.offline.request.v2", r.ID, r.TenantID, r.DeploymentID,
		r.Epoch, r.CAKeySHA256, r.Requester, r.Subject, crypto.SHA256Hex(r.CSRDER), r.Reason,
		r.TTLSeconds, r.ExpiresAt.UTC().UnixNano()})
}

// VerifyOfflineApprovals is a signer-side, public-key-only gate. It rejects a
// caller's bare names even if those names belong to the roster. The caller must
// hold distinct signatures over this exact live request from m custodians.
func VerifyOfflineApprovals(policy OfflinePolicy, request OfflineRequest, approvals []OfflineApproval, now time.Time) error {
	if err := ValidateOfflinePolicy(policy); err != nil {
		return err
	}
	if request.TenantID != policy.TenantID || request.DeploymentID != policy.DeploymentID || request.Epoch != policy.Epoch {
		return errors.New("breakglass: offline request does not match installed tenant, deployment and policy epoch")
	}
	if strings.TrimSpace(request.ID) == "" || strings.TrimSpace(request.Requester) == "" ||
		strings.TrimSpace(request.Reason) == "" || request.TTLSeconds <= 0 || request.TTLSeconds > policy.MaxTTLSeconds {
		return errors.New("breakglass: offline request identity, reason or lifetime is invalid")
	}
	if decoded, err := hex.DecodeString(request.CAKeySHA256); err != nil || len(decoded) != 32 ||
		request.CAKeySHA256 != strings.ToLower(request.CAKeySHA256) {
		return errors.New("breakglass: offline request needs a canonical recovery CA public-key fingerprint")
	}
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(24*time.Hour)) {
		return errors.New("breakglass: offline request has expired or exceeds the approval window")
	}
	info, err := InspectEmergencyCSR(request.Subject, request.CSRDER)
	if err != nil {
		return err
	}
	if len(info.DNSNames)+len(info.IPAddresses)+len(info.EmailAddresses)+len(info.URIs) == 0 {
		return errors.New("breakglass: offline CSR must carry at least one policy-checked SAN")
	}
	if err := crypto.EnforceLeafProfileInfo(info, time.Duration(request.TTLSeconds)*time.Second, crypto.LeafProfile{
		PermittedDNSSuffixes:  policy.PermittedDNSSuffixes,
		PermittedIPCIDRs:      policy.PermittedIPCIDRs,
		PermittedEmailDomains: policy.PermittedEmailDomains,
		PermittedURIPrefixes:  policy.PermittedURIPrefixes,
	}); err != nil {
		return fmt.Errorf("breakglass: offline identity policy: %w", err)
	}
	roster := make(map[string][]byte, len(policy.Custodians))
	for _, custodian := range policy.Custodians {
		roster[custodian.ID] = custodian.PublicKeyDER
	}
	if len(approvals) < policy.Threshold || len(approvals) > len(roster) {
		return errors.New("breakglass: offline custodian quorum not met")
	}
	message, err := request.CanonicalBytes()
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(approvals))
	for _, approval := range approvals {
		pub, allowed := roster[approval.CustodianID]
		if !allowed || seen[approval.CustodianID] || approval.CustodianID == request.Requester {
			return errors.New("breakglass: unauthorized, repeated or self-approving custodian")
		}
		if err := crypto.VerifyEd25519(pub, message, approval.Signature); err != nil {
			return fmt.Errorf("breakglass: invalid custodian signature: %w", err)
		}
		seen[approval.CustodianID] = true
	}
	return nil
}

// InspectEmergencyCSR validates the signed workload identity reviewed by the
// custodians without linking the online control-plane package into the signer.
func InspectEmergencyCSR(subject string, csrDER []byte) (crypto.CSRInfo, error) {
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		return crypto.CSRInfo{}, fmt.Errorf("breakglass: CSR must be a signed PKCS#10 certificate request: %w", err)
	}
	if subject == "" || info.CommonName != subject {
		return crypto.CSRInfo{}, errors.New("breakglass: CSR common name must exactly match emergency certificate subject")
	}
	return info, nil
}

// ValidateOfflinePolicy rejects malformed trust roots before a signer commits
// a kit. Duplicate identities and unparseable keys must not become authority.
func ValidateOfflinePolicy(policy OfflinePolicy) error {
	if policy.TenantID == "" || policy.DeploymentID == "" || policy.Epoch == 0 ||
		policy.Threshold < 2 || policy.Threshold > len(policy.Custodians) || policy.MaxTTLSeconds <= 0 {
		return errors.New("breakglass: invalid offline policy")
	}
	if len(policy.PermittedDNSSuffixes)+len(policy.PermittedIPCIDRs)+len(policy.PermittedEmailDomains)+len(policy.PermittedURIPrefixes) == 0 {
		return errors.New("breakglass: offline policy must bound at least one SAN identity type")
	}
	roster := make(map[string][]byte, len(policy.Custodians))
	for _, custodian := range policy.Custodians {
		if custodian.ID == "" || len(custodian.PublicKeyDER) == 0 || roster[custodian.ID] != nil {
			return errors.New("breakglass: invalid or duplicate custodian in offline policy")
		}
		if err := crypto.ValidateEd25519PublicKeyDER(custodian.PublicKeyDER); err != nil {
			return fmt.Errorf("breakglass: invalid custodian public key: %w", err)
		}
		roster[custodian.ID] = custodian.PublicKeyDER
	}
	return nil
}
