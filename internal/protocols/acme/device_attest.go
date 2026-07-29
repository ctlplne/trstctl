// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// DeviceAttestationPolicy is the already tenant/profile-scoped TPM policy the
// ACME package needs. Private attestation keys never cross this interface.
type DeviceAttestationPolicy struct {
	TrustedRootsPEM   [][]byte
	AllowedAlgorithms []int64
	MaxAge            time.Duration
}

// DeviceAttestationPolicySource resolves the policy for exactly one tenant and
// identifier. false means device-attest-01 stays absent, which is the default.
type DeviceAttestationPolicySource interface {
	DeviceAttestationPolicy(ctx context.Context, tenantID, identifier string) (DeviceAttestationPolicy, bool, error)
}

// DeviceAttestationBinding is the full server context cryptographically bound
// into the TPM WebAuthn challenge.
type DeviceAttestationBinding struct {
	TenantID     string
	AccountURL   string
	OrderID      string
	ChallengeID  string
	Token        string
	Nonce        string
	Identifier   string
	CSRKeySHA256 []byte
	IssuedAt     time.Time
}

// DeviceAttestationResponse is the device-attest-01 challenge payload.
type DeviceAttestationResponse struct {
	DeviceIdentifier string          `json:"device_identifier"`
	IssuedAt         time.Time       `json:"issued_at"`
	CSR              string          `json:"csr"`
	Attestation      json.RawMessage `json:"attestation"`
}

func deviceAttestationBinding(binding DeviceAttestationBinding) ([]byte, error) {
	if binding.TenantID == "" || binding.AccountURL == "" || binding.OrderID == "" ||
		binding.ChallengeID == "" || binding.Token == "" || binding.Nonce == "" ||
		binding.Identifier == "" || len(binding.CSRKeySHA256) != 32 || binding.IssuedAt.IsZero() {
		return nil, errors.New("acme: incomplete device attestation binding")
	}
	canonical, err := json.Marshal(struct {
		Version      int    `json:"version"`
		TenantID     string `json:"tenant_id"`
		AccountURL   string `json:"account_url"`
		OrderID      string `json:"order_id"`
		ChallengeID  string `json:"challenge_id"`
		Token        string `json:"token"`
		Nonce        string `json:"nonce"`
		Identifier   string `json:"identifier"`
		CSRKeySHA256 string `json:"csr_key_sha256"`
		IssuedAt     string `json:"issued_at"`
	}{
		Version:      1,
		TenantID:     binding.TenantID,
		AccountURL:   binding.AccountURL,
		OrderID:      binding.OrderID,
		ChallengeID:  binding.ChallengeID,
		Token:        binding.Token,
		Nonce:        binding.Nonce,
		Identifier:   binding.Identifier,
		CSRKeySHA256: base64.RawURLEncoding.EncodeToString(binding.CSRKeySHA256),
		IssuedAt:     binding.IssuedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("acme: encode device attestation binding: %w", err)
	}
	return crypto.SHA256Sum(canonical), nil
}

func (s *Server) validateDeviceAttestation(
	ctx context.Context,
	msg *jose.ACMEMessage,
	acct *account,
	ch *challenge,
	az *authorization,
	o *order,
) ([]byte, error) {
	if msg == nil || acct == nil || ch == nil || az == nil || o == nil {
		return nil, errors.New("device attestation state is incomplete")
	}
	if o.accountURL != acct.url {
		return nil, errors.New("device attestation account does not own this order")
	}
	if ch.status != statusPending {
		return nil, errors.New("device attestation challenge is not pending")
	}
	policy, enabled, err := s.lookupDeviceAttestationPolicy(ctx, az.domain)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, errors.New("device attestation is not enabled for this tenant, profile, and identifier")
	}

	var response DeviceAttestationResponse
	if err := json.Unmarshal(msg.Payload, &response); err != nil {
		return nil, fmt.Errorf("decode device attestation response: %w", err)
	}
	if response.DeviceIdentifier != az.domain {
		return nil, errors.New("device attestation identifier does not match the authorization")
	}
	now := s.deviceAttestNow()
	if response.IssuedAt.IsZero() || response.IssuedAt.After(now.Add(30*time.Second)) ||
		now.Sub(response.IssuedAt) > policy.MaxAge {
		return nil, errors.New("device attestation is outside the allowed freshness window")
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(response.CSR)
	if err != nil {
		return nil, fmt.Errorf("decode device attestation CSR: %w", err)
	}
	csrDigest, err := deviceattest.CSRPublicKeySHA256(csrDER)
	if err != nil {
		return nil, err
	}
	challenge, err := deviceAttestationBinding(DeviceAttestationBinding{
		TenantID:     s.stateTenantID,
		AccountURL:   acct.url,
		OrderID:      o.id,
		ChallengeID:  ch.id,
		Token:        ch.token,
		Nonce:        msg.Protected.Nonce,
		Identifier:   az.domain,
		CSRKeySHA256: csrDigest,
		IssuedAt:     response.IssuedAt,
	})
	if err != nil {
		return nil, err
	}
	result, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		response.Attestation,
		challenge,
		policy.TrustedRootsPEM,
		policy.AllowedAlgorithms,
		now,
	)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(result.PublicKeySHA256, csrDigest) {
		return nil, errors.New("device attestation key does not match the bound CSR")
	}
	if o.attestedKeySHA256 != "" &&
		o.attestedKeySHA256 != base64.RawURLEncoding.EncodeToString(csrDigest) {
		return nil, errors.New("device attestation key does not match the key already bound to this order")
	}
	return csrDigest, nil
}

func (s *Server) lookupDeviceAttestationPolicy(ctx context.Context, identifier string) (DeviceAttestationPolicy, bool, error) {
	if s.deviceAttestationPolicy == nil {
		return DeviceAttestationPolicy{}, false, nil
	}
	policy, enabled, err := s.deviceAttestationPolicy.DeviceAttestationPolicy(ctx, s.stateTenantID, identifier)
	if err != nil {
		return DeviceAttestationPolicy{}, false, fmt.Errorf("acme: device attestation policy lookup for %q: %w", identifier, err)
	}
	if !enabled {
		return DeviceAttestationPolicy{}, false, nil
	}
	if len(policy.TrustedRootsPEM) == 0 || len(policy.AllowedAlgorithms) == 0 ||
		policy.MaxAge <= 0 || policy.MaxAge > 24*time.Hour {
		return DeviceAttestationPolicy{}, false, errors.New("acme: device attestation policy is incomplete")
	}
	return policy, true, nil
}
