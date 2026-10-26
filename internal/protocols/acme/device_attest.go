// SPDX-License-Identifier: BUSL-1.1

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

// deviceAttestationBinding is the challenge a device-attest-01 attestation
// signs: SHA-256 of the canonical binding.
func deviceAttestationBinding(binding DeviceAttestationBinding) ([]byte, error) {
	canonical, err := deviceAttestationBindingJSON(binding)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(canonical), nil
}

// deviceAttestationBindingJSON is the canonical binding itself, retained as
// evidence so a reader can see what the attestation bound and recompute its
// challenge.
func deviceAttestationBindingJSON(binding DeviceAttestationBinding) ([]byte, error) {
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
	return canonical, nil
}

// deviceAttestationFormatTPM names the retained evidence's format: a WebAuthn
// credential carrying a TPM 2.0 attestation statement.
const deviceAttestationFormatTPM = "tpm-webauthn"

// deviceAttestationOutcome is a verified device-attest-01 response: the key it
// bound, and the evidence to retain when that key is device-bound.
type deviceAttestationOutcome struct {
	keyDigest []byte
	evidence  *acmeDeviceAttestationState
}

func (s *Server) validateDeviceAttestation(
	ctx context.Context,
	msg *jose.ACMEMessage,
	acct *account,
	ch *challenge,
	az *authorization,
	o *order,
) (deviceAttestationOutcome, error) {
	if msg == nil || acct == nil || ch == nil || az == nil || o == nil {
		return deviceAttestationOutcome{}, errors.New("device attestation state is incomplete")
	}
	if o.accountURL != acct.url {
		return deviceAttestationOutcome{}, errors.New("device attestation account does not own this order")
	}
	if ch.status != statusPending {
		return deviceAttestationOutcome{}, errors.New("device attestation challenge is not pending")
	}
	policy, enabled, err := s.lookupDeviceAttestationPolicy(ctx, az.domain)
	if err != nil {
		return deviceAttestationOutcome{}, err
	}
	if !enabled {
		return deviceAttestationOutcome{}, errors.New("device attestation is not enabled for this tenant, profile, and identifier")
	}

	var response DeviceAttestationResponse
	if err := json.Unmarshal(msg.Payload, &response); err != nil {
		return deviceAttestationOutcome{}, fmt.Errorf("decode device attestation response: %w", err)
	}
	if response.DeviceIdentifier != az.domain {
		return deviceAttestationOutcome{}, errors.New("device attestation identifier does not match the authorization")
	}
	now := s.deviceAttestNow()
	if response.IssuedAt.IsZero() || response.IssuedAt.After(now.Add(30*time.Second)) ||
		now.Sub(response.IssuedAt) > policy.MaxAge {
		return deviceAttestationOutcome{}, errors.New("device attestation is outside the allowed freshness window")
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(response.CSR)
	if err != nil {
		return deviceAttestationOutcome{}, fmt.Errorf("decode device attestation CSR: %w", err)
	}
	csrDigest, err := deviceattest.CSRPublicKeySHA256(csrDER)
	if err != nil {
		return deviceAttestationOutcome{}, err
	}
	binding, err := deviceAttestationBindingJSON(DeviceAttestationBinding{
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
		return deviceAttestationOutcome{}, err
	}
	result, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		response.Attestation,
		crypto.SHA256Sum(binding),
		policy.TrustedRootsPEM,
		policy.AllowedAlgorithms,
		now,
	)
	if err != nil {
		return deviceAttestationOutcome{}, err
	}
	if !bytes.Equal(result.PublicKeySHA256, csrDigest) {
		return deviceAttestationOutcome{}, errors.New("device attestation key does not match the bound CSR")
	}
	if o.attestedKeySHA256 != "" &&
		o.attestedKeySHA256 != base64.RawURLEncoding.EncodeToString(csrDigest) {
		return deviceAttestationOutcome{}, errors.New("device attestation key does not match the key already bound to this order")
	}
	outcome := deviceAttestationOutcome{keyDigest: csrDigest}
	// A valid attestation of a key the TPM could release still proves the
	// device; only a key it cannot release earns a device-bound custody claim.
	if result.DeviceBound {
		outcome.evidence = &acmeDeviceAttestationState{
			Format:                       deviceAttestationFormatTPM,
			Credential:                   append([]byte(nil), response.Attestation...),
			Binding:                      binding,
			PublicKeySHA256:              result.PublicKeySHA256,
			AttestationCertificateSHA256: result.AttestationCertificateSHA256,
			TrustedRootsSHA256:           crypto.SHA256Sum(bytes.Join(policy.TrustedRootsPEM, []byte("\n"))),
			VerifiedAt:                   now,
		}
	}
	return outcome, nil
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
