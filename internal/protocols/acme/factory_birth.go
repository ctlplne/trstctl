// SPDX-License-Identifier: BUSL-1.1

package acme

import (
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

// P12-L2: ACME as a factory device's first-boot path. A device born on a
// factory line (P12) answers device-attest-01 for its own name with its birth
// certificate and its birth key's signature over the challenge binding, and
// the order's certificate is recorded as the device's first boot, as its EST
// first boot would be. The factory decides whether the birth certificate may
// enroll; this package checks the signature and binds the order's key.

// FactoryBirthFormat is the device-attest-01 format of a birth certificate.
const FactoryBirthFormat = "trstctl-factory-birth"

// factoryBirthMaxAge bounds how old a birth certificate's answer may be.
const factoryBirthMaxAge = 5 * time.Minute

// FactoryBirthGrant is a birth certificate the factory lets enroll: its
// batch, serial and public key (PKIX DER).
type FactoryBirthGrant struct {
	BatchID      string `json:"batch_id"`
	Serial       string `json:"serial"`
	PublicKeyDER []byte `json:"public_key_der"`
}

// FactoryBirthAuthority is the factory behind first boot over ACME (P12-L2).
type FactoryBirthAuthority interface {
	// FactoryDevice reports whether identifier names a device a reconciled
	// birth certificate was issued for, so device-attest-01 is offered.
	FactoryDevice(ctx context.Context, tenantID, identifier string) (bool, error)
	// VerifyFactoryBirth checks that birthDER may enroll identifier on first
	// boot with a request whose CSR is csrSHA256.
	VerifyFactoryBirth(ctx context.Context, tenantID, identifier string, birthDER []byte, csrSHA256 string) (FactoryBirthGrant, error)
	// RecordFactoryFirstBoot records the operational certificate issued
	// against the grant.
	RecordFactoryFirstBoot(ctx context.Context, tenantID string, grant FactoryBirthGrant, csrSHA256 string, operationalPEM []byte) error
}

// WithFactoryBirthAuthority opts this ACME mount into first boot for factory
// devices (P12-L2). Nil keeps it off.
func (s *Server) WithFactoryBirthAuthority(a FactoryBirthAuthority) *Server {
	s.factoryBirth = a
	return s
}

func (s *Server) isFactoryDevice(ctx context.Context, identifier string) (bool, error) {
	if s.factoryBirth == nil {
		return false, nil
	}
	ok, err := s.factoryBirth.FactoryDevice(ctx, s.stateTenantID, identifier)
	if err != nil {
		return false, fmt.Errorf("acme: factory device lookup for %q: %w", identifier, err)
	}
	return ok, nil
}

// validateFactoryBirth checks a birth certificate's answer to device-attest-01:
// the factory lets the certificate enroll the authorization's identifier, and
// its key signed the binding of this account, order, challenge, identifier,
// the CSR's key and the time. The JWS nonce is left out of the binding: a
// stock client signs the answer before it fetches the nonce, and the account's
// JWS carries the replay protection.
func (s *Server) validateFactoryBirth(ctx context.Context, msg *jose.ACMEMessage, acct *account, ch *challenge, az *authorization, o *order) (deviceAttestationOutcome, error) {
	if s.factoryBirth == nil {
		return deviceAttestationOutcome{}, errors.New("factory first boot is not enabled on this ACME mount")
	}
	var response DeviceAttestationResponse
	if err := json.Unmarshal(msg.Payload, &response); err != nil {
		return deviceAttestationOutcome{}, fmt.Errorf("decode device attestation response: %w", err)
	}
	if response.DeviceIdentifier != az.domain {
		return deviceAttestationOutcome{}, errors.New("device attestation identifier does not match the authorization")
	}
	now := s.deviceAttestNow()
	if response.IssuedAt.IsZero() || response.IssuedAt.After(now.Add(30*time.Second)) || now.Sub(response.IssuedAt) > factoryBirthMaxAge {
		return deviceAttestationOutcome{}, errors.New("the birth certificate's answer is outside the allowed freshness window")
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(response.CSR)
	if err != nil {
		return deviceAttestationOutcome{}, fmt.Errorf("decode device attestation CSR: %w", err)
	}
	csrDigest, err := deviceattest.CSRPublicKeySHA256(csrDER)
	if err != nil {
		return deviceAttestationOutcome{}, err
	}
	birthDER, err := base64.RawURLEncoding.DecodeString(response.BirthCertificate)
	if err != nil || len(birthDER) == 0 {
		return deviceAttestationOutcome{}, errors.New("the birth certificate is not base64url DER")
	}
	signature, err := base64.RawURLEncoding.DecodeString(response.BirthSignature)
	if err != nil || len(signature) == 0 {
		return deviceAttestationOutcome{}, errors.New("the birth key's signature is not base64url")
	}
	grant, err := s.factoryBirth.VerifyFactoryBirth(ctx, s.stateTenantID, az.domain, birthDER, crypto.SHA256Hex(csrDER))
	if err != nil {
		return deviceAttestationOutcome{}, err
	}
	binding, err := FactoryBirthBinding(DeviceAttestationBinding{
		TenantID: s.stateTenantID, AccountURL: acct.url, OrderID: o.id, ChallengeID: ch.id, Token: ch.token,
		Identifier: az.domain, CSRKeySHA256: csrDigest, IssuedAt: response.IssuedAt,
	})
	if err != nil {
		return deviceAttestationOutcome{}, err
	}
	if err := crypto.VerifyMessage(grant.PublicKeyDER, binding, signature); err != nil {
		return deviceAttestationOutcome{}, errors.New("the birth key did not sign this challenge")
	}
	if o.attestedKeySHA256 != "" && o.attestedKeySHA256 != base64.RawURLEncoding.EncodeToString(csrDigest) {
		return deviceAttestationOutcome{}, errors.New("device attestation key does not match the key already bound to this order")
	}
	return deviceAttestationOutcome{keyDigest: csrDigest, factoryBirth: &grant}, nil
}

// FactoryBirthBinding is what a factory device's birth key signs to answer
// device-attest-01 (P12-L2): the canonical JSON of the format, the tenant,
// the account URL, the order and challenge IDs (the last path segment of the
// order and challenge URLs), the challenge token, the identifier, the CSR
// key's SHA-256 and the time. Unlike a TPM answer it binds no JWS nonce.
func FactoryBirthBinding(b DeviceAttestationBinding) ([]byte, error) {
	if b.TenantID == "" || b.AccountURL == "" || b.OrderID == "" || b.ChallengeID == "" || b.Token == "" ||
		b.Identifier == "" || len(b.CSRKeySHA256) != 32 || b.IssuedAt.IsZero() {
		return nil, errors.New("acme: incomplete factory birth binding")
	}
	return json.Marshal(struct {
		Version      int    `json:"version"`
		Format       string `json:"format"`
		TenantID     string `json:"tenant_id"`
		AccountURL   string `json:"account_url"`
		OrderID      string `json:"order_id"`
		ChallengeID  string `json:"challenge_id"`
		Token        string `json:"token"`
		Identifier   string `json:"identifier"`
		CSRKeySHA256 string `json:"csr_key_sha256"`
		IssuedAt     string `json:"issued_at"`
	}{
		Version: 1, Format: FactoryBirthFormat, TenantID: b.TenantID, AccountURL: b.AccountURL, OrderID: b.OrderID,
		ChallengeID: b.ChallengeID, Token: b.Token, Identifier: b.Identifier,
		CSRKeySHA256: base64.RawURLEncoding.EncodeToString(b.CSRKeySHA256), IssuedAt: b.IssuedAt.UTC().Format(time.RFC3339Nano),
	})
}

// recordFactoryFirstBoot records a finalized order's certificate as the
// device's first boot.
func (s *Server) recordFactoryFirstBoot(ctx context.Context, grant FactoryBirthGrant, csrDER, certificatePEM []byte) error {
	if s.factoryBirth == nil {
		return errors.New("factory first boot is not enabled on this ACME mount")
	}
	return s.factoryBirth.RecordFactoryFirstBoot(ctx, s.stateTenantID, grant, crypto.SHA256Hex(csrDER), certificatePEM)
}
