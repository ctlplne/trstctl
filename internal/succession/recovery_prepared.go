// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

const recoverySuccessorDomain = "trstctl/pcas/recovery-successor/v1\x00"
const recoveryRecordDomain = "trstctl/pcas/recovery-record/v1\x00"
const recoveryProofDomain = "trstctl/pcas/recovery-proof/v1\x00"
const kemRewrapRecordDomain = "trstctl/pcas/kem-rewrap-record/v1\x00"

// KEMRewrapRecordEventID is the first-writer fence for one tenant identity's
// paired-signing/KEM successor at an epoch.
func KEMRewrapRecordEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return recoveryEventID(kemRewrapRecordDomain, bound)
}

// RecoveryProofEventID is the unique proof decision for one recovery record.
func RecoveryProofEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return recoveryEventID(recoveryProofDomain, bound)
}

// RecoveryRecordEventID fences a recovery record by its authenticated tenant,
// stable identity and epoch, independent of request ID. Competing approved
// requests cannot both become the source of the same succession epoch.
func RecoveryRecordEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return recoveryEventID(recoveryRecordDomain, bound)
}

// RecoverySuccessorEventID is a first-writer fence for one tenant identity's
// epoch. The event log's indexed ID lookup makes admission and crash retries
// bounded even when the tenant has a long history.
func RecoverySuccessorEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return recoveryEventID(recoverySuccessorDomain, bound)
}

// The first-writer event IDs use a domain-separated SHA-256 UUIDv8. Keeping
// this derivation here avoids pulling a general UUID package (and its SQL
// driver dependency) into the isolated signing process through succession.
func recoveryEventID(domain string, bound []byte) string {
	message := make([]byte, 0, len(domain)+len(bound))
	message = append(message, domain...)
	message = append(message, bound...)
	digest := crypto.SHA256Sum(message)
	digest[6] = (digest[6] & 0x0f) | 0x80 // UUID version 8
	digest[8] = (digest[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

// RecoverySuccessorSigningMessage includes every public field except the
// signature. Its explicit domain keeps a signature for this custody receipt
// from authorizing any other signer command.
func RecoverySuccessorSigningMessage(p RecoverySuccessorPreparedV1) ([]byte, error) {
	bound, err := json.Marshal(struct {
		TenantID        string `json:"tenant_id"`
		IdentityID      string `json:"identity_id"`
		Epoch           uint64 `json:"epoch"`
		Algorithm       string `json:"algorithm"`
		Handle          string `json:"handle"`
		PublicKeyDER    []byte `json:"public_key_der"`
		DeploymentScope string `json:"deployment_scope"`
		RequestID       string `json:"request_id"`
	}{p.TenantID, p.IdentityID, p.Epoch, p.Algorithm, p.Handle,
		p.PublicKeyDER, p.DeploymentScope, p.RequestID})
	if err != nil {
		return nil, err
	}
	return append([]byte(recoverySuccessorDomain), bound...), nil
}

// VerifyRecoverySuccessorPrepared proves that the signer holding the exact
// tenant-scoped key acknowledged this immutable public receipt.
func VerifyRecoverySuccessorPrepared(p RecoverySuccessorPreparedV1) error {
	if p.TenantID == "" || p.IdentityID == "" || p.Epoch == 0 ||
		p.Algorithm == "" || p.DeploymentScope == "" || p.RequestID == "" ||
		len(p.PublicKeyDER) == 0 || len(p.SignerSignature) == 0 {
		return errors.New("pcas recovery: incomplete prepared successor receipt")
	}
	if p.Handle != TenantKeyHandle(p.TenantID, p.IdentityID, p.Epoch) {
		return errors.New("pcas recovery: prepared successor handle is not tenant bound")
	}
	message, err := RecoverySuccessorSigningMessage(p)
	if err != nil {
		return err
	}
	if err := crypto.VerifyAlgorithmMessage(crypto.PublicKey{
		Algorithm: crypto.Algorithm(p.Algorithm), DER: p.PublicKeyDER,
	}, message, p.SignerSignature); err != nil {
		return fmt.Errorf("pcas recovery: prepared successor signature: %w", err)
	}
	return nil
}
