// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// FactoryAttestationSegment is what a factory device's key attestation binds
// beside its tenant and CSR (P12-L1): its batch and its name, so an
// attestation made for one device or batch vouches for no other, and an edge
// host's attestation (bound to a segment ID) is never a device's.
func FactoryAttestationSegment(batchID, deviceName string) string {
	return "factory/" + strings.ToLower(strings.TrimSpace(batchID)) + "/" + strings.ToLower(strings.TrimSpace(deviceName))
}

// VerifyFactoryDeviceAttestation checks a device's TPM attestation of its own
// key at birth (P12-L1): over the challenge binding the tenant, the device's
// factory segment and its CSR, against the batch's pinned roots; the attested
// key must be the CSR's and device-bound (fixedTPM, fixedParent,
// sensitiveDataOrigin). Given the birth certificate, the certificate must
// certify that same key. The station checks before it signs; the control
// plane checks again when it reconciles the journal.
func VerifyFactoryDeviceAttestation(credentialJSON []byte, tenantID, batchID, deviceName string, csrDER, certificateDER []byte,
	rootsPEM [][]byte, now time.Time) error {
	attested, err := VerifyEdgeCAAttestation(credentialJSON, tenantID, FactoryAttestationSegment(batchID, deviceName), csrDER, rootsPEM, "tpm2", now)
	if err != nil {
		return err
	}
	if certificateDER == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return &EdgeAttestationError{kind: ErrEdgeAttestationRefused, msg: fmt.Sprintf("birth certificate: %v", err)}
	}
	certified := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(certified[:], attested.CSRKeySHA256) != 1 {
		return &EdgeAttestationError{kind: ErrEdgeAttestationRefused, msg: "the birth certificate does not certify the attested key"}
	}
	return nil
}

// maxFactoryAttestationRoots bounds a batch's pinned roots (P12-L1).
const maxFactoryAttestationRoots = 16

// ParseFactoryAttestationRoots checks a batch's device attestation roots
// (P12-L1): at most 16, each one PEM CA certificate.
func ParseFactoryAttestationRoots(rootsPEM []string) error {
	if len(rootsPEM) > maxFactoryAttestationRoots {
		return fmt.Errorf("at most %d device attestation roots", maxFactoryAttestationRoots)
	}
	for i, raw := range rootsPEM {
		block, rest := pem.Decode([]byte(raw))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(block.Bytes) > maxDeviceAttestationBytes {
			return fmt.Errorf("device attestation root %d is not one PEM certificate", i)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("device attestation root %d: %w", i, err)
		}
		if !cert.IsCA {
			return fmt.Errorf("device attestation root %d is not a CA certificate", i)
		}
	}
	return nil
}
