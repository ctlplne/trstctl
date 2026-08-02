// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	attestorFloorDir = "agid-attestors"
	attestorSpentDir = "agid-attestor-spent"
)

// SignedAttestation is the portable, signer-verifiable attestation evidence carried in
// AttestationBody.Payload for the durable INT-WIRE path. It is signed by a provisioned
// attestor key whose public half lives in the signer's keystore floor, so the isolated
// signer can verify evidence without SQL, NATS, HTTP, or a cloud verifier.
type SignedAttestation struct {
	KeyID     string            `json:"key_id"`
	Method    string            `json:"method"`
	Subject   string            `json:"subject"`
	Claims    map[string]string `json:"claims,omitempty"`
	Evidence  []byte            `json:"evidence,omitempty"`
	Signature []byte            `json:"signature,omitempty"`
}

// SignAttestation signs a portable attestation payload with signer and returns the JSON
// body to put in AttestationBody.Payload. The private attestor key remains with the caller;
// the isolated signer only needs the public key provisioned by DurableAttestationTrustStore.
func SignAttestation(signer crypto.Signer, keyID, method, subject string, claims map[string]string, evidence []byte) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("delegation: attestation signer is required")
	}
	a := SignedAttestation{
		KeyID:    keyID,
		Method:   method,
		Subject:  subject,
		Claims:   cloneClaims(claims),
		Evidence: append([]byte(nil), evidence...),
	}
	body := a.signingBytes()
	sig, err := signer.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("delegation: sign attestation: %w", err)
	}
	a.Signature = sig
	return json.Marshal(a)
}

// DurableAttestationTrustStore is an AN-4-safe filesystem trust floor for attestation
// verifier public keys. It stores only public DER under the signer keystore directory.
type DurableAttestationTrustStore struct {
	dir string
}

// NewDurableAttestationTrustStore returns a trust floor rooted at floorDir.
func NewDurableAttestationTrustStore(floorDir string) *DurableAttestationTrustStore {
	return &DurableAttestationTrustStore{dir: floorDir}
}

// PutVerifier stores a public attestor key under keyID.
func (s *DurableAttestationTrustStore) PutVerifier(_ context.Context, keyID string, publicDER []byte) error {
	if s == nil || s.dir == "" {
		return fmt.Errorf("delegation: attestation trust store has no directory")
	}
	if keyID == "" {
		return fmt.Errorf("delegation: attestation verifier key id is required")
	}
	if len(publicDER) == 0 {
		return fmt.Errorf("delegation: attestation verifier public key is required")
	}
	dir := filepath.Join(s.dir, attestorFloorDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("delegation: create attestation trust floor: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyID+".der"), publicDER, 0o600); err != nil {
		return fmt.Errorf("delegation: write attestation verifier: %w", err)
	}
	return nil
}

// VerifyEvidence implements AttestationVerifier.
func (s *DurableAttestationTrustStore) VerifyEvidence(method string, payload []byte) (VerifiedAttestation, error) {
	if s == nil || s.dir == "" {
		return VerifiedAttestation{}, ErrAttestationInvalid
	}
	var att SignedAttestation
	if err := json.Unmarshal(payload, &att); err != nil {
		return VerifiedAttestation{}, fmt.Errorf("%w: malformed signed attestation", ErrAttestationInvalid)
	}
	if method != "" && att.Method != method {
		return VerifiedAttestation{}, fmt.Errorf("%w: method mismatch", ErrAttestationInvalid)
	}
	pub, err := os.ReadFile(filepath.Join(s.dir, attestorFloorDir, att.KeyID+".der"))
	if err != nil {
		return VerifiedAttestation{}, fmt.Errorf("%w: unknown attestation verifier", ErrAttestationInvalid)
	}
	if len(att.Signature) == 0 {
		return VerifiedAttestation{}, fmt.Errorf("%w: missing signature", ErrAttestationInvalid)
	}
	if err := crypto.VerifyMessage(pub, att.signingBytes(), att.Signature); err != nil {
		return VerifiedAttestation{}, fmt.Errorf("%w: bad signature", ErrAttestationInvalid)
	}
	if err := s.markSpent(crypto.SHA256Sum(att.signingBytes())); err != nil {
		return VerifiedAttestation{}, err
	}
	return VerifiedAttestation{
		Method:  att.Method,
		Subject: att.Subject,
		Claims:  cloneClaims(att.Claims),
	}, nil
}

func (s *DurableAttestationTrustStore) markSpent(evidenceDigest []byte) error {
	dir := filepath.Join(s.dir, attestorSpentDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("delegation: create spent-attestation floor: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("delegation: open spent-attestation floor: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(hex.EncodeToString(evidenceDigest)+".spent", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAttestationReplay
	}
	if err != nil {
		return fmt.Errorf("delegation: mark attestation spent: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte("spent\n")); err != nil {
		return fmt.Errorf("delegation: write spent-attestation marker: %w", err)
	}
	return nil
}

func (a SignedAttestation) signingBytes() []byte {
	var b bytes.Buffer
	b.WriteString("agid/agentid/signed-attestation/v1")
	writeField(&b, "key_id")
	writeStr(&b, a.KeyID)
	writeField(&b, "method")
	writeStr(&b, a.Method)
	writeField(&b, "subject")
	writeStr(&b, a.Subject)
	writeField(&b, "claims")
	keys := make([]string, 0, len(a.Claims))
	for k := range a.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeU64(&b, uint64(len(keys)))
	for _, k := range keys {
		writeStr(&b, k)
		writeStr(&b, a.Claims[k])
	}
	writeField(&b, "evidence")
	writeBytes(&b, a.Evidence)
	return b.Bytes()
}

func cloneClaims(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
