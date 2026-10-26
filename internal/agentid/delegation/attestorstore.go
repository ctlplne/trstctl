// SPDX-License-Identifier: BUSL-1.1

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
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	// attestorFloorDir is the operator-provisioned floor: one public key per key
	// ID, trusted for every tenant and every method.
	attestorFloorDir = "agid-attestors"
	// attestorTenantFloorDir holds attestors a tenant registered through the
	// control plane, each bound to that tenant and one attestation method.
	attestorTenantFloorDir = "agid-tenant-attestors"
	attestorSpentDir       = "agid-attestor-spent"
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
// verifier public keys. It stores only public key material under the signer keystore
// directory: the operator-provisioned floor (one key per key ID, for every tenant) and
// the tenant floor the control plane provisions over the signer transport (A150), where
// each key is bound to one tenant and one attestation method by its first writer.
type DurableAttestationTrustStore struct {
	dir string
	mu  sync.Mutex
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
	if !safeAnchorSegment(keyID) {
		return fmt.Errorf("delegation: attestation verifier key id %q is empty or unsafe", keyID)
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

// VerifyEvidence implements AttestationVerifier against the operator-provisioned
// floor only. The signer gate calls VerifyTenantEvidence, which also consults the
// requesting tenant's own attestors.
func (s *DurableAttestationTrustStore) VerifyEvidence(method string, payload []byte) (VerifiedAttestation, error) {
	return s.verify("", method, payload)
}

// VerifyTenantEvidence implements TenantAttestationVerifier. An attestor the tenant
// registered under the evidence's key ID decides alone: its key verifies the signature,
// the evidence must be for the method it was registered for, and the evidence cannot
// claim a class above that method's. Without one, the operator-provisioned floor
// decides, as it always has. Another tenant's attestors are never consulted.
func (s *DurableAttestationTrustStore) VerifyTenantEvidence(tenantID, method string, payload []byte) (VerifiedAttestation, error) {
	return s.verify(tenantID, method, payload)
}

func (s *DurableAttestationTrustStore) verify(tenantID, method string, payload []byte) (VerifiedAttestation, error) {
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
	pub, boundMethod, err := s.lookupVerifier(tenantID, att.KeyID)
	if err != nil {
		return VerifiedAttestation{}, err
	}
	if boundMethod != "" {
		if att.Method != boundMethod {
			return VerifiedAttestation{}, fmt.Errorf("%w: attestor %s is registered for method %s, not %s", ErrAttestationInvalid, att.KeyID, boundMethod, att.Method)
		}
		if claimed, ok := methodClass[att.Claims["attestation_class"]]; ok && claimed > ClassOfMethod(boundMethod) {
			return VerifiedAttestation{}, fmt.Errorf("%w: attestor %s cannot vouch for class %s above its method %s", ErrAttestationInvalid, att.KeyID, claimed, boundMethod)
		}
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

// lookupVerifier resolves the public key for keyID: the tenant's own attestor when it
// registered one (with the method it is bound to), else the operator-provisioned floor
// (with no method binding). The key ID comes from the evidence, so it must be a single
// safe path segment before it names a file; the files are read through a directory
// handle so a swapped-in symlink cannot redirect the read (CWE-22, CWE-367).
func (s *DurableAttestationTrustStore) lookupVerifier(tenantID, keyID string) ([]byte, string, error) {
	if !safeAnchorSegment(keyID) {
		return nil, "", fmt.Errorf("%w: unknown attestation verifier", ErrAttestationInvalid)
	}
	if tenantID != "" {
		pemPath, methodPath, err := s.tenantPaths(tenantID, keyID)
		if err != nil {
			return nil, "", fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
		}
		pubPEM, pemErr := readUnderRoot(pemPath)
		rawMethod, methodErr := readUnderRoot(methodPath)
		switch {
		case pemErr == nil && methodErr == nil:
			pub, err := DecodeRootAnchorPEM(pubPEM)
			if err != nil {
				return nil, "", fmt.Errorf("%w: unreadable tenant attestor", ErrAttestationInvalid)
			}
			return pub, strings.TrimSpace(string(rawMethod)), nil
		case !errors.Is(pemErr, os.ErrNotExist) || !errors.Is(methodErr, os.ErrNotExist):
			// Half a binding (a crash between its two files, or a damaged floor)
			// refuses rather than falling back: the tenant chose this key ID.
			return nil, "", fmt.Errorf("%w: tenant attestor %s is incompletely provisioned", ErrAttestationInvalid, keyID)
		}
	}
	root, err := os.OpenRoot(filepath.Join(s.dir, attestorFloorDir))
	if err != nil {
		return nil, "", fmt.Errorf("%w: unknown attestation verifier", ErrAttestationInvalid)
	}
	defer func() { _ = root.Close() }()
	pub, err := root.ReadFile(keyID + ".der")
	if err != nil {
		return nil, "", fmt.Errorf("%w: unknown attestation verifier", ErrAttestationInvalid)
	}
	return pub, "", nil
}

// ProvisionAgentAttestor binds keyID, for tenantID, to publicDER and method: the
// signer half of the control plane's attestor registration. The first writer wins: an
// identical retry (including one that completes a binding interrupted between its two
// files) succeeds, and a different key or method for the same tenant and key ID is
// refused with signing.ErrAgentAttestorConflict.
func (s *DurableAttestationTrustStore) ProvisionAgentAttestor(_ context.Context, tenantID, keyID string, publicDER []byte, method string) error {
	if s == nil || s.dir == "" {
		return errors.New("delegation: attestation trust store has no directory")
	}
	pemPath, methodPath, err := s.tenantPaths(tenantID, keyID)
	if err != nil {
		return fmt.Errorf("%v: %w", err, signing.ErrAgentAttestorInvalid)
	}
	if ClassOfMethod(method) == ClassNone {
		return fmt.Errorf("delegation: unknown attestation method %q: %w", method, signing.ErrAgentAttestorInvalid)
	}
	if err := crypto.ValidatePublicKeyDER(publicDER); err != nil {
		return fmt.Errorf("delegation: attestor public key: %v: %w", err, signing.ErrAgentAttestorInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("delegation: create signer floor directory: %w", err)
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return fmt.Errorf("delegation: open signer floor directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	relPEM, err := filepath.Rel(s.dir, pemPath)
	if err != nil || !filepath.IsLocal(relPEM) {
		return errors.New("delegation: attestor public key path escaped signer floor")
	}
	relMethod, err := filepath.Rel(s.dir, methodPath)
	if err != nil || !filepath.IsLocal(relMethod) {
		return errors.New("delegation: attestor method path escaped signer floor")
	}
	if err := root.MkdirAll(filepath.Dir(relPEM), 0o700); err != nil {
		return fmt.Errorf("delegation: create tenant attestor directory: %w", err)
	}
	existingPEM, pemErr := root.ReadFile(relPEM)
	if pemErr != nil && !errors.Is(pemErr, os.ErrNotExist) {
		return fmt.Errorf("delegation: read first-writer attestor key: %w", pemErr)
	}
	if pemErr == nil {
		stored, err := DecodeRootAnchorPEM(existingPEM)
		if err != nil || !bytes.Equal(stored, publicDER) {
			return fmt.Errorf("delegation: attestor key ID is already bound to another key: %w", signing.ErrAgentAttestorConflict)
		}
	}
	existingMethod, methodErr := root.ReadFile(relMethod)
	if methodErr != nil && !errors.Is(methodErr, os.ErrNotExist) {
		return fmt.Errorf("delegation: read first-writer attestor method: %w", methodErr)
	}
	if methodErr == nil && strings.TrimSpace(string(existingMethod)) != method {
		return fmt.Errorf("delegation: attestor key ID is already bound to another method: %w", signing.ErrAgentAttestorConflict)
	}
	if errors.Is(pemErr, os.ErrNotExist) {
		if err := root.WriteFile(relPEM, EncodeRootAnchorPEM(publicDER), 0o600); err != nil {
			return fmt.Errorf("delegation: write attestor public key: %w", err)
		}
	}
	if errors.Is(methodErr, os.ErrNotExist) {
		if err := root.WriteFile(relMethod, []byte(method+"\n"), 0o600); err != nil {
			return fmt.Errorf("delegation: write attestor method: %w", err)
		}
	}
	return nil
}

// ReadAgentAttestor reads one tenant attestor binding back from the signer floor. A
// missing or half-written binding reports os.ErrNotExist, which the signer answers as
// NotFound, so the control plane lists it as unprovisioned.
func (s *DurableAttestationTrustStore) ReadAgentAttestor(_ context.Context, tenantID, keyID string) ([]byte, string, error) {
	if s == nil || s.dir == "" {
		return nil, "", errors.New("delegation: attestation trust store has no directory")
	}
	pemPath, methodPath, err := s.tenantPaths(tenantID, keyID)
	if err != nil {
		return nil, "", err
	}
	pubPEM, err := readUnderRoot(pemPath)
	if err != nil {
		return nil, "", err
	}
	publicDER, err := DecodeRootAnchorPEM(pubPEM)
	if err != nil {
		return nil, "", err
	}
	method, err := readUnderRoot(methodPath)
	if err != nil {
		return nil, "", err
	}
	return publicDER, strings.TrimSpace(string(method)), nil
}

func (s *DurableAttestationTrustStore) tenantPaths(tenantID, keyID string) (string, string, error) {
	if !safeAnchorSegment(tenantID) {
		return "", "", fmt.Errorf("delegation: unsafe tenant id %q for attestor path", tenantID)
	}
	if !safeAnchorSegment(keyID) {
		return "", "", fmt.Errorf("delegation: unsafe key id %q for attestor path", keyID)
	}
	base := filepath.Join(s.dir, attestorTenantFloorDir, tenantID, keyID)
	return base + ".pem", base + ".method", nil
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
