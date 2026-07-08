// SPDX-License-Identifier: LicenseRef-trstctl-EE

package digest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	DigestVersionV1       = "xrec.digest/v1"
	ArtifactKindStateRoot = "state-digest"
)

var (
	ErrInvalidDigest  = errors.New("digest: invalid state digest")
	ErrUntrustedKey   = errors.New("digest: untrusted signing key")
	ErrSecretEvidence = errors.New("digest: secret material in evidence")
)

// Watermark binds the observation position and time into the digest body.
type Watermark struct {
	Position   string
	ObservedAt int64
}

// Body is the R-14 canonical signed state digest body.
type Body struct {
	Version        string
	SpecVersion    string
	AuthorityID    string
	TenantID       string
	MerkleRoot     []byte
	RecordCount    uint64
	HashAlg        string
	PostureSummary PostureSummary
	Watermark      Watermark
	GeneratedAt    int64
}

// BuildRequest describes one state digest generation.
type BuildRequest struct {
	Set         canon.Set
	AuthorityID string
	Rules       []Rule
	Watermark   Watermark
	GeneratedAt int64
}

// BuiltDigest is the unsigned digest body plus the Merkle tree it commits to.
type BuiltDigest struct {
	Body Body
	Tree *Tree
}

// SignedDigest is the body plus signer-side signature material.
type SignedDigest struct {
	Body         Body
	DigestHash   []byte
	KeyID        string
	Algorithm    crypto.Algorithm
	PublicKeyDER []byte
	Signature    []byte
}

// ArtifactSigningClient is satisfied by *signing.Client and by signer-side test
// doubles. It can request a signature, but it does not hold the key.
type ArtifactSigningClient interface {
	SignArtifact(context.Context, signing.ArtifactSignRequest) (signing.ArtifactSignature, error)
}

// Build constructs the unsigned state digest from a canonical set.
func Build(req BuildRequest) (BuiltDigest, error) {
	tree, err := BuildTreeFromSet(req.Set)
	if err != nil {
		return BuiltDigest{}, err
	}
	posture, err := SummarizePosture(req.Rules, req.Set.Records)
	if err != nil {
		return BuiltDigest{}, err
	}
	body := Body{
		Version:        DigestVersionV1,
		SpecVersion:    req.Set.SpecVersion,
		AuthorityID:    strings.TrimSpace(req.AuthorityID),
		TenantID:       req.Set.TenantID,
		MerkleRoot:     append([]byte(nil), tree.Root...),
		RecordCount:    uint64(len(req.Set.Records)),
		HashAlg:        HashAlgSHA256,
		PostureSummary: posture,
		Watermark:      Watermark{Position: strings.TrimSpace(req.Watermark.Position), ObservedAt: req.Watermark.ObservedAt},
		GeneratedAt:    req.GeneratedAt,
	}
	if _, err := body.CanonicalBytes(); err != nil {
		return BuiltDigest{}, err
	}
	return BuiltDigest{Body: body, Tree: tree}, nil
}

// CanonicalBytes returns the deterministic bytes signed by the isolated signer.
func (b Body) CanonicalBytes() ([]byte, error) {
	b = b.withDefaults()
	if err := b.validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('{')
	writeJSONPair(&out, "authority_id", func() { writeJSONString(&out, b.AuthorityID) }, true)
	writeJSONPair(&out, "generated_at", func() { writeJSONInt(&out, b.GeneratedAt) }, false)
	writeJSONPair(&out, "hash_alg", func() { writeJSONString(&out, b.HashAlg) }, false)
	writeJSONPair(&out, "merkle_root", func() { writeJSONString(&out, hex.EncodeToString(b.MerkleRoot)) }, false)
	writeJSONPair(&out, "posture_summary", func() { writePostureJSON(&out, b.PostureSummary) }, false)
	writeJSONPair(&out, "record_count", func() { writeJSONUint(&out, b.RecordCount) }, false)
	writeJSONPair(&out, "spec_version", func() { writeJSONString(&out, b.SpecVersion) }, false)
	writeJSONPair(&out, "tenant_id", func() { writeJSONString(&out, b.TenantID) }, false)
	writeJSONPair(&out, "version", func() { writeJSONString(&out, b.Version) }, false)
	writeJSONPair(&out, "watermark", func() { writeWatermarkJSON(&out, b.Watermark) }, false)
	out.WriteByte('}')
	bytes := out.Bytes()
	if containsSecretEvidence(bytes) {
		return nil, ErrSecretEvidence
	}
	return bytes, nil
}

// DigestHash returns SHA-256 over the canonical digest body.
func (b Body) DigestHash() ([]byte, error) {
	body, err := b.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(body), nil
}

// Sign asks the isolated signer to sign the canonical digest body.
func Sign(ctx context.Context, client ArtifactSigningClient, body Body, keyID string) (SignedDigest, error) {
	if client == nil {
		return SignedDigest{}, ErrInvalidDigest
	}
	bodyBytes, err := body.CanonicalBytes()
	if err != nil {
		return SignedDigest{}, err
	}
	hash := crypto.SHA256Sum(bodyBytes)
	res, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        ArtifactKindStateRoot,
		TenantID:    body.withDefaults().TenantID,
		AuthorityID: body.withDefaults().AuthorityID,
		KeyID:       strings.TrimSpace(keyID),
		Payload:     bodyBytes,
	})
	if err != nil {
		return SignedDigest{}, err
	}
	return SignedDigest{
		Body:         body.withDefaults(),
		DigestHash:   hash,
		KeyID:        res.KeyID,
		Algorithm:    res.Algorithm,
		PublicKeyDER: append([]byte(nil), res.PublicKeyDER...),
		Signature:    append([]byte(nil), res.Signature...),
	}, nil
}

// Verify verifies the digest body, digest hash, trusted key, and signature. The
// trusted map is keyed by KeyID; an arbitrary embedded public key is not enough.
func (s SignedDigest) Verify(trusted map[string]crypto.PublicKey) error {
	if s.KeyID == "" || len(s.Signature) == 0 || len(s.PublicKeyDER) == 0 {
		return ErrInvalidDigest
	}
	bodyBytes, err := s.Body.CanonicalBytes()
	if err != nil {
		return err
	}
	hash := crypto.SHA256Sum(bodyBytes)
	if !bytes.Equal(hash, s.DigestHash) {
		return fmt.Errorf("%w: digest hash mismatch", ErrInvalidDigest)
	}
	pub, ok := trusted[s.KeyID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUntrustedKey, s.KeyID)
	}
	if pub.Algorithm != s.Algorithm || !bytes.Equal(pub.DER, s.PublicKeyDER) {
		return fmt.Errorf("%w: public key mismatch for %s", ErrUntrustedKey, s.KeyID)
	}
	if err := crypto.VerifyDigest(pub, hash, s.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDigest, err)
	}
	return nil
}

func (b Body) withDefaults() Body {
	if b.Version == "" {
		b.Version = DigestVersionV1
	}
	if b.HashAlg == "" {
		b.HashAlg = HashAlgSHA256
	}
	b.MerkleRoot = append([]byte(nil), b.MerkleRoot...)
	b.PostureSummary = b.PostureSummary.normalized()
	return b
}

func (b Body) validate() error {
	if b.Version != DigestVersionV1 || b.SpecVersion == "" || b.AuthorityID == "" || b.TenantID == "" {
		return ErrInvalidDigest
	}
	if len(b.MerkleRoot) != 32 || b.HashAlg != HashAlgSHA256 {
		return ErrInvalidDigest
	}
	if len(b.PostureSummary.PolicySetHash) != 32 || b.Watermark.Position == "" || b.Watermark.ObservedAt == 0 {
		return ErrInvalidDigest
	}
	if b.GeneratedAt == 0 {
		return ErrInvalidDigest
	}
	return nil
}

func writeJSONPair(b *bytes.Buffer, key string, writeValue func(), first bool) {
	if !first {
		b.WriteByte(',')
	}
	writeJSONString(b, key)
	b.WriteByte(':')
	writeValue()
}

func writePostureJSON(b *bytes.Buffer, s PostureSummary) {
	s = s.normalized()
	b.WriteByte('{')
	writeJSONPair(b, "per_rule", func() {
		b.WriteByte('[')
		for i, rule := range s.PerRule {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('{')
			writeJSONPair(b, "rule_id", func() { writeJSONString(b, rule.RuleID) }, true)
			writeJSONPair(b, "satisfying_count", func() { writeJSONUint(b, rule.SatisfyingCount) }, false)
			writeJSONPair(b, "violating_count", func() { writeJSONUint(b, rule.ViolatingCount) }, false)
			b.WriteByte('}')
		}
		b.WriteByte(']')
	}, true)
	writeJSONPair(b, "policy_set_hash", func() { writeJSONString(b, hex.EncodeToString(s.PolicySetHash)) }, false)
	b.WriteByte('}')
}

func writeWatermarkJSON(b *bytes.Buffer, w Watermark) {
	b.WriteByte('{')
	writeJSONPair(b, "observed_at", func() { writeJSONInt(b, w.ObservedAt) }, true)
	writeJSONPair(b, "position", func() { writeJSONString(b, w.Position) }, false)
	b.WriteByte('}')
}

func writeJSONString(b *bytes.Buffer, s string) {
	encoded, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	b.Write(encoded)
}

func writeJSONInt(b *bytes.Buffer, v int64) {
	b.WriteString(fmt.Sprintf("%d", v))
}

func writeJSONUint(b *bytes.Buffer, v uint64) {
	b.WriteString(fmt.Sprintf("%d", v))
}

func containsSecretEvidence(in []byte) bool {
	low := bytes.ToLower(in)
	markers := [][]byte{
		[]byte("-----begin private key-----"),
		[]byte("super-secret-password"),
		[]byte("secret-value-sentinel"),
		[]byte("password="),
		[]byte("token="),
		[]byte("api_key="),
	}
	for _, marker := range markers {
		if bytes.Contains(low, marker) {
			return true
		}
	}
	return false
}
