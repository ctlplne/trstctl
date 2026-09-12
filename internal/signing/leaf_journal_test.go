// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// This adapter reaches the actual persistent signer, including its constraints,
// private-operation counter, and sealed journal. It does not cache signatures.
type journalLeafTestSigner struct {
	server *Server
	public crypto.PublicKey
	op     string
}

func (s journalLeafTestSigner) Public() crypto.PublicKey    { return s.public }
func (s journalLeafTestSigner) Algorithm() crypto.Algorithm { return s.public.Algorithm }
func (s journalLeafTestSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	r, err := s.server.Sign(context.Background(), &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "leaf-journal-ca"}, Digest: digest,
		Hash: hashToProto(opts.Hash), RsaPadding: paddingToProto(opts.RSAPadding),
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN, OperationId: s.op,
	})
	if err != nil {
		return nil, err
	}
	return r.GetSignature(), nil
}

func TestPreparedLeafJournalPreservesCertificateAcrossRestart(t *testing.T) {
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	dir := t.TempDir()
	srv, err := NewPersistentServer(NewKeyStore(dir, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	key, err := srv.GenerateKey(t.Context(), &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: "leaf-journal-ca",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer := journalLeafTestSigner{server: srv, public: crypto.PublicKey{Algorithm: crypto.ECDSAP256, DER: key.GetPublicKey()}}
	ca, err := crypto.SelfSignedCACert(signer, "leaf journal CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "leaf.example.test", DNSNames: []string{"leaf.example.test"}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := crypto.NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	signer.op = "tenant-a:original-lifecycle-command"
	var operations atomic.Int32
	srv.signGate = func() { operations.Add(1) }
	profile := crypto.LeafProfile{ClampTTLToIssuer: true}
	first, err := crypto.SignLeafFromCSRWithPreparation(ca, signer, csr, 2*time.Hour, profile, prepared)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPersistentServer(NewKeyStore(dir, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	restarted.signGate = func() { operations.Add(1) }
	signer.server = restarted
	replay, err := crypto.SignLeafFromCSRWithPreparation(ca, signer, csr, 2*time.Hour, profile, prepared)
	if err != nil || !bytes.Equal(first.DER, replay.DER) || !first.ValidityAnchor.Equal(replay.ValidityAnchor) {
		t.Fatalf("restart changed retained certificate: %v", err)
	}
	if operations.Load() != 1 {
		t.Fatalf("private operations=%d, want one", operations.Load())
	}
	// A corrected maximum can shorten the encoded validity of an older
	// template. Its original signing operation must refuse the new bytes,
	// including after restart; it must never quietly mint a replacement.
	bounded := profile
	bounded.MaxValidity = time.Hour
	if leaf, err := crypto.SignLeafFromCSRWithPreparation(ca, signer, csr, 2*time.Hour, bounded, prepared); err == nil || !strings.Contains(err.Error(), "different signing tuple") || len(leaf.DER) != 0 {
		t.Fatalf("changed validity did not refuse the retained operation: %v", err)
	}
	if operations.Load() != 1 {
		t.Fatalf("changed validity repeated the private operation: %d", operations.Load())
	}
	changed := prepared
	changed.Serial = append([]byte(nil), prepared.Serial...)
	changed.Serial[len(changed.Serial)-1] ^= 1
	if leaf, err := crypto.SignLeafFromCSRWithPreparation(ca, signer, csr, 2*time.Hour, profile, changed); err == nil || len(leaf.DER) != 0 {
		t.Fatal("same operation accepted a different certificate serial")
	}
	profile.AllowedExtKeyUsage = []string{"serverAuth"}
	if leaf, err := crypto.SignLeafFromCSRWithPreparation(ca, signer, csr, 2*time.Hour, profile, prepared); err == nil || len(leaf.DER) != 0 {
		t.Fatal("same operation accepted a different certificate profile")
	}
	if operations.Load() != 1 {
		t.Fatalf("changed tuple reached private operation: %d", operations.Load())
	}
}
