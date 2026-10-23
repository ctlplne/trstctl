// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// lyingSigner reports one public key and signs with another: the second
// reading of eMudhra's account, a certificate naming a key the HSM does not
// hold.
type lyingSigner struct {
	DigestSigner
	claimed PublicKey
}

func (l lyingSigner) Public() PublicKey { return l.claimed }

// replayingSigner answers every request with the first signature it made, the
// way a provider that kept an old proof would.
type replayingSigner struct {
	DigestSigner
	mu   sync.Mutex
	kept []byte
}

func (r *replayingSigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kept != nil {
		return r.kept, nil
	}
	sig, err := r.DigestSigner.SignDigest(digest, opts)
	r.kept = sig
	return sig, err
}

func smallScalarKey(t *testing.T, curve elliptic.Curve, k *big.Int) *ecdsa.PrivateKey {
	t.Helper()
	raw := make([]byte, (curve.Params().BitSize+7)/8)
	k.FillBytes(raw)
	key, err := ecdsa.ParseRawPrivateKey(curve, raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func lockedSignerOf(t *testing.T, alg Algorithm, key any) *LockedSigner {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := NewLockedSignerFromPKCS8(alg, der)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ls.Destroy)
	return ls
}

func generatedSigner(t *testing.T, alg Algorithm) *LockedSigner {
	t.Helper()
	ls, err := GenerateLockedKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ls.Destroy)
	return ls
}

// selfSignedCADER builds a self-signed CA certificate the way an air-gapped
// tool would, so the import and cross-sign paths can be shown keys trstctl
// itself refuses to certify.
func selfSignedCADER(t *testing.T, name string, pub any, priv stdcrypto.Signer) []byte {
	t.Helper()
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func fixtureCertDER(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	return block.Bytes
}

func wantErr(t *testing.T, what string, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("%s: err = %v, want one containing %q", what, err, contains)
	}
}

// eMudhra, Part 4: possession is a fresh challenge signed by the held key and
// verified against the exact public key going into the certificate.
func TestProvePossessionAcceptsTheHolderAndRefusesAnImpostor(t *testing.T) {
	for _, alg := range []Algorithm{ECDSAP256, ECDSAP384, ECDSAP521, RSA2048} {
		key := generatedSigner(t, alg)
		if err := ProvePossession(key, key.Public()); err != nil {
			t.Fatalf("%s holder: %v", alg, err)
		}
	}
	a, b := generatedSigner(t, ECDSAP384), generatedSigner(t, ECDSAP384)
	wantErr(t, "a certificate naming another key", ProvePossession(a, b.Public()), "does not hold the private key")
	wantErr(t, "a signer reporting another key", ProvePossession(lyingSigner{DigestSigner: a, claimed: b.Public()}, b.Public()), "does not hold the private key")

	// Every proof is a fresh challenge: a kept signature does not answer the next one.
	replay := &replayingSigner{DigestSigner: a}
	if err := ProvePossession(replay, a.Public()); err != nil {
		t.Fatalf("first proof: %v", err)
	}
	wantErr(t, "a replayed proof", ProvePossession(replay, a.Public()), "does not hold the private key")

	// Ed25519 has no digest-signing path: the caller records it as unproven.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := ProvePossession(a, PublicKey{Algorithm: Ed25519, DER: edDER}); !errors.Is(err, ErrPossessionUnsupported) {
		t.Fatalf("Ed25519: err = %v, want ErrPossessionUnsupported", err)
	}
}

func TestRefuseWeakKeyRefusesSmallScalarsAndPassesOrdinaryKeys(t *testing.T) {
	four := lockedSignerOf(t, ECDSAP384, smallScalarKey(t, elliptic.P384(), big.NewInt(4)))
	wantErr(t, "P-384 scalar 4", RefuseWeakKey(four.Public()), "its private key is 4")
	n := elliptic.P384().Params().N
	minusFour := lockedSignerOf(t, ECDSAP384, smallScalarKey(t, elliptic.P384(), new(big.Int).Sub(n, big.NewInt(4))))
	wantErr(t, "P-384 scalar n-4", RefuseWeakKey(minusFour.Public()), "its private key is n − 4")
	for _, alg := range []Algorithm{ECDSAP256, ECDSAP384, RSA2048} {
		if err := RefuseWeakKey(generatedSigner(t, alg).Public()); err != nil {
			t.Fatalf("an ordinary %s key was refused: %v", alg, err)
		}
	}
	// A post-quantum key has no classical structure to test; an unlabeled key
	// that does not parse is refused rather than waved through.
	if err := RefuseWeakKey(PublicKey{Algorithm: Algorithm("ML-DSA-65"), DER: []byte("raw ML-DSA key bytes")}); err != nil {
		t.Fatalf("ML-DSA: %v", err)
	}
	wantErr(t, "an unparseable unlabeled key", RefuseWeakKey(PublicKey{DER: []byte("not a key")}), "does not parse")
}

// Done-when: the ceremony refuses a mismatched or weak key.
func TestCeremonyRefusesWeakOrImpostorCAKeys(t *testing.T) {
	parent := generatedSigner(t, ECDSAP256)
	root, err := SelfSignedHierarchyCA(parent, HierarchyCAProfile{CommonName: "Ceremony Root", MaxPathLen: 2, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	profile := HierarchyCAProfile{CommonName: "Ceremony Intermediate", MaxPathLen: 0, TTL: 24 * time.Hour}

	// The weak key holds its own private key, so possession passes; it is
	// refused as weak, whether it arrives as a signer or a bare public key
	// (a SPIRE CSR, an edge device).
	weak := lockedSignerOf(t, ECDSAP384, smallScalarKey(t, elliptic.P384(), big.NewInt(4)))
	_, err = SignIntermediateHierarchyCAForSigner(root.CertificateDER, parent, weak, profile)
	wantErr(t, "a weak child signer", err, "refusing a weak key")
	_, err = SignIntermediateHierarchyCA(root.CertificateDER, parent, weak.Public(), profile)
	wantErr(t, "a weak child public key", err, "refusing a weak key")
	_, err = SelfSignedHierarchyCA(weak, HierarchyCAProfile{CommonName: "Weak Root", MaxPathLen: 1, TTL: 24 * time.Hour})
	wantErr(t, "a weak root", err, "refusing a weak key")

	// A child that reports another key never gets a certificate.
	honest, other := generatedSigner(t, ECDSAP256), generatedSigner(t, ECDSAP256)
	_, err = SignIntermediateHierarchyCAForSigner(root.CertificateDER, parent, lyingSigner{DigestSigner: honest, claimed: other.Public()}, profile)
	wantErr(t, "a mismatched child", err, "does not hold the private key")

	issued, err := SignIntermediateHierarchyCAForSigner(root.CertificateDER, parent, honest, profile)
	if err != nil {
		t.Fatalf("honest child: %v", err)
	}
	if err := VerifyCertificateSigner(issued.CertificateDER, honest.Public()); err != nil {
		t.Fatalf("issued intermediate does not name the child key: %v", err)
	}
}

// A CA certificate that is on the distrust list or carries a weak key is
// refused wherever the ceremony accepts one from outside: an offline root, an
// imported chain, a cross-sign target.
func TestCeremonyRefusesDistrustedAndWeakCACertificates(t *testing.T) {
	emsign := fixtureCertDER(t, "../keyposture/testdata/emsign-ecc-root-ca-g3.pem")
	_, err := VerifyImportedOfflineRoot(emsign, HierarchyCAProfile{CommonName: "emSign ECC Root CA - G3", MaxPathLen: -1, TTL: time.Hour})
	wantErr(t, "emSign ECC Root CA - G3 as an offline root", err, "is on the distrust list (emSign ECC Root CA - G3)")

	// Scalar 56 is EM EV TLS CA - G3C's own key: a root made with it anywhere
	// is caught by the distrust list's key match before the weak-key check.
	reused := smallScalarKey(t, elliptic.P384(), big.NewInt(56))
	_, err = VerifyImportedOfflineRoot(selfSignedCADER(t, "Reused Key Root", reused.Public(), reused), HierarchyCAProfile{CommonName: "Reused Key Root", MaxPathLen: 1, TTL: 30 * 24 * time.Hour})
	wantErr(t, "a root reusing an eMudhra key", err, "is on the distrust list (EM EV TLS CA - G3C)")

	weakKey := smallScalarKey(t, elliptic.P384(), big.NewInt(5))
	weakRoot := selfSignedCADER(t, "Weak Offline Root", weakKey.Public(), weakKey)
	_, err = VerifyImportedOfflineRoot(weakRoot, HierarchyCAProfile{CommonName: "Weak Offline Root", MaxPathLen: 1, TTL: 30 * 24 * time.Hour})
	wantErr(t, "a weak offline root", err, "its private key is 5,")

	weakPub := lockedSignerOf(t, ECDSAP384, weakKey).Public()
	_, _, err = VerifyImportedCAChain([][]byte{weakRoot}, weakPub, HierarchyCAProfile{CommonName: "Weak Offline Root", MaxPathLen: 1, TTL: 30 * 24 * time.Hour})
	wantErr(t, "a weak imported CA", err, "refusing the imported CA with a weak key")

	issuer := generatedSigner(t, ECDSAP256)
	root, err := SelfSignedHierarchyCA(issuer, HierarchyCAProfile{CommonName: "Cross Root", MaxPathLen: 2, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyImportedCAChain([][]byte{root.CertificateDER, emsign}, issuer.Public(), HierarchyCAProfile{CommonName: "Cross Root", MaxPathLen: 2, TTL: 48 * time.Hour})
	wantErr(t, "a chain through emSign", err, "imported CA chain certificate 1 is on the distrust list")

	_, err = CrossSignHierarchyCA(root.CertificateDER, issuer, weakRoot)
	wantErr(t, "a weak cross-sign target", err, "refusing the cross-sign target with a weak key")
	_, err = CrossSignHierarchyCA(root.CertificateDER, issuer, emsign)
	wantErr(t, "a distrusted cross-sign target", err, "the cross-sign target is on the distrust list")
	wantErr(t, "an imported cross-certificate over a weak target", VerifyCrossSignedCA(root.CertificateDER, weakRoot, weakRoot), "refusing the cross-sign target with a weak key")
}

// The offline root's half of the ceremony: a signature over the context and
// the ceremony id, made where the key lives, checked against the root.
func TestVerifyOfflinePossession(t *testing.T) {
	const ceremony = "7d6f5a8e-1c2b-4a3d-9e8f-0a1b2c3d4e5f"
	message := OfflinePossessionMessage(ceremony)
	if !strings.HasPrefix(string(message), "trstctl offline root proof of possession v1\x00") || !strings.HasSuffix(string(message), ceremony) {
		t.Fatalf("message = %q", message)
	}
	digest := sha256.Sum256(message)

	// ECDSA P-384, as `openssl dgst -sha256 -sign root.key` produces it.
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecRoot := selfSignedCADER(t, "Offline EC Root", ecKey.Public(), ecKey)
	ecSig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflinePossession(ecRoot, ceremony, ecSig); err != nil {
		t.Fatalf("ECDSA P-384: %v", err)
	}
	wantErr(t, "another ceremony's signature", VerifyOfflinePossession(ecRoot, "a-different-ceremony", ecSig), "does not verify")

	// RSA, PKCS #1 v1.5 over SHA-256.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048) // #nosec G403 -- a throwaway test root key
	if err != nil {
		t.Fatal(err)
	}
	rsaRoot := selfSignedCADER(t, "Offline RSA Root", rsaKey.Public(), rsaKey)
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, stdcrypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOfflinePossession(rsaRoot, ceremony, rsaSig); err != nil {
		t.Fatalf("RSA-2048: %v", err)
	}
	wantErr(t, "an EC signature against the RSA root", VerifyOfflinePossession(rsaRoot, ceremony, ecSig), "does not verify")

	// Ed25519 signs the message itself.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edRoot := selfSignedCADER(t, "Offline Ed25519 Root", edPub, edPriv)
	if err := VerifyOfflinePossession(edRoot, ceremony, ed25519.Sign(edPriv, message)); err != nil {
		t.Fatalf("Ed25519: %v", err)
	}

	wantErr(t, "no ceremony id", VerifyOfflinePossession(ecRoot, " ", ecSig), "needs the ceremony id")
	wantErr(t, "no signature", VerifyOfflinePossession(ecRoot, ceremony, nil), "is empty")
}
