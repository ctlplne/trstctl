package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestSignCSROverUDS is the S1.4 acceptance test: the control plane launches the
// signer as its own process, then signs a CSR through it over a Unix domain
// socket, and the resulting CSR verifies.
func TestSignCSROverUDS(t *testing.T) {
	bin := buildSigner(t)

	// Keep the socket path short (UDS sun_path is limited to ~108 bytes).
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")

	ctx := context.Background()
	client, stop, err := signing.StartChild(ctx, bin, socket)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	defer stop()

	signer, err := client.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// The private key lives in the signer; CreateCertificateRequest signs the
	// CSR's TBS digest by calling the signer's Sign RPC over the UDS.
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "test.trstctl.com",
		DNSNames:   []string{"test.trstctl.com"},
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest over UDS: %v", err)
	}
	if err := crypto.VerifyCertificateRequest(csr); err != nil {
		t.Errorf("CSR signed over UDS is invalid: %v", err)
	}

	if err := signer.Destroy(ctx); err != nil {
		t.Errorf("Destroy: %v", err)
	}
}

// TestSignerBinaryRequiresContentAuthorizationForCASign proves SIGNER-001 at the
// shipped process boundary: the real trstctl-signer binary starts with a signer
// content-authorizer, a privileged CA handle is dual-control, and a raw CA_SIGN
// digest request without a token is denied even though the handle and purpose are
// otherwise valid.
func TestSignerBinaryRequiresContentAuthorizationForCASign(t *testing.T) {
	bin := buildSigner(t)
	dir, err := os.MkdirTemp("", "sa")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")
	authSecret := filepath.Join(dir, "sign-auth.bin")

	ctx := context.Background()
	client, stop, err := signing.StartChild(ctx, bin, socket, "--auth-secret", authSecret)
	if err != nil {
		t.Fatalf("StartChild with --auth-secret: %v", err)
	}
	defer stop()
	defer func() { _ = client.Close() }()

	authz, err := signing.LoadOrCreateAuthorizer(authSecret)
	if err != nil {
		t.Fatalf("LoadOrCreateAuthorizer: %v", err)
	}
	defer authz.Destroy()

	caSigner, err := client.GenerateDualControlKeyHandle(ctx, crypto.ECDSAP256, "issuing-ca",
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, authz)
	if err != nil {
		t.Fatalf("GenerateDualControlKeyHandle: %v", err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("approved certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caSigner.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("attested CA sign through real signer binary failed: %v", err)
	}

	forgeDigest, err := crypto.Digest(crypto.SHA256, []byte("attacker-chosen certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RawSignForTest(ctx, &signerpb.SignRequest{
		Handle:  &signerpb.KeyHandle{Id: "issuing-ca"},
		Digest:  forgeDigest,
		Hash:    signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("raw CA_SIGN without signer auth token = %v, want PermissionDenied", status.Code(err))
	}
}
