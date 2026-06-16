package signing_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/signing"
)

// freeLoopbackAddr reserves an ephemeral loopback port and returns its address,
// so parallel signer instances in these tests don't collide. (net here is in a
// _test file, not the package proper — AN-3 only constrains non-test code.)
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startMTLSSigner stands up an in-memory signing server on a real TCP socket over
// the cross-node mTLS channel (ServeServerMTLS) and returns its address.
func startMTLSSigner(t *testing.T, ctx context.Context, cfg mtls.SignerPeerConfig) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	go func() {
		_ = signing.ServeServerMTLS(ctx, addr, signing.NewServer(), cfg, signing.ServeOptions{})
	}()
	return addr
}

// TestSignOverMTLS_EndToEnd is the SIGNER-005 acceptance: the isolated signer is
// reached over a real, mutually-authenticated, mutually-pinned mTLS network
// connection (not the UDS), the control plane performs a real Sign over that
// connection, and the signature verifies. It also drives a full CSR over the
// wire, mirroring the UDS acceptance (TestSignCSROverUDS). Fails on the pre-fix
// tree, which had no mTLS transport at all (DialMTLS/ServeServerMTLS did not
// exist).
func TestSignOverMTLS_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	const serverName = "trstctl-signer.svc"
	mat, err := mtls.GenerateSignerPeerMaterial(dir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startMTLSSigner(t, ctx, mat.Signer)

	// The control plane dials over mTLS, presenting its pinned client cert and
	// pinning the signer's cert; it waits until the signer reports SERVING.
	client, err := signing.DialReadyMTLS(ctx, addr, mat.ControlPlane, serverName, 10*time.Second)
	if err != nil {
		t.Fatalf("DialReadyMTLS (correct mutual certs): %v", err)
	}
	defer func() { _ = client.Close() }()

	// (a) A real Sign over the network connection: generate a key in the signer,
	// sign a digest, and verify the signature against the public key the signer
	// returned. The private key never crossed the wire.
	signer, err := client.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey over mTLS: %v", err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("sign-this-over-mtls"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	sig, err := signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("SignDigest over mTLS: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature returned over mTLS")
	}
	if err := crypto.VerifyDigest(signer.Public(), digest, sig, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Errorf("signature produced over the mTLS connection does not verify: %v", err)
	}

	// Full CSR over the wire (parity with the UDS acceptance): the CSR's TBS digest
	// is signed by the remote signer over mTLS and the result is a valid CSR.
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "leaf.trstctl.com",
		DNSNames:   []string{"leaf.trstctl.com"},
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest over mTLS: %v", err)
	}
	if err := crypto.VerifyCertificateRequest(csr); err != nil {
		t.Errorf("CSR signed over mTLS is invalid: %v", err)
	}
	if err := signer.Destroy(ctx); err != nil {
		t.Errorf("Destroy over mTLS: %v", err)
	}
}

// TestSignOverMTLS_RejectsUntrustedPeer is the SIGNER-005 negative acceptance: a
// control-plane client that presents an UNTRUSTED certificate (issued by a
// different CA, not anchored by the signer's peer-CA and not matching the pin) is
// rejected at the mTLS handshake — it can never reach Sign. Fails-closed.
func TestSignOverMTLS_RejectsUntrustedPeer(t *testing.T) {
	const serverName = "trstctl-signer.svc"

	// The signer's provisioned material (it pins the legitimate control plane).
	signerDir := t.TempDir()
	good, err := mtls.GenerateSignerPeerMaterial(signerDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (signer): %v", err)
	}

	// A SEPARATE, attacker-controlled PKI: its own CA, its own client cert. It does
	// not chain to the signer's peer-CA and its key is not the pinned key.
	attackerDir := t.TempDir()
	attacker, err := mtls.GenerateSignerPeerMaterial(attackerDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (attacker): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startMTLSSigner(t, ctx, good.Signer)

	// Sanity: the legitimate client connects (so the listener is up and the only
	// difference in the negative case is the untrusted client material).
	legit, err := signing.DialReadyMTLS(ctx, addr, good.ControlPlane, serverName, 10*time.Second)
	if err != nil {
		t.Fatalf("legit client could not connect (listener not up?): %v", err)
	}
	_ = legit.Close()

	// The attacker presents its own (untrusted, unpinned) client cert but still
	// trusts/pins the real signer so the FAILURE is on the SERVER verifying the
	// CLIENT, isolating the server-side mutual-auth check. DialMTLS itself succeeds
	// (lazy connect); the RPC must fail because the handshake is rejected.
	attackerCfg := mtls.SignerPeerConfig{
		CertFile:   attacker.ControlPlane.CertFile, // untrusted client cert/key
		KeyFile:    attacker.ControlPlane.KeyFile,
		PeerCAFile: good.ControlPlane.PeerCAFile, // trust the real signer
		PeerPinHex: good.ControlPlane.PeerPinHex, // pin the real signer
	}
	rogue, err := signing.DialMTLS(addr, attackerCfg, serverName)
	if err != nil {
		t.Fatalf("DialMTLS (attacker) unexpectedly failed before handshake: %v", err)
	}
	defer func() { _ = rogue.Close() }()

	hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
	defer hcancel()
	_, err = rogue.GenerateKey(hctx, crypto.ECDSAP256)
	if err == nil {
		t.Fatal("an untrusted/unpinned client cert was ACCEPTED by the signer over mTLS — mutual auth not enforced")
	}
	if code := status.Code(err); code != codes.Unavailable && code != codes.DeadlineExceeded {
		t.Logf("untrusted peer rejected with gRPC code %v (err=%v)", code, err)
	}
	if healthy := rogue.Healthy(hctx); healthy {
		t.Fatal("untrusted client saw the signer as SERVING — the rejected handshake leaked through")
	}
}

// TestSignOverMTLS_RejectsCASignedButUnpinnedPeer proves the pin is load-bearing,
// not just CA membership: a client whose certificate is signed by the SAME CA the
// signer trusts, but whose KEY is not the pinned key, is still rejected. This is
// the "both-ways cert pinning" requirement — a stolen-but-reissued credential
// from the same CA cannot impersonate the control plane.
func TestSignOverMTLS_RejectsCASignedButUnpinnedPeer(t *testing.T) {
	const serverName = "trstctl-signer.svc"
	dir := t.TempDir()
	mat, err := mtls.GenerateSignerPeerMaterial(dir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial: %v", err)
	}

	// A SECOND control-plane cert from the SAME CA bundle but a different key — its
	// pin differs. We mint it by regenerating material that reuses nothing but is a
	// distinct keypair; to keep it anchored to the SAME CA, we instead corrupt only
	// the pin the signer expects so that the legit client's (CA-valid) cert no
	// longer matches the configured pin.
	//
	// Concretely: keep the signer trusting the real CA (CA check passes) but pin a
	// DIFFERENT key. The legit client presents a CA-valid cert whose key != the
	// pin, so the pin check must reject it even though the chain verifies.
	wrongPinDir := t.TempDir()
	other, err := mtls.GenerateSignerPeerMaterial(wrongPinDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (other key for pin): %v", err)
	}
	signerCfg := mtls.SignerPeerConfig{
		CertFile:   mat.Signer.CertFile,
		KeyFile:    mat.Signer.KeyFile,
		PeerCAFile: mat.Signer.PeerCAFile,   // still trust the real control-plane CA (chain passes)
		PeerPinHex: other.Signer.PeerPinHex, // but pin a DIFFERENT key
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startMTLSSigner(t, ctx, signerCfg)

	// The legit control plane (CA-valid cert) connects but its key does not match
	// the (deliberately mismatched) pin the signer expects, so the handshake is
	// refused.
	client, err := signing.DialMTLS(addr, mat.ControlPlane, serverName)
	if err != nil {
		t.Fatalf("DialMTLS: %v", err)
	}
	defer func() { _ = client.Close() }()
	hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
	defer hcancel()
	if client.Healthy(hctx) {
		t.Fatal("a CA-valid but UNPINNED client cert was accepted — pinning is not enforced server-side")
	}
}

// TestSignOverMTLS_RejectsUntrustedSigner proves the client side also pins: a
// control plane configured to expect signer A is dialed at a signer whose cert is
// signed by a different CA / has a different key, and the connection is refused
// (the client verifies+pins the server). This is the second direction of mutual
// pinning.
func TestSignOverMTLS_RejectsUntrustedSigner(t *testing.T) {
	const serverName = "trstctl-signer.svc"

	realDir := t.TempDir()
	real, err := mtls.GenerateSignerPeerMaterial(realDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (real): %v", err)
	}
	// A rogue signer with its OWN PKI listening on its own port.
	rogueDir := t.TempDir()
	rogue, err := mtls.GenerateSignerPeerMaterial(rogueDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (rogue): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rogueAddr := startMTLSSigner(t, ctx, rogue.Signer)

	// The control plane is configured to trust+pin the REAL signer, but is pointed
	// at the rogue signer's address. The server cert won't match the pin / won't
	// chain to the expected CA, so the client refuses.
	client, err := signing.DialMTLS(rogueAddr, real.ControlPlane, serverName)
	if err != nil {
		t.Fatalf("DialMTLS: %v", err)
	}
	defer func() { _ = client.Close() }()
	hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
	defer hcancel()
	if client.Healthy(hctx) {
		t.Fatal("the control plane talked to a signer it did not pin — server-cert pinning not enforced")
	}
}

// TestSignerMTLSConfigFailsClosed: incomplete mTLS material is rejected at
// credential construction, so the served binary never starts a half-configured
// (e.g. unpinned) signer channel.
func TestSignerMTLSConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	mat, err := mtls.GenerateSignerPeerMaterial(dir, "s", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bad := mat.Signer
	bad.PeerPinHex = "" // drop the pin
	if _, err := mtls.SignerServerCredentials(bad); err == nil {
		t.Error("SignerServerCredentials accepted a config with no peer pin (should fail closed)")
	} else if !strings.Contains(err.Error(), "peer-pin") {
		t.Errorf("error should name the missing peer-pin: %v", err)
	}
	if _, err := mtls.SignerClientCredentials(mat.ControlPlane, ""); err == nil {
		t.Error("SignerClientCredentials accepted an empty server name (should fail closed)")
	}
}
