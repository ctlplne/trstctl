// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type edgeHandleTestBackend struct {
	mu         sync.Mutex
	name       string
	keys       map[string]*LockedSigner
	operations map[string]string
	next       int
}

func newEdgeHandleTestBackend(name string) *edgeHandleTestBackend {
	return &edgeHandleTestBackend{name: name, keys: make(map[string]*LockedSigner), operations: make(map[string]string)}
}

func (b *edgeHandleTestBackend) Name() string { return b.name }

func (b *edgeHandleTestBackend) GenerateManagedKey(ctx context.Context, algorithm Algorithm) (Signer, KeyRef, error) {
	return b.GenerateManagedKeyForOperation(ctx, fmt.Sprintf("unscoped-%d", time.Now().UnixNano()), algorithm)
}

func (b *edgeHandleTestBackend) GenerateManagedKeyForOperation(ctx context.Context, operationID string, algorithm Algorithm) (Signer, KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, KeyRef{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if id := b.operations[operationID]; id != "" {
		key := b.keys[id]
		return edgeHandleTestSigner{key}, KeyRef{ID: id, Algorithm: algorithm}, nil
	}
	key, err := GenerateLockedKey(algorithm)
	if err != nil {
		return nil, KeyRef{}, err
	}
	b.next++
	id := fmt.Sprintf("opaque-%d", b.next)
	b.keys[id] = key
	b.operations[operationID] = id
	return edgeHandleTestSigner{key}, KeyRef{ID: id, Algorithm: algorithm}, nil
}

func (b *edgeHandleTestBackend) RotateKey(ctx context.Context, ref KeyRef) (Signer, KeyRef, error) {
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

func (b *edgeHandleTestBackend) RotateKeyForOperation(ctx context.Context, operationID string, ref KeyRef) (Signer, KeyRef, error) {
	return b.GenerateManagedKeyForOperation(ctx, operationID, ref.Algorithm)
}

func (b *edgeHandleTestBackend) RevokeKey(context.Context, KeyRef) error  { return nil }
func (b *edgeHandleTestBackend) ZeroizeKey(context.Context, KeyRef) error { return nil }
func (b *edgeHandleTestBackend) RevokeKeyForOperation(context.Context, string, KeyRef) error {
	return nil
}
func (b *edgeHandleTestBackend) ZeroizeKeyForOperation(context.Context, string, KeyRef) error {
	return nil
}

func (b *edgeHandleTestBackend) SignManagedDigest(ctx context.Context, ref KeyRef, digest []byte, opts SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	key := b.keys[ref.ID]
	b.mu.Unlock()
	if key == nil {
		return nil, fmt.Errorf("test device: unknown handle %q", ref.ID)
	}
	return key.SignDigest(digest, opts)
}

func (b *edgeHandleTestBackend) destroy() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, key := range b.keys {
		key.Destroy()
	}
}

type edgeHandleTestSigner struct{ *LockedSigner }

func (s edgeHandleTestSigner) Sign(message []byte, opts SignOptions) ([]byte, error) {
	hash := opts.Hash
	if hash == "" {
		hash = SHA256
	}
	digest, err := Digest(hash, message)
	if err != nil {
		return nil, err
	}
	return s.SignDigest(digest, opts)
}

func edgeParent(t *testing.T) (IssuedHierarchyCA, *LockedSigner, PublicKey) {
	t.Helper()
	parentSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	childSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(childSigner.Destroy)
	parent, err := SelfSignedHierarchyCA(parentSigner, HierarchyCAProfile{
		CommonName: "Edge Parent", PermittedDNSDomains: []string{"corp.example"},
		MaxPathLen: 2, EKUs: []string{"serverAuth"}, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return parent, parentSigner, childSigner.Public()
}

// An unconstrained delegated CA is a second root on a host nobody can reach.
func TestMintingRefusesAnUnconstrainedEdgeCA(t *testing.T) {
	t.Parallel()
	parent, signer, pub := edgeParent(t)
	_, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a",
	})
	if err == nil {
		t.Fatal("a delegated edge CA was minted with NO name constraints.\n\n" +
			"That is not a delegation, it is a second root — on a box the platform cannot reach " +
			"to revoke.")
	}
	if !strings.Contains(err.Error(), "second root") {
		t.Errorf("the refusal does not explain what was nearly created: %v", err)
	}
	// A blank entry must not be treated as a constraint either.
	if _, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a", PermittedDNSDomains: []string{"  "},
	}); err == nil {
		t.Fatal("a blank permitted domain was accepted; it widens the constraint to everything")
	}
}

// A too-long TTL is REFUSED, not clamped. Silently shortening leaves an
// operator planning renewals around a date that is wrong.
func TestATooLongEdgeCATTLIsRefusedNotClamped(t *testing.T) {
	t.Parallel()
	parent, signer, pub := edgeParent(t)
	_, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a", PermittedDNSDomains: []string{"seg-a.corp.example"},
		TTL: 365 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("a one-year delegated edge CA was minted.\n\n" +
			"The short life IS the bound that makes delegating a signing key defensible. Clamping " +
			"silently would be worse than refusing: the operator would plan renewals around a " +
			"date that is wrong.")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("the refusal does not name the ceiling: %v", err)
	}
}

// The minted certificate must actually carry the constraints and a path length
// of zero — an edge CA issues leaves and may never mint another CA.
func TestAMintedEdgeCACarriesItsConstraintsAndCannotDelegate(t *testing.T) {
	t.Parallel()
	parent, signer, pub := edgeParent(t)
	got, err := MintDelegatedEdgeCA(parent.CertificateDER, signer, pub, EdgeCARequest{
		CommonName: "segment-a", PermittedDNSDomains: []string{"seg-a.corp.example"},
		TTL: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(got.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.PermittedDNSDomains) == 0 {
		t.Fatal("the minted edge CA carries NO name constraints in the certificate itself.\n\n" +
			"A constraint that lives only in our records is not a constraint: the edge host " +
			"enforces what the certificate says, and nothing else.")
	}
	if !cert.MaxPathLenZero && cert.MaxPathLen != 0 {
		t.Fatalf("path length = %d; an edge CA that can mint another CA is an unbounded tree "+
			"rooted on an unreachable host", cert.MaxPathLen)
	}
	if d := time.Until(cert.NotAfter); d > maxEdgeCATTL+time.Hour {
		t.Fatalf("minted CA lives %v, past the %v ceiling", d, maxEdgeCATTL)
	}
}

// The default when a caller does not choose must be the SAFE answer.
func TestTheDefaultEdgeCALifetimeIsShort(t *testing.T) {
	t.Parallel()
	if defaultEdgeCATTL > maxEdgeCATTL {
		t.Fatal("the default exceeds the ceiling")
	}
	if defaultEdgeCATTL > 14*24*time.Hour {
		t.Fatalf("default = %v; an operator who did not think about lifetime must get the safe "+
			"answer, not the convenient one", defaultEdgeCATTL)
	}
	if defaultHierarchyCATTL <= maxEdgeCATTL {
		t.Fatal("the general CA default is within the edge ceiling, so this path would not need " +
			"its own bound — check that the edge path is still refusing the general default")
	}
}

// The edge host is restarted between CSR generation and issuance in real life.
// The only durable value the agent may need is an opaque device handle plus the
// PUBLIC key. If this test ever needs PKCS#8/PEM private bytes, the custody repair
// has regressed into the exact software-export path it is meant to remove.
func TestEdgeCAHandleCreatesCSRAndIssuesAfterRestartWithoutPrivateBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	device := newEdgeHandleTestBackend("tpm2")
	t.Cleanup(device.destroy)

	handle, csrDER, err := GenerateEdgeCAKeyHandleAndCSR(
		ctx, "tenant-a/segment-a/generation-1", "segment-a edge CA", ECDSAP256, device,
	)
	if err != nil {
		t.Fatalf("hardware CSR: %v", err)
	}
	if handle.Provider != "tpm2" || handle.KeyID == "" || len(handle.PublicKeyDER) == 0 {
		t.Fatalf("incomplete public handle: %+v", handle)
	}
	if err := VerifyCertificateRequest(csrDER); err != nil {
		t.Fatalf("CSR is not self-signed by the device key: %v", err)
	}

	parentSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := SelfSignedHierarchyCA(parentSigner, HierarchyCAProfile{
		CommonName: "edge parent", MaxPathLen: 1, TTL: 24 * time.Hour,
		PermittedDNSDomains: []string{"edge.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, csrDER, EdgeCARequest{
		CommonName: "segment-a edge CA", PermittedDNSDomains: []string{"edge.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("mint delegation: %v", err)
	}

	// A new wrapper models reopening the TPM/PKCS#11 session after the one-shot
	// CSR process exited. It shares only the DEVICE state, never private bytes.
	reopened := &edgeHandleTestBackend{name: "tpm2", keys: device.keys, operations: device.operations}
	leaf, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, reopened, EdgeLeafRequest{
		CommonName: "db.edge.example.test", TTL: 30 * time.Minute,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue through reopened hardware handle: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(mustParseCertificate(t, delegation.CertificateDER)); err != nil {
		t.Fatalf("leaf was not signed by the delegated device key: %v", err)
	}

	wrongProvider := &edgeHandleTestBackend{name: "pkcs11", keys: device.keys, operations: device.operations}
	if _, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, wrongProvider, EdgeLeafRequest{
		CommonName: "db.edge.example.test",
	}, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("provider-confused handle error = %v, want a closed refusal", err)
	}

	tampered := handle
	tampered.PublicKeyDER = append([]byte(nil), handle.PublicKeyDER...)
	tampered.PublicKeyDER[len(tampered.PublicKeyDER)-1] ^= 0xff
	if _, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, tampered, reopened, EdgeLeafRequest{
		CommonName: "db.edge.example.test",
	}, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("tampered public handle error = %v, want a closed refusal", err)
	}

	otherHandle, _, err := GenerateEdgeCAKeyHandleAndCSR(
		ctx, "tenant-a/segment-a/generation-2", "segment-a successor", ECDSAP256, device,
	)
	if err != nil {
		t.Fatal(err)
	}
	swapped := handle
	swapped.KeyID = otherHandle.KeyID
	if _, err := IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, swapped, reopened, EdgeLeafRequest{
		CommonName: "db.edge.example.test",
	}, time.Now().UTC()); err == nil || (!strings.Contains(err.Error(), "sign edge leaf") && !strings.Contains(err.Error(), "does not match")) {
		t.Fatalf("swapped device object error = %v, want a closed signature-binding refusal", err)
	}
}

func TestEdgeCAHandleConcurrentRetryReusesOneKeyAndSignsSafely(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	device := newEdgeHandleTestBackend("tpm2")
	t.Cleanup(device.destroy)
	const workers = 12
	type result struct {
		handle EdgeCAKeyHandle
		csr    []byte
		err    error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle, csr, err := GenerateEdgeCAKeyHandleAndCSR(
				ctx, "tenant-a/segment-a/concurrent-generation", "race edge CA", ECDSAP256, device,
			)
			results <- result{handle: handle, csr: csr, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var first EdgeCAKeyHandle
	for got := range results {
		if got.err != nil {
			t.Fatalf("concurrent retry: %v", got.err)
		}
		if err := VerifyCertificateRequest(got.csr); err != nil {
			t.Fatalf("concurrent CSR: %v", err)
		}
		if first.KeyID == "" {
			first = got.handle
		} else if got.handle.KeyID != first.KeyID || !strings.EqualFold(got.handle.Provider, first.Provider) {
			t.Fatalf("same durable operation created multiple handles: first=%+v got=%+v", first, got.handle)
		}
	}
	device.mu.Lock()
	keyCount := len(device.keys)
	device.mu.Unlock()
	if keyCount != 1 {
		t.Fatalf("concurrent retry created %d device keys, want exactly one", keyCount)
	}
}

func mustParseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
