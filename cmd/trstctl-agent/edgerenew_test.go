// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

type recordingRenewalSender struct {
	mu       sync.Mutex
	requests []*transport.EdgeRenewalRequest
	resp     *transport.EdgeRenewalResponse
	err      error
}

func (s *recordingRenewalSender) RenewEdgeDelegation(_ context.Context, req *transport.EdgeRenewalRequest) (*transport.EdgeRenewalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	return s.resp, s.err
}

func (s *recordingRenewalSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// A220: the agent asks to renew only inside --edge-renew-before, with a CSR
// the delegated CA's TPM key signed and a credential over its challenge; it
// installs the renewed chain, and after a refusal it keeps the old one and
// waits an hour before asking again.
func TestEdgeRenewerRenewsInsideTheWindowWithAFreshAttestation(t *testing.T) {
	ctx := context.Background()
	identity, err := deviceattesttest.NewTPMIdentity(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	provider := identity.EdgeCAKeyProvider()
	handle, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(ctx, "renew-test", "renew edge CA", crypto.ECDSAP256, provider)
	if err != nil {
		t.Fatal(err)
	}
	parentKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentKey.Destroy)
	parent, err := crypto.SelfSignedHierarchyCA(parentKey, crypto.HierarchyCAProfile{CommonName: "renew parent", MaxPathLen: 1, TTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	delegate := func() []byte {
		t.Helper()
		issued, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentKey, csrDER, crypto.EdgeCARequest{
			CommonName: "renew edge CA", PermittedDNSDomains: []string{"edge.example.test"}, TTL: 2 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return append(issued.CertificatePEM, parent.CertificatePEM...)
	}
	current, renewedChain := delegate(), delegate()
	certPath := filepath.Join(t.TempDir(), "edge-ca.crt")
	if err := os.WriteFile(certPath, current, 0o600); err != nil {
		t.Fatal(err)
	}
	const tenant, segment = "tenant-a", "segment-a"
	clock := time.Now().UTC()
	renewer := &edgeRenewer{certPath: certPath, before: 24 * time.Hour, now: func() time.Time { return clock },
		prepare: func(ctx context.Context) ([]byte, []byte, error) {
			csr, err := crypto.EdgeCSRForKeyHandle(ctx, handle, provider, "renew edge CA")
			if err != nil {
				return nil, nil, err
			}
			credential, err := identity.CredentialJSON(crypto.EdgeAttestationChallenge(tenant, segment, csr))
			return csr, credential, err
		}}
	sender := &recordingRenewalSender{resp: &transport.EdgeRenewalResponse{DelegationID: "renewed", Serial: "01", CertificatePEM: string(renewedChain), NotAfter: clock.Add(48 * time.Hour)}}

	renewer.afterHeartbeat(ctx, sender)
	if sender.count() != 0 {
		t.Fatal("the agent asked to renew two days before expiry with a one-day window")
	}
	renewer.before = 7 * 24 * time.Hour
	sender.err = status.Error(codes.PermissionDenied, "attestation: the root is not pinned")
	renewer.afterHeartbeat(ctx, sender)
	if sender.count() != 1 {
		t.Fatalf("renewal requests = %d inside the window", sender.count())
	}
	if raw, _ := os.ReadFile(certPath); string(raw) != string(current) { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatal("a refused renewal replaced the delegation certificate")
	}
	renewer.afterHeartbeat(ctx, sender)
	if sender.count() != 1 {
		t.Fatal("a refused renewal was retried before the hour passed")
	}
	clock = clock.Add(61 * time.Minute)
	sender.err = nil
	renewer.afterHeartbeat(ctx, sender)
	if sender.count() != 2 {
		t.Fatalf("renewal requests = %d after the retry interval", sender.count())
	}
	req := sender.requests[1]
	facts, err := crypto.CertificateFactsFromPEM(current)
	if err != nil {
		t.Fatal(err)
	}
	if req.Serial != facts.SerialHex {
		t.Fatalf("renewal named serial %s; want the held delegation's %s", req.Serial, facts.SerialHex)
	}
	attestation, err := deviceattest.VerifyEdgeCAAttestation(req.AttestationCredentialJSON, tenant, segment, req.CSRDER,
		[][]byte{identity.RootPEM()}, "tpm2", clock)
	if err != nil {
		t.Fatalf("the renewal's attestation does not verify: %v", err)
	}
	if crypto.SHA256Hex(attestation.CSRKeySHA256) != crypto.SHA256Hex(mustCSRKey(t, csrDER)) {
		t.Fatal("the renewal CSR is not for the delegated CA's key")
	}
	if raw, _ := os.ReadFile(certPath); string(raw) != string(renewedChain) { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatal("the renewed chain was not installed")
	}
	var off *edgeRenewer
	off.afterHeartbeat(ctx, sender)
	if newEdgeRenewer(edgeCAOptions{caCert: certPath}, false, time.Hour) != nil {
		t.Fatal("--edge-renew off built a renewer")
	}
}

func mustCSRKey(t *testing.T, csrDER []byte) []byte {
	t.Helper()
	key, err := deviceattest.CSRPublicKeySHA256(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
