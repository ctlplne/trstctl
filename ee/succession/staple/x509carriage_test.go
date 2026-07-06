// SPDX-License-Identifier: LicenseRef-trstctl-EE

package staple_test

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/staple"
	"trstctl.com/trstctl/internal/crypto"
)

func stapleCA(t *testing.T) ([]byte, crypto.DigestSigner) {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl PCAS Staple CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return caDER, caKey
}

func stapleCSR(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "svc.example.com", DNSNames: []string{"svc.example.com"},
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestINT15_AttachmentCarriedInRealCertificate proves the succession attachment is
// carried in a REAL X.509 certificate extension and verified inline from the parsed
// certificate, and that a required-but-absent attachment on a real certificate fails
// (claim 32).
func TestINT15_AttachmentCarriedInRealCertificate(t *testing.T) {
	caDER, caKey := stapleCA(t)

	// A signed epoch checkpoint at epoch 5 is the attachment.
	cpKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := succession.SignEpochCheckpoint(cpKey, succession.SignedEpochCheckpoint{
		DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/app", TenantID: "t",
		Epoch: 5, Algorithm: crypto.ECDSAP384, PublicKeyDER: []byte{1, 2, 3}, IssuedAt: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	att := staple.Attachment{Checkpoint: &cp}

	// Issue a real leaf carrying the attachment; it verifies against the CA.
	certDER, err := staple.IssueStapledLeaf(caDER, caKey, stapleCSR(t), att, time.Hour)
	if err != nil {
		t.Fatalf("issue stapled leaf: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(certDER, caDER); err != nil {
		t.Fatalf("stapled leaf does not verify against CA: %v", err)
	}

	// The attachment round-trips out of the real, parsed certificate.
	got, found, err := staple.AttachmentFromCertificate(certDER)
	if err != nil || !found {
		t.Fatalf("extract attachment: found=%v err=%v", found, err)
	}
	if got.Checkpoint == nil || got.Checkpoint.Epoch != 5 {
		t.Fatalf("extracted attachment checkpoint = %+v, want epoch 5", got.Checkpoint)
	}

	// Inline verification from the real certificate accepts a newer epoch.
	res, err := staple.VerifyStapledCertificate(certDER, staple.Policy{
		ExpectedTenant: "t", RequireAttachment: true, LastAccepted: 4, CheckpointKeyDER: cpKey.Public().DER,
	})
	if err != nil {
		t.Fatalf("verify stapled certificate: %v", err)
	}
	if res.Epoch != 5 {
		t.Fatalf("posture epoch = %d, want 5", res.Epoch)
	}

	// Absence-as-failure: a real leaf with NO attachment extension fails a
	// required-attachment policy (a presenter cannot strip the proof to downgrade).
	plain, err := crypto.SignLeafFromCSR(caDER, caKey, stapleCSR(t), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := staple.AttachmentFromCertificate(plain); found {
		t.Fatal("plain leaf reported an attachment")
	}
	if _, err := staple.VerifyStapledCertificate(plain, staple.Policy{RequireAttachment: true, CheckpointKeyDER: cpKey.Public().DER}); !errors.Is(err, staple.ErrAttachmentRequired) {
		t.Fatalf("absent attachment: got %v, want ErrAttachmentRequired", err)
	}
}
