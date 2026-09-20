// SPDX-License-Identifier: BUSL-1.1

package staple_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/staple"
)

const tenant = "tenant-1"

func chain(t *testing.T) succession.SampleChain {
	t.Helper()
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://d", "spiffe://d/id", tenant)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// TestStapling_InlineVerify: a carried record chain verifies inline; a tampered
// attachment fails (PCAS-claim-31).
func TestStapling_InlineVerify(t *testing.T) {
	sc := chain(t)
	att := staple.Attachment{Records: sc.Records}
	res, err := staple.VerifyStapled(&att, staple.Policy{
		ExpectedTenant: tenant, Genesis: &sc.Genesis, TrustRootPubDER: sc.TrustRootPubDER, RequireAttachment: true,
	})
	if err != nil {
		t.Fatalf("inline verify: %v", err)
	}
	if res.Epoch != 2 {
		t.Fatalf("current epoch = %d, want 2", res.Epoch)
	}

	bad := staple.Attachment{Records: append([]succession.SuccessionRecord{}, sc.Records...)}
	tr := bad.Records[0]
	tr.Possession.Signature = append([]byte{0x00}, tr.Possession.Signature...)
	bad.Records[0] = tr
	if _, err := staple.VerifyStapled(&bad, staple.Policy{ExpectedTenant: tenant, Genesis: &sc.Genesis, TrustRootPubDER: sc.TrustRootPubDER}); err == nil {
		t.Fatal("tampered attachment verified")
	}
}

// TestStapling_CheckpointOrRecordLimb: both a record chain and a signed checkpoint
// verify inline and yield a current epoch (PCAS-claim-31).
func TestStapling_CheckpointOrRecordLimb(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	sc, err := succession.BuildSampleChain(be, "spiffe://d", "spiffe://d/id", tenant)
	if err != nil {
		t.Fatal(err)
	}
	recRes, err := staple.VerifyStapled(&staple.Attachment{Records: sc.Records}, staple.Policy{
		ExpectedTenant: tenant, Genesis: &sc.Genesis, TrustRootPubDER: sc.TrustRootPubDER,
	})
	if err != nil {
		t.Fatalf("record limb: %v", err)
	}

	signer, _ := be.GenerateKey(crypto.ECDSAP256)
	cp := succession.SignedEpochCheckpoint{
		DeploymentScope: sc.Genesis.DeploymentScope, IdentityID: sc.Genesis.IdentityID, TenantID: tenant,
		Epoch: 5, Algorithm: crypto.ECDSAP256, PublicKeyDER: []byte{1}, IssuedAt: 1,
	}
	cp, _ = succession.SignEpochCheckpoint(signer, cp)
	cpRes, err := staple.VerifyStapled(&staple.Attachment{Checkpoint: &cp}, staple.Policy{
		ExpectedTenant: tenant, CheckpointKeyDER: signer.Public().DER,
	})
	if err != nil {
		t.Fatalf("checkpoint limb: %v", err)
	}
	if recRes.Epoch == 0 || cpRes.Epoch != 5 {
		t.Fatalf("limbs: record epoch %d, checkpoint epoch %d", recRes.Epoch, cpRes.Epoch)
	}
}

// TestStapling_TLSExtensionCarriage: the attachment round-trips through a TLS
// extension and verifies (PCAS-claim-32).
func TestStapling_TLSExtensionCarriage(t *testing.T) {
	sc := chain(t)
	ext, err := staple.Attachment{Records: sc.Records}.ToTLSExtension()
	if err != nil {
		t.Fatal(err)
	}
	if ext.Type != staple.TLSExtensionType {
		t.Fatal("wrong TLS extension type")
	}
	got, err := staple.FromTLSExtension(ext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staple.VerifyStapled(&got, staple.Policy{ExpectedTenant: tenant, Genesis: &sc.Genesis, TrustRootPubDER: sc.TrustRootPubDER}); err != nil {
		t.Fatalf("verify from TLS extension: %v", err)
	}
	if _, err := staple.FromTLSExtension(staple.TLSExtension{Type: 0x0000, Data: ext.Data}); !errors.Is(err, staple.ErrWrongExtension) {
		t.Fatal("a foreign TLS extension type was accepted")
	}
}

// TestStapling_CertExtensionCarriage: the attachment round-trips through an X.509
// certificate extension and verifies (PCAS-claim-32).
func TestStapling_CertExtensionCarriage(t *testing.T) {
	sc := chain(t)
	ext, err := staple.Attachment{Records: sc.Records}.ToCertExtension()
	if err != nil {
		t.Fatal(err)
	}
	if ext.OID != staple.CertExtensionOID {
		t.Fatal("wrong certificate extension OID")
	}
	got, err := staple.FromCertExtension(ext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staple.VerifyStapled(&got, staple.Policy{ExpectedTenant: tenant, Genesis: &sc.Genesis, TrustRootPubDER: sc.TrustRootPubDER}); err != nil {
		t.Fatalf("verify from cert extension: %v", err)
	}
	if _, err := staple.FromCertExtension(staple.CertExtension{OID: "1.2.3", Value: ext.Value}); !errors.Is(err, staple.ErrWrongExtension) {
		t.Fatal("a foreign certificate extension OID was accepted")
	}
}

// TestStapling_AbsenceIsFailure: when policy requires an attachment, its absence is
// a verification failure (PCAS-claim-32).
func TestStapling_AbsenceIsFailure(t *testing.T) {
	if _, err := staple.VerifyStapled(nil, staple.Policy{RequireAttachment: true}); !errors.Is(err, staple.ErrAttachmentRequired) {
		t.Fatalf("absent required attachment: got %v, want ErrAttachmentRequired", err)
	}
}
