// SPDX-License-Identifier: LicenseRef-trstctl-EE

package federation_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/federation"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	localDep   = "spiffe://deployment-a"
	foreignDep = "spiffe://deployment-b"
)

func foreignChain(t *testing.T, be crypto.KeyGenerator) succession.SampleChain {
	t.Helper()
	sc, err := succession.BuildSampleChain(be, foreignDep, foreignDep+"/id", "tenant-b")
	if err != nil {
		t.Fatalf("BuildSampleChain: %v", err)
	}
	return sc
}

// TestFederation_RecordByRecordVerify: a valid foreign chain imports (bridge
// produced) only after every record verifies; a tampered mid-chain record
// quarantines (PCAS-claim-34).
func TestFederation_RecordByRecordVerify(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	localAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	f := foreignChain(t, be)

	res, err := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, f.Records, 100)
	if err != nil {
		t.Fatalf("valid import: %v", err)
	}
	if res.Bridge == nil {
		t.Fatal("valid chain produced no bridge")
	}
	if err := federation.VerifyBridge(localAuth.Public().DER, nil, *res.Bridge, false); err != nil {
		t.Fatalf("bridge verify: %v", err)
	}

	bad := append([]succession.SuccessionRecord{}, f.Records...)
	tr := bad[0]
	tr.Possession.Signature = append([]byte{0x00}, tr.Possession.Signature...)
	bad[0] = tr
	res2, err := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, bad, 100)
	if !errors.Is(err, federation.ErrImportVerification) {
		t.Fatalf("tampered import: got %v, want ErrImportVerification", err)
	}
	if res2.Bridge != nil || res2.Quarantine == nil {
		t.Fatal("tampered import produced a bridge or no quarantine")
	}
}

// TestFederation_MonotoneMapping: the bridge epoch mapping is monotone, and a
// reordered/downgraded foreign chain cannot import (PCAS-claim-34 / INV-14).
func TestFederation_MonotoneMapping(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	localAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	f := foreignChain(t, be)
	res, _ := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, f.Records, 100)
	b := *res.Bridge
	for e := uint64(0); e < 5; e++ {
		if b.MapEpoch(e+1) <= b.MapEpoch(e) {
			t.Fatalf("epoch mapping not monotone at %d", e)
		}
	}
	rev := append([]succession.SuccessionRecord{}, f.Records...)
	rev[0], rev[1] = rev[1], rev[0]
	if _, err := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, rev, 100); !errors.Is(err, federation.ErrImportVerification) {
		t.Fatalf("reordered chain imported: %v", err)
	}
}

// TestFederation_NoAuthoritativeImport: only a bridge record is produced; the
// foreign records are not returned for local authoritative storage (PCAS-claim-34).
func TestFederation_NoAuthoritativeImport(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	localAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	f := foreignChain(t, be)
	res, _ := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, f.Records, 100)
	if res.Bridge == nil {
		t.Fatal("no bridge")
	}
	head := f.Records[len(f.Records)-1]
	hd, _ := succession.Commit(head.Fields)
	if string(res.Bridge.ForeignHeadDigest) != string(hd) {
		t.Fatal("bridge does not bind the verified foreign head digest")
	}
	if res.Bridge.ForeignDeployment != foreignDep || res.Bridge.LocalDeployment != localDep {
		t.Fatal("bridge does not bind both deployment ids")
	}
}

// TestFederation_MutualDualSignedBridge: the mutual bridge requires both
// authorities' signatures over the common commitment (PCAS-claim-43).
func TestFederation_MutualDualSignedBridge(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	localAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	foreignAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	f := foreignChain(t, be)
	res, _ := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, f.Records, 100)
	b := *res.Bridge

	if err := federation.VerifyBridge(localAuth.Public().DER, foreignAuth.Public().DER, b, true); err == nil {
		t.Fatal("mutual verify passed without a foreign countersignature")
	}
	mb, err := federation.Countersign(foreignAuth, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := federation.VerifyBridge(localAuth.Public().DER, foreignAuth.Public().DER, mb, true); err != nil {
		t.Fatalf("mutual verify: %v", err)
	}
	other, _ := be.GenerateKey(crypto.ECDSAP256)
	if err := federation.VerifyBridge(localAuth.Public().DER, other.Public().DER, mb, true); err == nil {
		t.Fatal("mutual verify passed with the wrong foreign key")
	}
}

// TestFederation_QuarantineOnFailedImport: a failed import emits a signed
// verification-failure event (PCAS-claim-44).
func TestFederation_QuarantineOnFailedImport(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	localAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	f := foreignChain(t, be)
	wrongRoot, _ := be.GenerateKey(crypto.ECDSAP256)
	res, err := federation.Import(localAuth, localDep, wrongRoot.Public().DER, f.Genesis, f.Records, 100)
	if !errors.Is(err, federation.ErrImportVerification) {
		t.Fatalf("got %v, want ErrImportVerification", err)
	}
	if res.Quarantine == nil {
		t.Fatal("no quarantine event")
	}
	if err := federation.VerifyQuarantine(localAuth.Public().DER, *res.Quarantine); err != nil {
		t.Fatalf("quarantine verify: %v", err)
	}
}

// TestFederation_LocalStateUnmodified: a failed import produces no bridge, so no
// local trust state is added (PCAS-claim-44). Import is side-effect-free.
func TestFederation_LocalStateUnmodified(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	localAuth, _ := be.GenerateKey(crypto.ECDSAP256)
	f := foreignChain(t, be)
	bad := append([]succession.SuccessionRecord{}, f.Records...)
	tr := bad[0]
	tr.PredecessorAtt = append([]byte{0x00}, tr.PredecessorAtt...)
	bad[0] = tr
	res, err := federation.Import(localAuth, localDep, f.TrustRootPubDER, f.Genesis, bad, 100)
	if !errors.Is(err, federation.ErrImportVerification) {
		t.Fatal("failed import not flagged")
	}
	if res.Bridge != nil {
		t.Fatal("failed import produced a bridge (local trust state would change)")
	}
}
