// SPDX-License-Identifier: LicenseRef-trstctl-EE

package issuer_test

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession/issuer"
	"trstctl.com/trstctl/internal/crypto"
)

type memEpochStore struct{ m map[string]uint64 }

func (s *memEpochStore) LastAccepted(id string) (uint64, bool, error) {
	e, ok := s.m[id]
	return e, ok, nil
}
func (s *memEpochStore) SetLastAccepted(id string, e uint64) error { s.m[id] = e; return nil }

func leafCSR(t *testing.T) []byte {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "svc.example.com", DNSNames: []string{"svc.example.com"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestINT14_RealLeafCarriesIssuerEpochExtension issues REAL end-entity certificates
// under an issuer-succession posture and proves the (issuer-epoch, rotation) tuple is
// carried as an X.509 extension a relying party parses and enforces: a leaf from a
// superseded issuer epoch is rejected (PCAS-claim-27).
func TestINT14_RealLeafCarriesIssuerEpochExtension(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl PCAS Issuer CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	const authority = "spiffe://d/ca"
	// Issue a leaf under the issuer's CURRENT posture (epoch 3).
	postureNow := issuer.IssuerPosture{IssuerID: authority, Epoch: 3, Algorithm: string(crypto.ECDSAP256), PublicDER: caKey.Public().DER}
	fresh, err := issuer.IssueLeafCertificate(caDER, caKey, leafCSR(t), postureNow, 1, time.Hour)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	// It is a real certificate that verifies against the CA.
	if err := crypto.VerifyLeafSignedByCA(fresh, caDER); err != nil {
		t.Fatalf("issued leaf does not verify against CA: %v", err)
	}
	// The tuple is carried in an X.509 extension and parses back.
	id, epoch, rot, err := issuer.ParseAuthorityEpoch(fresh)
	if err != nil {
		t.Fatalf("parse authority epoch: %v", err)
	}
	if id != authority || epoch != 3 || rot != 1 {
		t.Fatalf("parsed tuple = (%q,%d,%d), want (%q,3,1)", id, epoch, rot, authority)
	}

	// Relying party: the current-epoch leaf is accepted and advances the store.
	store := &memEpochStore{m: map[string]uint64{}}
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: epoch, RotationVersion: rot}, store); err != nil {
		t.Fatalf("fresh leaf rejected: %v", err)
	}

	// A leaf issued under a SUPERSEDED issuer epoch (2) is a real certificate too, but
	// the relying party rejects it once it has accepted epoch 3.
	postureStale := issuer.IssuerPosture{IssuerID: authority, Epoch: 2, Algorithm: string(crypto.ECDSAP256), PublicDER: caKey.Public().DER}
	stale, err := issuer.IssueLeafCertificate(caDER, caKey, leafCSR(t), postureStale, 1, time.Hour)
	if err != nil {
		t.Fatalf("issue stale leaf: %v", err)
	}
	_, staleEpoch, staleRot, err := issuer.ParseAuthorityEpoch(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := rpverify.AcceptLeafTuple(authority, rpverify.LeafTuple{IssuerEpoch: staleEpoch, RotationVersion: staleRot}, store); !errors.Is(err, rpverify.ErrStaleIssuerEpoch) {
		t.Fatalf("stale-authority leaf: got %v, want ErrStaleIssuerEpoch", err)
	}

	// A leaf with NO succession-authority extension is detectable, so a policy that
	// requires the extension can treat its absence as a failure.
	plain, err := crypto.SignLeafFromCSR(caDER, caKey, leafCSR(t), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := issuer.ParseAuthorityEpoch(plain); !errors.Is(err, issuer.ErrNoAuthorityEpoch) {
		t.Fatalf("plain leaf: got %v, want ErrNoAuthorityEpoch", err)
	}
}
