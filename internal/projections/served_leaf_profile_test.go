package projections_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// derOf decodes the first PEM CERTIFICATE block to DER (the leaf is first in the
// chain PEM the served path returns).
func derOf(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("expected a PEM CERTIFICATE block")
	}
	return blk.Bytes
}

// servedLeafProfile is a representative operator-configured served-leaf profile:
// a CDP, an AIA OCSP responder, an AIA CA-issuers pointer, and a policy OID — the
// RFC 5280 / CA-Browser-Forum pointers a served leaf must carry (PKIGOV-001).
var servedLeafProfile = crypto.LeafProfile{
	CRLDistributionPoints: []string{"http://crl.trstctl.test/issuing-ca.crl"},
	OCSPServers:           []string{"http://ocsp.trstctl.test"},
	IssuingCertificateURL: []string{"http://pki.trstctl.test/issuing-ca.crt"},
	CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
}

// TestServedLeafCarriesRevocationPointersAndSKI is the PKIGOV-001 acceptance: a
// leaf minted by the *served* issuing path (Server.IssueLeaf — the exact function
// the outbox handler calls) carries a Subject Key Identifier, an Authority Key
// Identifier, the configured CRL distribution point, the AIA OCSP and CA-issuers
// URLs, and the certificatePolicies OID. Before the fix the served leaf set none
// of these (RFC 5280 / BR-non-conformant), so the SKI/CDP/AIA/policy assertions
// below fail on the pre-fix tree and pass after.
func TestServedLeafCarriesRevocationPointersAndSKI(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{
		Store: st, Log: log, Signer: prov, LeafProfile: servedLeafProfile,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A subscriber CSR, built through the crypto boundary (AN-3), driven through the
	// served signing path.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "payments.svc.test", DNSNames: []string{"payments.svc.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	leafPEM, err := asm.IssueLeaf(context.Background(), csrDER, 24*time.Hour)
	if err != nil {
		t.Fatalf("served IssueLeaf: %v", err)
	}
	info, err := certinfo.Inspect(leafPEM)
	if err != nil {
		t.Fatalf("inspect served leaf: %v", err)
	}

	// SKI: always present now (chain-building / RFC 5280 §4.2.1.2). 20 hex bytes for
	// the SHA-1 method-1 identifier.
	if info.SubjectKeyID == "" {
		t.Error("served leaf has no Subject Key Identifier (PKIGOV-001: SKI must be set)")
	}
	if len(info.SubjectKeyID) != 40 {
		t.Errorf("SubjectKeyID = %q, want 40 hex chars (SHA-1)", info.SubjectKeyID)
	}
	// AKI: present (filled from the issuing CA's SKI) so the leaf names its issuer.
	if info.AuthorityKeyID == "" {
		t.Error("served leaf has no Authority Key Identifier")
	}
	// CDP: relying parties can locate the CRL.
	if got := info.CRLDistributionPoints; len(got) != 1 || got[0] != servedLeafProfile.CRLDistributionPoints[0] {
		t.Errorf("CRLDistributionPoints = %v, want %v", got, servedLeafProfile.CRLDistributionPoints)
	}
	// AIA OCSP: relying parties can check status live.
	if got := info.OCSPServers; len(got) != 1 || got[0] != servedLeafProfile.OCSPServers[0] {
		t.Errorf("OCSPServers (AIA) = %v, want %v", got, servedLeafProfile.OCSPServers)
	}
	// AIA CA-issuers: chain building can fetch the parent.
	if got := info.IssuingCertificateURL; len(got) != 1 || got[0] != servedLeafProfile.IssuingCertificateURL[0] {
		t.Errorf("IssuingCertificateURL (AIA) = %v, want %v", got, servedLeafProfile.IssuingCertificateURL)
	}
	// certificatePolicies: the leaf is issued under a declared policy.
	if got := info.PolicyOIDs; len(got) != 1 || got[0] != servedLeafProfile.CertificatePolicyOIDs[0] {
		t.Errorf("PolicyOIDs = %v, want %v", got, servedLeafProfile.CertificatePolicyOIDs)
	}

	// And the leaf still verifies against the assembled CA (fail-closed unchanged).
	if err := crypto.VerifyLeafSignedByCA(derOf(t, leafPEM), derOf(t, asm.CACertPEM())); err != nil {
		t.Errorf("served leaf does not verify against the assembled CA: %v", err)
	}
}

// TestServedLeafAlwaysHasSKIWithoutConfiguredPointers proves the SKI half of the
// fix is unconditional: even with no CDP/AIA configured (zero LeafProfile), the
// served leaf still carries a Subject Key Identifier — so every deployment gains
// the chain-building fix regardless of whether it has configured revocation URLs.
func TestServedLeafAlwaysHasSKIWithoutConfiguredPointers(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "svc.test"}, key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := asm.IssueLeaf(context.Background(), csrDER, time.Hour)
	if err != nil {
		t.Fatalf("served IssueLeaf: %v", err)
	}
	info, err := certinfo.Inspect(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	if info.SubjectKeyID == "" {
		t.Error("served leaf must carry a Subject Key Identifier even with no configured CDP/AIA")
	}
}

// TestServedMintRejectsOutOfProfileRequest is the PKIGOV-002 acceptance: with a
// default profile bound on the served path, an out-of-profile served issuance is
// rejected before signing — no certificate lands in inventory — and an
// issuance.profile_evaluated deny event is emitted. A control with a permissive
// profile proves an in-profile mint still succeeds. Before the fix the served
// mint bypassed the profile model entirely, so the out-of-profile request would
// have minted a certificate.
func TestServedMintRejectsOutOfProfileRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}

	// --- Deny case: a profile that the served mint (30-day ECDSA leaf) violates. ---
	t.Run("out-of-profile is rejected with a deny event", func(t *testing.T) {
		st := newStore(t)
		log := openLog(t)
		prov, stop := startSignerChild(t)
		defer stop()

		// The served mint issues a 30-day leaf; a 1h validity ceiling makes it
		// out-of-profile and must reject.
		storeProfile(t, st, tenantA, "served-default", profile.CertificateProfile{
			Name: "served-default", AllowedKeyAlgorithms: []string{"ECDSA"}, MinECDSABits: 256,
			MaxValidity: profile.Duration(time.Hour), AllowedProtocols: []string{"api"},
		})

		asm, err := server.Build(context.Background(), server.Deps{
			Store: st, Log: log, Signer: prov,
			LeafProfile: servedLeafProfile, DefaultProfile: "served-default",
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		ts := httptest.NewServer(asm.Handler())
		defer ts.Close()

		id := issueIdentity(t, ts, st)

		// Run the outbox sweep. A handler (mint) failure is recorded on the outbox row
		// for retry rather than surfaced by Drain (by design), so we assert the
		// *effect*: nothing was minted and a deny decision was recorded.
		if err := asm.Drain(context.Background()); err != nil {
			t.Fatalf("Drain itself should not error (handler failure is recorded on the row): %v", err)
		}

		// No certificate was minted into inventory — the out-of-profile request was
		// rejected before signing (fail closed). A successful mint would have produced
		// exactly one row, so emptiness is the disconfirming signal.
		token := mintToken(t, st, "certs:read")
		if items := list(t, ts, token, "/api/v1/certificates"); len(items) != 0 {
			t.Fatalf("out-of-profile request minted %d certs; want 0 (fail closed)", len(items))
		}

		// A deny decision was recorded on the served path (issuance.profile_evaluated).
		if allow, deny := profileDecisions(t, log); deny < 1 {
			t.Errorf("served profile decisions: allow=%d deny=%d; want >=1 deny", allow, deny)
		}
		_ = id
	})

	// --- Allow case: a permissive profile lets the served mint through. ---
	t.Run("in-profile mint succeeds with an allow event", func(t *testing.T) {
		st := newStore(t)
		log := openLog(t)
		prov, stop := startSignerChild(t)
		defer stop()

		// Generous ceiling (1 year) + ECDSA allowed → the 30-day ECDSA leaf is in
		// profile.
		storeProfile(t, st, tenantA, "served-default", profile.CertificateProfile{
			Name: "served-default", AllowedKeyAlgorithms: []string{"ECDSA"}, MinECDSABits: 256,
			MaxValidity: profile.Duration(365 * 24 * time.Hour), AllowedProtocols: []string{"api"},
		})

		asm, err := server.Build(context.Background(), server.Deps{
			Store: st, Log: log, Signer: prov,
			LeafProfile: servedLeafProfile, DefaultProfile: "served-default",
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		ts := httptest.NewServer(asm.Handler())
		defer ts.Close()

		_ = issueIdentity(t, ts, st)
		if err := asm.Drain(context.Background()); err != nil {
			t.Fatalf("in-profile served mint should succeed: %v", err)
		}
		token := mintToken(t, st, "certs:read")
		if items := list(t, ts, token, "/api/v1/certificates"); len(items) != 1 {
			t.Fatalf("in-profile request minted %d certs; want 1", len(items))
		}
		if allow, _ := profileDecisions(t, log); allow < 1 {
			t.Errorf("expected an allow profile decision on the served path, got %d", allow)
		}
	})
}

// issueIdentity creates an owner+issuer+identity and transitions it to "issued",
// enqueuing the ca.issue outbox entry the served handler processes. It returns the
// identity id.
func issueIdentity(t *testing.T, ts *httptest.Server, st *store.Store) string {
	t.Helper()
	// certs:issue is the separate privileged-issue authority (RED-004) the issuance
	// transition requires; the profile check is what should gate the mint here, so the
	// token must clear the scope gate first.
	token := mintToken(t, st, "owners:write", "issuers:write", "identities:write", "identities:read", "certs:read", "certs:issue")
	ownerID := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"payments"}`)
	issuerID := created(t, ts, token, "/api/v1/issuers",
		`{"kind":"x509_ca","name":"Acme CA","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}`)
	id := created(t, ts, token, "/api/v1/identities",
		`{"kind":"x509_certificate","name":"payments.svc.test","owner_id":"`+ownerID+`","issuer_id":"`+issuerID+`"}`)
	if code, body := req(t, ts, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, `{"to":"issued"}`); code != http.StatusOK {
		t.Fatalf("transition to issued = %d: %s", code, body)
	}
	return id
}

// profileDecisions counts allow/deny issuance.profile_evaluated events in the log.
func profileDecisions(t *testing.T, log *events.Log) (allow, deny int) {
	t.Helper()
	if err := log.Replay(context.Background(), 0, func(ev events.Event) error {
		if ev.Type != "issuance.profile_evaluated" {
			return nil
		}
		var d struct {
			Decision string `json:"decision"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		switch d.Decision {
		case "allow":
			allow++
		case "deny":
			deny++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	return allow, deny
}
