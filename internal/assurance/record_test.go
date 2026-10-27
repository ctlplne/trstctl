// SPDX-License-Identifier: BUSL-1.1

package assurance_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/store"
)

var (
	t0       = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	identity = "11111111-1111-4111-8111-111111111111"
)

// renewedVerified is a certificate a renewal issued, a relay saw served, and a
// discovery scan found: every stage but revocation has evidence.
func renewedVerified() assurance.Inputs {
	notBefore, notAfter := t0, t0.Add(30*24*time.Hour)
	anchor := t0.Add(time.Minute)
	owner := "22222222-2222-4222-8222-222222222222"
	predecessorEnd := t0.Add(10 * 24 * time.Hour)
	completed := t0.Add(2 * time.Hour)
	signedAt := t0.Add(90 * time.Minute)
	return assurance.Inputs{
		TenantID: "33333333-3333-4333-8333-333333333333", Now: t0.Add(24 * time.Hour),
		IdentityIDs: []string{identity},
		Evidence: store.CredentialEvidence{
			Certificate: store.Certificate{
				ID: "cert-new", Subject: "CN=checkout.example.test", SANs: []string{"checkout.example.test"},
				Issuer: "CN=trstctl Issuing CA", Serial: "0a", Fingerprint: "fp-new", NotBefore: &notBefore, NotAfter: &notAfter,
				Status: "active", Source: "issued", IssuanceIdempotencyKey: "renew:transition:k1", IssuanceEventID: "evt-issued",
				ValidityAnchor: &anchor, OwnerID: &owner, KeyOrigin: "host_agent",
			},
			Owner: &store.Owner{ID: owner, Name: "Checkout team", Kind: store.OwnerKind("team")},
			Discoveries: []store.DiscoveryObservation{{
				FindingID: "finding-1", SourceID: "src-1", SourceName: "edge scan", SourceKind: "network", RunID: "run-1",
				Kind: "certificate", Ref: "10.0.0.5:443", Provenance: "tls-handshake", DiscoveredAt: t0.Add(3 * time.Hour),
			}},
			Deliveries: []store.DeliveryEvidence{
				{Receipt: store.ConnectorDeliveryReceipt{ID: "rcpt-deploy", IdentityID: &identity, Destination: "connector.deploy",
					Connector: "apache", Target: "checkout-edge", Fingerprint: "fp-new", Status: "delivered", IdempotencyKey: "deploy-1",
					UpdatedAt: t0.Add(80 * time.Minute)}},
				{Receipt: store.ConnectorDeliveryReceipt{ID: "rcpt-verified", IdentityID: &identity, Destination: "connector.deploy",
					Connector: "apache", Target: "checkout-edge", Fingerprint: "fp-new", Status: "verified", IdempotencyKey: "deploy-1:verified",
					UpdatedAt: t0.Add(91 * time.Minute)}, SignedBy: "agent-checkout-host", SignerFingerprint: "sha256:agent", SignedObservedAt: &signedAt},
			},
			Endpoints: []store.EndpointVerification{{
				EndpointID: "checkout-edge:443", Address: "checkout.example.test:443", Vantage: "relay", Reached: true,
				ExpectedFingerprint: "fp-new", ObservedFingerprint: "fp-new", CheckedSANs: true, CheckedChain: true,
				EvidenceDigest: "sha256:transcript", AgentCommonName: "relay-dmz", LastCheckedAt: t0.Add(4 * time.Hour),
			}},
			Rotations: []store.RotationRun{{ID: "run-renew", IdentityID: identity, Status: "succeeded", Trigger: "scheduler",
				PredecessorFingerprint: "fp-old", SuccessorFingerprint: "fp-new", CreatedAt: t0, CompletedAt: &completed}},
			Predecessor: &store.CertificateLink{ID: "cert-old", Fingerprint: "fp-old", Status: "superseded", NotAfter: &predecessorEnd},
		},
		Issuance: assurance.IssuanceEvidence{EventID: "evt-renewing", Binding: &store.OperationApprovalIssuanceBinding{
			ProfileName: "web-internal", ProfileID: "profile-1", ProfileVersion: 3, ProfileSpecDigest: "sha256:spec",
			RequestedTTLSeconds: 2592000, EffectiveTTLSeconds: 2592000,
		}},
		Audit: []assurance.AuditReference{{Sequence: 42, EventID: "evt-issued", Type: "certificate.recorded", At: t0, Hash: "h42"}},
	}
}

// A179 done-when, first half: a renewed, verified certificate's record carries
// every stage with evidence IDs, and says which stages were independently
// observed.
func TestRecordCarriesEveryStageWithEvidenceIDs(t *testing.T) {
	r := assurance.Build(renewedVerified())
	if r.Format != assurance.Format || r.Credential.CertificateID != "cert-new" || !slices.Equal(r.Credential.IdentityIDs, []string{identity}) {
		t.Fatalf("credential = %+v", r.Credential)
	}
	if len(r.Discovery) != 1 || r.Discovery[0].EvidenceID != "discovery-finding:finding-1" || r.Discovery[0].Basis != assurance.BasisObserved {
		t.Fatalf("discovery = %+v", r.Discovery)
	}
	if r.Owner == nil || r.Owner.EvidenceID == "" || r.Owner.Name != "Checkout team" {
		t.Fatalf("owner = %+v", r.Owner)
	}
	i := r.Issuance
	if !i.IssuedByTrstctl || i.EvidenceID != "event:evt-issued" || i.Profile == nil || i.Profile.Name != "web-internal" ||
		i.Profile.Version != 3 || i.Profile.EvidenceID != "event:evt-renewing" || i.IssuedAt == nil || !i.IssuedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("issuance = %+v profile %+v", i, i.Profile)
	}
	if len(r.Deployments) != 1 || r.Deployments[0].EvidenceID != "connector-receipt:rcpt-deploy" || r.Deployments[0].Basis != assurance.BasisRecorded {
		t.Fatalf("deployments = %+v", r.Deployments)
	}
	if len(r.Verifications) != 2 {
		t.Fatalf("verifications = %+v", r.Verifications)
	}
	signed, endpoint := r.Verifications[0], r.Verifications[1]
	if signed.Basis != assurance.BasisSignedObservation || signed.Agent != "agent-checkout-host" || signed.ServedFingerprint != "fp-new" || signed.EvidenceID != "connector-receipt:rcpt-verified" {
		t.Fatalf("signed verification = %+v", signed)
	}
	if endpoint.Basis != assurance.BasisSignedObservation || endpoint.Vantage != "relay" || endpoint.ServedFingerprint != "fp-new" ||
		!endpoint.CheckedChain || endpoint.TranscriptDigest != "sha256:transcript" || endpoint.Outcome != "verified" {
		t.Fatalf("endpoint verification = %+v", endpoint)
	}
	if r.Renewals.Predecessor == nil || r.Renewals.Predecessor.CertificateID != "cert-old" || len(r.Renewals.Runs) != 1 ||
		r.Renewals.Runs[0].Role != "successor" || r.Renewals.Runs[0].EvidenceID != "rotation-run:run-renew" {
		t.Fatalf("renewals = %+v", r.Renewals)
	}
	if r.Revocation != nil || len(r.Audit) != 1 {
		t.Fatalf("revocation %+v audit %+v", r.Revocation, r.Audit)
	}
	if !slices.Equal(r.IndependentlyObserved, []string{"discovery", "deployment", "verification"}) ||
		!slices.Equal(r.RecordedOnly, []string{"owner", "issuance", "renewal"}) || !slices.Equal(r.Absent, []string{"revocation"}) {
		t.Fatalf("observed %v recorded %v absent %v", r.IndependentlyObserved, r.RecordedOnly, r.Absent)
	}
}

// A delivery nobody saw served is recorded, not observed.
func TestDeliveryWithoutServedEvidenceIsRecordedOnly(t *testing.T) {
	in := renewedVerified()
	in.Evidence.Deliveries = in.Evidence.Deliveries[:1]
	in.Evidence.Endpoints[0].ObservedFingerprint = "fp-other"
	in.Evidence.Endpoints[0].Mismatch = "fingerprint"
	in.Evidence.Discoveries = nil
	r := assurance.Build(in)
	if slices.Contains(r.IndependentlyObserved, "deployment") || slices.Contains(r.IndependentlyObserved, "verification") {
		t.Fatalf("a mismatching endpoint observed the deployment: %v", r.IndependentlyObserved)
	}
	if r.Verifications[0].Outcome != "mismatch" || !slices.Contains(r.Absent, "discovery") {
		t.Fatalf("verifications %+v absent %v", r.Verifications, r.Absent)
	}
}

func signer(t *testing.T, kid string) *jose.SigningKey {
	t.Helper()
	key, err := jose.GenerateRSASigningKey(kid)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pinned(t *testing.T, key *jose.SigningKey) *jose.JWKSet {
	t.Helper()
	doc, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	set, err := jose.ParseJWKSet(doc)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// A179 done-when, second half: the record verifies offline against pinned keys,
// and a tampered record fails.
func TestSignedRecordVerifiesOfflineAndTamperingFails(t *testing.T) {
	key := signer(t, "audit-export")
	record := assurance.Build(renewedVerified())
	signed, err := assurance.Sign(key, record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed.Rendering, "connector-receipt:rcpt-verified") || !strings.Contains(signed.Rendering, "## Verifications") {
		t.Fatalf("rendering lacks evidence IDs:\n%s", signed.Rendering)
	}
	document, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := assurance.Verify(document, pinned(t, key))
	if err != nil {
		t.Fatalf("a genuine record failed: %v", err)
	}
	if verified.Record.Credential.Fingerprint != "fp-new" || verified.KeyID != "audit-export" || verified.RecordSHA256 != signed.RecordSHA256 {
		t.Fatalf("verified = %+v", verified)
	}

	tamper := func(name string, edit func(map[string]any), want string) {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(document, &doc); err != nil {
			t.Fatal(err)
		}
		edit(doc)
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assurance.Verify(raw, pinned(t, key)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: verify = %v, want an error containing %q", name, err, want)
		}
	}
	tamper("record copy", func(doc map[string]any) {
		doc["record"].(map[string]any)["credential"].(map[string]any)["status"] = "revoked"
	}, "differs from the signed record")
	tamper("signature payload", func(doc map[string]any) {
		parts := strings.Split(doc["signed_record"].(string), ".")
		parts[1] = parts[1][:len(parts[1])-2] + "AA"
		doc["signed_record"] = strings.Join(parts, ".")
	}, "signature")
	tamper("digest", func(doc map[string]any) { doc["record_sha256"] = "sha256:00" }, "record_sha256")
	tamper("unsigned", func(doc map[string]any) { delete(doc, "signed_record") }, "no signed_record")

	if _, err := assurance.Verify(document, pinned(t, signer(t, "audit-export"))); err == nil {
		t.Fatal("a record verified under keys that did not sign it")
	}
	other, err := key.SignArtifact(jose.ArtifactCryptoReadiness, signed.Record)
	if err != nil {
		t.Fatal(err)
	}
	var doc assurance.Signed
	if err := json.Unmarshal(document, &doc); err != nil {
		t.Fatal(err)
	}
	doc.SignedRecord = other
	raw, _ := json.Marshal(doc)
	if _, err := assurance.Verify(raw, pinned(t, key)); err == nil {
		t.Fatal("a record signed under another artifact domain verified")
	}
}
