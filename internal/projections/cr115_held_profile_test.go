// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// An upstream may approve a held request with an output certificate that
// differs from the CSR. The profile must still bind what trstctl records.
type cr115HeldCA struct{ returned ca.Certificate }

func (*cr115HeldCA) Name() string { return "cr115-held-upstream" }
func (*cr115HeldCA) Issue(context.Context, ca.IssueRequest) (ca.Certificate, error) {
	return ca.Certificate{}, &ca.HeldError{RequestID: 11501}
}
func (c *cr115HeldCA) RetrieveHeld(context.Context, int) (ca.Certificate, error) {
	return c.returned, nil
}

type cr115ImmediateCA struct{ returned ca.Certificate }

func (*cr115ImmediateCA) Name() string { return "cr115-immediate-upstream" }
func (c *cr115ImmediateCA) Issue(context.Context, ca.IssueRequest) (ca.Certificate, error) {
	return c.returned, nil
}

type cr115RecordingCA struct{ calls int }

func (*cr115RecordingCA) Name() string { return "cr115-recording-upstream" }
func (c *cr115RecordingCA) Issue(context.Context, ca.IssueRequest) (ca.Certificate, error) {
	c.calls++
	return ca.Certificate{}, errors.New("upstream was reached")
}

func cr115TLV(tag byte, value []byte) []byte {
	if len(value) >= 128 {
		panic("CR115 fixture needs long-form DER")
	}
	var length byte
	for range value {
		length++
	}
	return append([]byte{tag, length}, value...)
}

func TestCR115UnknownCSRSubjectAltNameCannotReachExternalCA(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "cr115-unknown-san"}); err != nil {
		t.Fatal(err)
	}
	storeProfile(t, s, tenantA, "web", profile.CertificateProfile{Name: "web", AllowedDNSSuffixes: []string{"allowed.example"},
		AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour)})
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	// Microsoft UPN otherName, which an AD CS supply-in-request template can
	// turn into a smart-card logon identity, beside an allowed DNS SAN.
	upnOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03}
	other := cr115TLV(0xa0, append(append([]byte(nil), upnOID...), cr115TLV(0xa0, cr115TLV(0x0c, []byte("administrator@corp.example")))...))
	san := cr115TLV(0x30, append(cr115TLV(0x82, []byte("app.allowed.example")), other...))
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "app.allowed.example",
		ExtraExtensions: []crypto.CertificateExtension{{OID: "2.5.29.17", Value: san}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &cr115RecordingCA{}
	svc := ca.NewIssuanceService(upstream, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)
	_, err = svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: csr, DNSNames: []string{"app.allowed.example"},
		TTL: time.Hour, ProfileName: "web", Protocol: "api"}, "cr115-unknown-san")
	if !errors.Is(err, ca.ErrExternalProfileRefused) || upstream.calls != 0 {
		t.Fatalf("UPN otherName reached external CA: calls=%d err=%v", upstream.calls, err)
	}
}

func TestCR115ImmediateExternalCAOutputMustMatchPinnedProfile(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "cr115-immediate"}); err != nil {
		t.Fatal(err)
	}
	storeProfile(t, s, tenantA, "web", profile.CertificateProfile{Name: "web", AllowedDNSSuffixes: []string{"allowed.example"},
		AllowedEKUs: []string{"serverAuth", "clientAuth"}, MaxValidity: profile.Duration(24 * time.Hour)})
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "CR115 immediate CA", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(csrKey.Destroy)
	cleanCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "app.allowed.example",
		DNSNames: []string{"app.allowed.example"}, RequestedEKUs: []string{"serverAuth"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "admin.victim.example",
		DNSNames: []string{"admin.victim.example"}, RequestedEKUs: []string{"clientAuth"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := crypto.SignLeafFromCSR(caDER, caKey, wrongCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(wrongDER)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &cr115ImmediateCA{returned: ca.Certificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER}),
		Serial:         info.SerialNumber, NotAfter: info.NotAfter, Issuer: "cr115-immediate-upstream",
	}}
	svc := ca.NewIssuanceService(upstream, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s)
	_, err = svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: cleanCSR, DNSNames: []string{"app.allowed.example"},
		TTL: time.Hour, ProfileName: "web", Protocol: "api"}, "cr115-immediate-key")
	if !errors.Is(err, ca.ErrExternalProfileRefused) {
		t.Fatalf("CA output outside the pinned web profile was accepted: %v", err)
	}
	// Both usages are allowed by the profile, but this caller asked only for
	// serverAuth. The upstream cannot add clientAuth to the same identity.
	tooBroadDER, err := crypto.SignLeafFromCSR(caDER, caKey, cleanCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tooBroadInfo, err := certinfo.Inspect(tooBroadDER)
	if err != nil {
		t.Fatal(err)
	}
	upstream.returned = ca.Certificate{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tooBroadDER}),
		Serial: tooBroadInfo.SerialNumber, NotAfter: tooBroadInfo.NotAfter, Issuer: upstream.Name()}
	_, err = svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: cleanCSR, DNSNames: []string{"app.allowed.example"},
		TTL: time.Hour, ProfileName: "web", Protocol: "api"}, "cr115-immediate-broad")
	if !errors.Is(err, ca.ErrExternalProfileRefused) {
		t.Fatalf("CA added clientAuth beyond this request's EKU: %v", err)
	}
	otherKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherKey.Destroy)
	otherCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "app.allowed.example",
		DNSNames: []string{"app.allowed.example"}, RequestedEKUs: []string{"serverAuth"}}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, otherCSR, time.Hour,
		crypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	otherInfo, err := certinfo.Inspect(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	upstream.returned = ca.Certificate{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}),
		Serial: otherInfo.SerialNumber, NotAfter: otherInfo.NotAfter, Issuer: upstream.Name()}
	_, err = svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: cleanCSR, DNSNames: []string{"app.allowed.example"},
		TTL: time.Hour, ProfileName: "web", Protocol: "api"}, "cr115-immediate-other-key")
	if !errors.Is(err, ca.ErrExternalProfileRefused) {
		t.Fatalf("CA returned a certificate for another CSR key: %v", err)
	}
	cleanDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, cleanCSR, time.Hour,
		crypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	cleanInfo, err := certinfo.Inspect(cleanDER)
	if err != nil {
		t.Fatal(err)
	}
	upstream.returned = ca.Certificate{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cleanDER}),
		Serial: cleanInfo.SerialNumber, NotAfter: cleanInfo.NotAfter, Issuer: upstream.Name()}
	if _, err := svc.Issue(ctx, ca.IssueRequest{TenantID: tenantA, CSR: cleanCSR, DNSNames: []string{"app.allowed.example"},
		TTL: time.Hour, ProfileName: "web", Protocol: "api"}, "cr115-immediate-good"); err != nil {
		t.Fatalf("the CA's compliant output was refused: %v", err)
	}
}

func TestCR115HeldExternalCAOutputMustMatchPinnedProfile(t *testing.T) {
	const authorityID = "a1000000-0000-4000-8000-000000000115"
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	registered, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("cr115-held-tenant")})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	storeProfile(t, s, tenantA, "web", profile.CertificateProfile{
		Name: "web", AllowedDNSSuffixes: []string{"allowed.example"}, AllowedEKUs: []string{"serverAuth"},
		MaxValidity: profile.Duration(24 * time.Hour),
	})
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "CR115 held CA", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cleanKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanKey.Destroy)
	cleanCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "app.allowed.example", DNSNames: []string{"app.allowed.example"}, RequestedEKUs: []string{"serverAuth"},
	}, cleanKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "admin.victim.example", DNSNames: []string{"admin.victim.example"}, RequestedEKUs: []string{"clientAuth"},
	}, cleanKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := crypto.SignLeafFromCSR(caDER, caKey, wrongCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wrongInfo, err := certinfo.Inspect(wrongDER)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &cr115HeldCA{returned: ca.Certificate{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER}),
		Serial: wrongInfo.SerialNumber, NotAfter: wrongInfo.NotAfter, Issuer: "cr115-held-upstream"}}
	svc := ca.NewIssuanceService(upstream, orchestrator.NewIdempotency(s), orchestrator.NewOutbox(s), s,
		ca.WithAuditLog(log), ca.WithOutboxIssueWorker(authorityID, nil))
	issueCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	_, _ = svc.Issue(issueCtx, ca.IssueRequest{TenantID: tenantA, CSR: cleanCSR, DNSNames: []string{"app.allowed.example"},
		TTL: time.Hour, ProfileName: "web", Protocol: "api", RequestBinding: "cr115-clean-bound-request"}, "cr115-held-key")
	pending, err := orchestrator.NewOutbox(s).Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	var msg orchestrator.Message
	for _, row := range pending {
		if row.Destination == ca.DestinationExternalCAIssue && row.IdempotencyKey == "cr115-held-key" {
			msg = orchestrator.Message{TenantID: tenantA, Destination: row.Destination, IdempotencyKey: row.IdempotencyKey, Payload: row.Payload}
		}
	}
	if len(msg.Payload) == 0 {
		t.Fatal("profiled held issuance was not durably queued")
	}
	if err := svc.DeliverExternalIssue(ctx, msg); err == nil {
		t.Fatal("upstream did not report its held request")
	}
	held, err := svc.HeldIssues(ctx, tenantA, 10)
	if err != nil || len(held) != 1 || held[0].CARequestID != 11501 {
		t.Fatalf("held request = %+v err=%v", held, err)
	}
	if !held[0].ProfileBindingKnown || held[0].ProfileName != "web" || held[0].ProfileVersion != 1 || held[0].ProfileDigest == "" ||
		held[0].SubjectSPKISHA256 == "" ||
		len(held[0].DNSNames) != 1 || held[0].DNSNames[0] != "app.allowed.example" {
		t.Fatalf("held request did not retain its authenticated profile and names: %+v", held[0])
	}
	resumed, err := svc.ResumeHeld(ctx, tenantA, 11501)
	if err == nil || !errors.Is(err, ca.ErrExternalProfileRefused) {
		t.Fatalf("CA output outside the pinned web profile was accepted: status=%s cert=%d bytes err=%v", resumed.Status, len(resumed.Certificate.CertificatePEM), err)
	}
	rows, err := s.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantA, "cr115-held-key")
	if err != nil || len(rows) != 0 {
		t.Fatalf("profile-violating certificate reached inventory: %d rows, %v", len(rows), err)
	}
	newProfile := storeProfile(t, s, tenantA, "web", profile.CertificateProfile{Name: "web",
		AllowedDNSSuffixes: []string{"new.allowed.example"}, AllowedEKUs: []string{"clientAuth"},
		MaxValidity: profile.Duration(24 * time.Hour)})
	if newProfile.Version != 2 {
		t.Fatalf("profile edit did not advance the active revision: v%d", newProfile.Version)
	}
	cleanDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, cleanCSR, time.Hour,
		crypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}})
	if err != nil {
		t.Fatal(err)
	}
	cleanInfo, err := certinfo.Inspect(cleanDER)
	if err != nil {
		t.Fatal(err)
	}
	upstream.returned = ca.Certificate{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cleanDER}),
		Serial: cleanInfo.SerialNumber, NotAfter: cleanInfo.NotAfter, Issuer: upstream.Name()}
	resumed, err = svc.ResumeHeld(ctx, tenantA, 11501)
	if err != nil || resumed.Status != store.ExternalCAHeldIssueIssued {
		t.Fatalf("the CA's compliant held output was refused: status=%s err=%v", resumed.Status, err)
	}
	rows, err = s.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantA, "cr115-held-key")
	if err != nil || len(rows) != 1 {
		t.Fatalf("compliant held certificate inventory = %d rows, %v", len(rows), err)
	}
	// A v1 held event has no durable profile provenance. After migration it
	// must remain resumable as a record, but cannot be issued to a caller.
	legacy, err := json.Marshal(map[string]any{"authority_id": authorityID, "ca_request_id": 11502,
		"issue_key": "cr115-legacy-key", "request_binding": "cr115-legacy-binding", "dns_names": []string{"app.allowed.example"}})
	if err != nil {
		t.Fatal(err)
	}
	legacyEvent, err := log.Append(ctx, events.Event{Type: projections.EventExternalCAIssueHeld,
		TenantID: tenantA, SchemaVersion: 1, Data: legacy})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, legacyEvent); err != nil {
		t.Fatal(err)
	}
	_, err = svc.ResumeHeld(ctx, tenantA, 11502)
	if !errors.Is(err, ca.ErrExternalProfileRefused) {
		t.Fatalf("legacy held request without profile provenance was resumed: %v", err)
	}
}
