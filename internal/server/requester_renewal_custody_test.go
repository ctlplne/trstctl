// SPDX-License-Identifier: MPL-2.0
package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Real PG/NATS/outbox with the existing local crypto signer fixture. This does
// not qualify an external connector, live scheduler or independent signer process.
func TestRequesterRenewalRetainsTransitionCSRThroughTwoRenewalsAndReplay(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "requester-renewal", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "requester.example.test", OwnerID: owner.ID, Attributes: []byte(`{"subject_csr_pem":"not the authorized transition CSR"}`)})
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateHostSubjectKey(ident.Name, []string{ident.Name})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.CSRDER})
	// The transition API stores the trimmed PEM envelope; its signed DER is unchanged.
	canonicalCSR := strings.TrimSpace(string(csr))
	nativeIssue := h.handler.issue
	seen := 0
	h.handler.issue = func(ctx context.Context, der []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		seen++
		if !bytes.Equal(der, key.CSRDER) {
			t.Error("renewal replaced the original requester CSR")
		}
		return nativeIssue(ctx, der, ttl, profile)
	}
	if err := h.orch.TransitionWithSubjectCSR(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "requester original", "requester-original-key", string(csr)); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	first := dispatcherCertificates(t, h)
	if len(first) != 1 {
		t.Fatalf("first leaves=%d", len(first))
	}
	original := first[0]
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatal(err)
	}
	// This fixture has no deployment connector. Use the production dispatcher's
	// CA scope and retain deployment intents as pending; never acknowledge a
	// deployment that did not happen merely to advance this custody regression.
	for index, key := range []string{"renew-requester-one", "renew-requester-two"} {
		if err := h.orch.TransitionWithIdempotency(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "manual custody regression", key); err != nil {
			t.Fatal(err)
		}
		pending := pendingOutboxByDestination(t, h, "ca.renew")
		message := orchestrator.Message{TenantID: h.tenant, Destination: pending.Destination, Payload: pending.Payload, IdempotencyKey: pending.IdempotencyKey}
		if n, err := h.outbox.DispatchScoped(ctx, h.handler, orchestrator.DestinationScope{IncludePrefixes: []string{"ca."}}); err != nil || n != 1 {
			t.Fatalf("CA dispatch processed %d rows, error %v", n, err)
		}
		if err := h.handler.Deliver(ctx, message); err != nil {
			t.Fatal(err)
		}
		// Each renewal adds exactly one successor deployment; initial deployment
		// remains pending too. Redelivery must not duplicate any of these intents.
		pendingDeploy, err := h.outbox.Pending(ctx, h.tenant)
		if err != nil || len(pendingDeploy) != index+2 {
			t.Fatalf("renewal pending deployment = %+v, error %v", pendingDeploy, err)
		}
		for _, pending := range pendingDeploy {
			if pending.Destination != "connector.deploy" || pending.Attempts != 0 || pending.Status != "pending" {
				t.Fatalf("unexpected side effect outside CA scope: %+v", pending)
			}
		}
	}
	certs := dispatcherCertificates(t, h)
	if len(certs) != 3 || seen != 3 {
		t.Fatalf("renewals/redelivery minted %d leaves/%d signer calls", len(certs), seen)
	}
	for _, cert := range certs {
		info, err := certinfo.Inspect(cert.CertificateDER)
		if err != nil || info.SPKISHA256 != crypto.SHA256Hex(key.PublicKeyDER) || cert.KeyOrigin != "requester" {
			t.Fatalf("requester key custody changed: %v", err)
		}
		got, err := h.store.IdentityRenewalCSR(ctx, h.tenant, ident.ID, cert.ID)
		if err != nil || got != canonicalCSR {
			t.Fatalf("explicit predecessor chain lost original transition: %v", err)
		}
	}
	if tenantEventTypes(t, h.log, h.tenant)["issuance.server_side_keygen"] != 0 {
		t.Fatal("renewal generated a private subject key")
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	for _, cert := range certs {
		got, err := h.store.IdentityRenewalCSR(ctx, h.tenant, ident.ID, cert.ID)
		if err != nil || got != canonicalCSR {
			t.Fatalf("replay lost exact CSR custody: %v", err)
		}
	}
	if got, err := h.store.GetCertificate(ctx, h.tenant, original.ID); err != nil || got.Status != "superseded" {
		t.Fatalf("predecessor lifecycle missing: %v", err)
	}
}

func TestRequesterRenewalRefusesMissingOrMismatchedCustodyBeforeSigner(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "requester-negative", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "guard.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateHostSubjectKey(ident.Name, []string{ident.Name})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.CSRDER})
	canonicalCSR := strings.TrimSpace(string(csr))
	if err := h.orch.TransitionWithSubjectCSR(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "requester original", "guard-original-key", string(csr)); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatal("missing first leaf")
	}
	old := certs[0]
	if got, err := h.store.IdentityRenewalCSR(ctx, h.tenant, ident.ID, old.ID); err != nil || got != canonicalCSR {
		t.Fatalf("original transition CSR before corruption: %v", err)
	}
	h.handler.issue = func(context.Context, []byte, time.Duration, crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		t.Fatal("custody refusal reached signer")
		return crypto.IssuedLeaf{}, nil
	}
	other := ident
	other.ID = "22222222-2222-4222-8222-222222222222"
	if _, err := h.handler.mintServedLeafForRenewal(ctx, h.tenant, other, old, ident.Name, []string{ident.Name}, "negative"); err == nil {
		t.Fatal("same-name identity borrowed another transition")
	}
	if _, err := h.store.IdentityRenewalCSR(ctx, "22222222-2222-2222-2222-222222222222", ident.ID, old.ID); err == nil {
		t.Fatal("cross-tenant requester lineage accepted")
	}
	for _, origin := range []string{"", "unknown", "host_agent"} {
		copy := old
		copy.KeyOrigin = origin
		if _, err := h.handler.mintServedLeafForRenewal(ctx, h.tenant, ident, copy, ident.Name, []string{ident.Name}, "negative"); err == nil {
			t.Fatalf("unproved custody %q accepted", origin)
		}
	}
	copy := old
	copy.Fingerprint = "wrong"
	if _, err := h.handler.mintServedLeafForRenewal(ctx, h.tenant, ident, copy, ident.Name, []string{ident.Name}, "negative"); err == nil {
		t.Fatal("predecessor bytes did not bind fingerprint")
	}
	otherKey, err := crypto.GenerateHostSubjectKey(ident.Name, []string{ident.Name})
	if err != nil {
		t.Fatal(err)
	}
	defer otherKey.Destroy()
	wrongCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: otherKey.CSRDER})
	for _, bad := range []string{"", string(wrongCSR), "-----BEGIN CERTIFICATE REQUEST-----\nAQID\n-----END CERTIFICATE REQUEST-----"} {
		// Deliberate test-only projection corruption: source truth is unchanged;
		// the production reader must refuse rather than generate a replacement.
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE identity_transitions SET subject_csr_pem=$3 WHERE tenant_id=$1 AND identity_id=$2`, h.tenant, ident.ID, bad)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.handler.mintServedLeafForRenewal(ctx, h.tenant, ident, old, ident.Name, []string{ident.Name}, "negative"); err == nil {
			t.Fatal("missing, malformed or wrong-key transition admitted")
		}
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	got, err := h.store.IdentityRenewalCSR(ctx, h.tenant, ident.ID, old.ID)
	if err != nil || got != canonicalCSR {
		t.Fatalf("source replay did not restore actual CSR: %v", err)
	}
}

func TestRequesterRenewalCSRRejectsSameKeyChangedNamesAndMalformedProof(t *testing.T) {
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "renewal identity test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	template := crypto.CertificateRequestTemplate{CommonName: "exact.example.test", DNSNames: []string{"exact.example.test"}, EmailAddresses: []string{"owner@example.test"}, URIs: []string{"spiffe://example.test/workload"}}
	der, err := crypto.CreateCertificateRequest(template, subject)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := crypto.SignLeafFromCSR(caDER, ca, der, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		t.Fatal(err)
	}
	old := store.Certificate{CertificateDER: certDER, Fingerprint: info.SHA256Fingerprint}
	encode := func(der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	if err := validateRequesterRenewalCSR(encode(der), old); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"cn", "dns", "email", "uri"} {
		changed := template
		switch field {
		case "cn":
			changed.CommonName = "other.example.test"
		case "dns":
			changed.DNSNames = []string{"other.example.test"}
		case "email":
			changed.EmailAddresses = []string{"other@example.test"}
		case "uri":
			changed.URIs = []string{"spiffe://example.test/other"}
		}
		other, err := crypto.CreateCertificateRequest(changed, subject)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRequesterRenewalCSR(encode(other), old); err == nil {
			t.Fatalf("same-key changed %s accepted", field)
		}
	}
	corrupt := bytes.Clone(der)
	corrupt[len(corrupt)-1] ^= 1
	for _, raw := range [][]byte{nil, encode(corrupt), append([]byte("unexpected prefix\n"), encode(der)...), append(encode(der), encode(der)...), bytes.Repeat([]byte("x"), 65537),
		append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n"), encode(der)...),
		append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n"), encode(der)...),
	} {
		if err := validateRequesterRenewalCSR(raw, old); err == nil {
			t.Error("malformed or unbounded public CSR accepted for renewal")
		}
		if _, _, err := decodeSubjectCSR(raw); err == nil {
			t.Error("malformed or unbounded public CSR accepted for issuance")
		}
	}
}
