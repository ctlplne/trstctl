// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type revocationTestCA struct {
	factoryTestCA
	revoke func(context.Context, ca.RevokeRequest) error
}

func (c revocationTestCA) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	return c.revoke(ctx, req)
}

func TestExternalCAFactoryRevocationCleansEveryAttempt(t *testing.T) {
	for _, upstreamError := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "refused"}[upstreamError], func(t *testing.T) {
			created, cleaned, called := 0, 0, 0
			denied := errors.New("authority unavailable")
			wrapped := factoryExternalCA{name: "test authority", factory: func(context.Context) (ca.CA, func(), error) {
				created++
				return revocationTestCA{revoke: func(context.Context, ca.RevokeRequest) error {
					called++
					if upstreamError {
						return denied
					}
					return nil
				}}, func() { cleaned++ }, nil
			}}
			err := ca.RevokeThrough(t.Context(), wrapped, ca.RevokeRequest{TenantID: "test-tenant", Serial: "01"})
			if upstreamError && !errors.Is(err, denied) || !upstreamError && err != nil {
				t.Fatalf("revocation error = %v", err)
			}
			if created != 1 || cleaned != 1 || called != 1 {
				t.Fatalf("created/cleaned/called = %d/%d/%d, want 1/1/1", created, cleaned, called)
			}
		})
	}
}

// This exercises the real outbox intent, PostgreSQL projections and NATS event
// log. The authority is a contract receiver; the independent Pebble/Apache walk
// must additionally prove that the deployed binary reaches a real authority.
func TestIdentityRevocationReachesSelectedCAAndRestoredPredecessor(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "revocation owner", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "revoke.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"issuing_authority_source":"external","issuing_authority_id":"later-selection"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issuance intent"); err != nil {
		t.Fatal(err)
	}

	first := recordRevocationTestLeaf(t, h, owner.ID, ident.Name, "selected-ca", "first", "")
	current := recordRevocationTestLeaf(t, h, owner.ID, ident.Name, "selected-ca", "current", first.ID)
	unrelated := recordRevocationTestLeaf(t, h, owner.ID, ident.Name, "selected-ca", "unrelated", "")
	// An agent can obtain a certificate and then fail before delivering it. The
	// retained job still binds every signed attempt to this exact identity.
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		payload, err := json.Marshal(RelayDeployIntent{IdentityID: ident.ID})
		if err != nil {
			return err
		}
		jobID, err = h.outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: h.tenant, Destination: "endpoint.renew", IdempotencyKey: "undelivered-host-job", Payload: payload, RequiredAgentRole: "host"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	undelivered := recordRevocationTestLeaf(t, h, owner.ID, ident.Name, "selected-ca", fmt.Sprintf("agentcsr:%d:1:abcd", jobID), "")
	for _, receipt := range []store.ConnectorDeliveryReceipt{
		{IdentityID: &ident.ID, Destination: "connector.deploy", Connector: "apache", Target: "canary", Fingerprint: first.Fingerprint, Status: "verified", IdempotencyKey: "first-deploy"},
		{IdentityID: &ident.ID, Destination: "connector.deploy", Connector: "apache", Target: "canary", Fingerprint: current.Fingerprint, Status: "verified", IdempotencyKey: "current-deploy"},
		{IdentityID: &ident.ID, Destination: "connector.rollback", Connector: "apache", Target: "canary", Fingerprint: first.Fingerprint, Status: "rolled_back", IdempotencyKey: "restore-first"},
	} {
		if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, receipt); err != nil {
			t.Fatal(err)
		}
	}

	fail := true
	seen := map[string]int{}
	cleaned := 0
	upstream := revocationTestCA{revoke: func(ctx context.Context, req ca.RevokeRequest) error {
		rows, err := h.outbox.Pending(ctx, h.tenant)
		if err != nil {
			return err
		}
		pending := false
		for _, row := range rows {
			if row.Destination == "revocation.publish" {
				pending = true
			}
		}
		if !pending {
			return errors.New("upstream called before transactional revocation intent")
		}
		info, err := certinfo.Inspect(req.CertificatePEM)
		if err != nil {
			return err
		}
		if req.TenantID != h.tenant || req.Serial != info.SerialNumber || req.ReasonCode != 1 {
			return errors.New("wrong exact certificate, tenant, or reason")
		}
		if info.SHA256Fingerprint == unrelated.Fingerprint {
			return errors.New("revoked unrelated same-owner/SAN certificate")
		}
		if fail {
			return errors.New("intentional authority outage")
		}
		seen[info.SHA256Fingerprint]++
		return nil
	}}
	srv := &Server{orch: h.orch, outbox: h.outbox}
	_, err = srv.buildExternalCAService(Deps{Store: h.store, Log: h.log, ExternalCAs: []ExternalCA{{ID: "selected-ca", Type: "letsencrypt", Name: "selected authority", Factory: func(context.Context) (ca.CA, func(), error) { return upstream, func() { cleaned++ }, nil }}}}, h.handler.idem)
	if err != nil {
		t.Fatal(err)
	}
	h.handler.externalCAs = srv.externalCAs
	if err = h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRevoked, "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	row := pendingOutboxByDestination(t, h, "revocation.publish")
	msg := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	if err := h.handler.Deliver(ctx, msg); err == nil {
		t.Error("upstream outage reported successful revocation")
	}
	for _, cert := range []store.Certificate{first, current, undelivered, unrelated} {
		got, err := h.store.GetCertificate(ctx, h.tenant, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == "revoked" {
			t.Errorf("certificate %s marked revoked before authority accepted", cert.ID)
		}
		if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), cert.Serial); err != nil || found {
			t.Errorf("external serial entered internal CA ledger: found=%t err=%v", found, err)
		}
	}
	fail = false
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatal(err)
	}
	if seen[first.Fingerprint] != 1 || seen[current.Fingerprint] != 1 || seen[undelivered.Fingerprint] != 1 || len(seen) != 3 {
		t.Errorf("authority received %v, want current, restored predecessor and undelivered host leaf", seen)
	}
	for _, cert := range []store.Certificate{first, current, undelivered} {
		got, err := h.store.GetCertificate(ctx, h.tenant, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "revoked" || got.RevocationReason != "keyCompromise" {
			t.Errorf("accepted upstream revocation missing: id=%s status=%s reason=%s", got.ID, got.Status, got.RevocationReason)
		}
		if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), cert.Serial); err != nil || found {
			t.Errorf("external serial polluted internal CA ledger: found=%t err=%v", found, err)
		}
	}
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatal(err)
	}
	if seen[first.Fingerprint] != 1 || seen[current.Fingerprint] != 1 {
		t.Fatalf("successful retry repeated upstream effects: %v", seen)
	}
	if cleaned < 3 {
		t.Fatalf("expected failed and successful factory clients destroyed, got %d", cleaned)
	}
}

// A failed CRL publication must remain retryable after the certificate mutation
// committed. Re-imported observation metadata must not erase issuance authority.
func TestPlatformIdentityRevocationRetriesPublicationAfterObservation(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "platform revocation owner", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "platform-revoke.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("certificates=%d", len(certs))
	}
	original := certs[0]
	observation := original
	observation.Source = "import"
	observation.IssuanceIdempotencyKey = ""
	observation.CertificatePEM = nil
	observation.CertificateDER = nil
	observation.ValidityAnchor = nil
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deploy"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "renew"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	certs = dispatcherCertificates(t, h)
	if len(certs) != 2 {
		t.Fatalf("renewal certificates=%d, want 2", len(certs))
	}
	if _, err := h.orch.RecordCertificate(ctx, h.tenant, observation); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRevoked, "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	row := pendingOutboxByDestination(t, h, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	attempts := 0
	h.handler.publishCRL = func(context.Context, string) error {
		attempts++
		if attempts == 1 {
			return errors.New("publisher unavailable")
		}
		return nil
	}
	if err := h.handler.Deliver(ctx, message); err == nil || err.Error() != "publisher unavailable" {
		t.Fatalf("expected only the injected publication error, got %v", err)
	}
	got, err := h.store.GetCertificate(ctx, h.tenant, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" {
		t.Fatalf("confirmed local revocation was not retained: %s", got.Status)
	}
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("publication attempts=%d, want 2", attempts)
	}
	for _, certificate := range dispatcherCertificates(t, h) {
		if certificate.Status != "revoked" {
			t.Errorf("renewal chain member %s was not revoked: %s", certificate.ID, certificate.Status)
		}
	}
	issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), original.Serial)
	if err != nil || !found || !issued.Revoked() {
		t.Fatalf("local revocation ledger missing: found=%t error=%v", found, err)
	}
}

func recordRevocationTestLeaf(t *testing.T, h *issuanceDispatcherHarness, owner, name, authority, key, predecessor string) store.Certificate {
	t.Helper()
	issued, err := testExternalCACertificate(ca.IssueRequest{CSR: serverTestCSR(t, name, nil), DNSNames: []string{name}}, "Independent revocation CA")
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certinfo.LeafDER(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	c := store.Certificate{OwnerID: &owner, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter, Source: "external-ca:" + authority, CertificateDER: der, CertificatePEM: issued.CertificatePEM,
		IssuanceIdempotencyKey: "external-test:" + key}
	fact := projections.CertificateRecorded{ID: uuid.NewString(), Source: c.Source,
		Subject: c.Subject, SANs: c.SANs, Issuer: c.Issuer, Serial: c.Serial,
		Fingerprint: c.Fingerprint, KeyAlgorithm: c.KeyAlgorithm, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		CertificateDER: c.CertificateDER, CertificatePEM: c.CertificatePEM,
		IssuanceIdempotencyKey: c.IssuanceIdempotencyKey, IssuanceRequestBinding: strings.Repeat("a", 64)}
	payload, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(h.tenant+"\x00certificate.recorded\x00"+c.IssuanceIdempotencyKey)).String()
	event, err := h.log.Append(t.Context(), events.Event{ID: eventID, TenantID: h.tenant, Type: projections.EventCertificateRecorded, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	// The host recording changes observation source after the upstream issuance.
	c.Source = "issued"
	c.IssuanceIdempotencyKey = "agentcsr:" + key
	if strings.HasPrefix(key, "agentcsr:") {
		c.IssuanceIdempotencyKey = key
	}
	if predecessor != "" {
		c, err = h.orch.RecordSuccessorCertificate(t.Context(), h.tenant, c, predecessor)
	} else {
		c, err = h.orch.RecordCertificate(t.Context(), h.tenant, c)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Source, "issued") {
		t.Fatal("fixture did not model host recording")
	}
	return c
}
