package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func TestIssuanceDispatcherRenewalMintsSuccessorAndSupersedesPredecessor(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "renewal-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "renew.served.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	dispatchOutbox(t, h, 1)

	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("after initial issue certificates = %d, want 1", len(certs))
	}
	old := certs[0]
	if old.Status != "active" {
		t.Fatalf("initial cert status = %q, want active", old.Status)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatalf("transition to deployed: %v", err)
	}
	dispatchOutbox(t, h, 1) // connector.deploy is explicitly acknowledged when no plugin owns it.

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "operator renewal"); err != nil {
		t.Fatalf("transition to renewing: %v", err)
	}
	renew := pendingOutboxByDestination(t, h, "ca.renew")
	msg := orchestrator.Message{
		TenantID: h.tenant, Destination: renew.Destination,
		Payload: renew.Payload, IdempotencyKey: renew.IdempotencyKey,
	}

	dispatchOutbox(t, h, 1)
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatalf("idempotent ca.renew redelivery: %v", err)
	}

	certs = dispatcherCertificates(t, h)
	if len(certs) != 2 {
		t.Fatalf("after renewal certificates = %d, want exactly 2 (predecessor + successor)", len(certs))
	}
	var gotOld, successor store.Certificate
	for _, c := range certs {
		if c.ID == old.ID {
			gotOld = c
		}
		if c.ReplacesID != nil && *c.ReplacesID == old.ID {
			successor = c
		}
	}
	if gotOld.ID == "" {
		t.Fatal("predecessor certificate disappeared from inventory")
	}
	if gotOld.Status != "superseded" || gotOld.RenewedAt == nil {
		t.Fatalf("predecessor status=%q renewed_at=%v, want superseded with renewal timestamp", gotOld.Status, gotOld.RenewedAt)
	}
	if successor.ID == "" {
		t.Fatal("renewal did not record a successor linked with replaces_id")
	}
	if successor.Status != "active" {
		t.Fatalf("successor status = %q, want active", successor.Status)
	}
	if successor.Serial == "" || successor.Serial == old.Serial {
		t.Fatalf("successor serial = %q, predecessor serial = %q; renewal must mint a distinct cert", successor.Serial, old.Serial)
	}
	if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), successor.Serial); err != nil {
		t.Fatalf("lookup successor issued-cert row: %v", err)
	} else if !found {
		t.Fatal("successor serial was not bridged into ca_issued_certs for OCSP/CRL")
	}
	state, err := h.orch.State(ctx, h.tenant, ident.ID)
	if err != nil {
		t.Fatalf("identity state: %v", err)
	}
	if state != orchestrator.StateDeployed {
		t.Fatalf("identity state after renewal = %q, want deployed", state)
	}
}

func TestIssuanceDispatcherRecoversRecordedCertificateBeforeRetryingSigner(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	baseIssue := h.handler.issue
	signCalls := 0
	h.handler.issue = func(ctx context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
		signCalls++
		return baseIssue(ctx, csrDER, ttl, leafProfile)
	}

	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "correct-001-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "correct-001.served.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue with crash gap"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	issue := pendingOutboxByDestination(t, h, "ca.issue")
	msg := orchestrator.Message{
		TenantID: h.tenant, Destination: issue.Destination,
		Payload: issue.Payload, IdempotencyKey: issue.IdempotencyKey,
	}

	injected := errors.New("crash after certificate.recorded before idempotency completion")
	failOnce := true
	h.handler.afterIssueSideEffects = func(context.Context) error {
		if !failOnce {
			return nil
		}
		failOnce = false
		return injected
	}
	if err := h.handler.Deliver(ctx, msg); !errors.Is(err, injected) {
		t.Fatalf("first delivery error = %v, want injected crash gap", err)
	}
	idemKey := "issue:" + msg.IdempotencyKey
	deleteCertificatesByIssuanceKey(t, h, idemKey)

	h.handler.afterIssueSideEffects = nil
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatalf("retry delivery: %v", err)
	}
	if signCalls != 1 {
		t.Fatalf("signer calls = %d, want 1; retry must recover recorded certificate before signing", signCalls)
	}
	certs, err := h.store.ListCertificatesByIssuanceIdempotencyKey(ctx, h.tenant, idemKey)
	if err != nil {
		t.Fatalf("list recovered certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("recovered certificates = %d, want 1", len(certs))
	}
	if certs[0].IssuanceIdempotencyKey != idemKey {
		t.Fatalf("issuance idempotency key = %q, want %q", certs[0].IssuanceIdempotencyKey, idemKey)
	}
	if len(certs[0].CertificateDER) == 0 {
		t.Fatal("recovered certificate has no DER; protocol retries could not return the original certificate")
	}
	if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), certs[0].Serial); err != nil {
		t.Fatalf("lookup recovered issued-cert row: %v", err)
	} else if !found {
		t.Fatal("recovered certificate serial was not repaired into ca_issued_certs")
	}
}

func TestIssuanceDispatcherFailsUnsupportedFirstPartyDestination(t *testing.T) {
	d := &issuanceDispatcher{}
	err := d.Deliver(context.Background(), orchestrator.Message{Destination: "ca.rotate"})
	if err == nil || !strings.Contains(err.Error(), "unsupported first-party outbox destination") {
		t.Fatalf("unsupported ca.* destination error = %v, want fail-closed error", err)
	}
	if err := d.Deliver(context.Background(), orchestrator.Message{Destination: "notification.expiry"}); err != nil {
		t.Fatalf("non-owned notification destination should remain unrouted, got %v", err)
	}
}

func TestIssuanceDispatcherServedProfileControlsLeafEKUs(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(365 * 24 * time.Hour), AllowedProtocols: []string{"api"},
	})

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "API EKU CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var issuedEKUs []string
	h.handler.defaultProfile = "tls-server"
	h.handler.issue = func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
		leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
		if err != nil {
			return nil, err
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			return nil, err
		}
		issuedEKUs = info.ExtKeyUsages
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
	}

	if _, err := h.handler.mintServedLeaf(ctx, h.tenant, "owner-1", "api.eku.test", []string{"api.eku.test"}); err != nil {
		t.Fatalf("mint served leaf: %v", err)
	}
	if !sameStrings(issuedEKUs, []string{"serverAuth"}) {
		t.Fatalf("issued EKUs = %v, want exactly [serverAuth]", issuedEKUs)
	}
}

func TestIssuanceDispatcherRejectsExcludedCSRRequestedEKUBeforeSigning(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{"api"},
	})

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "client-only.eku.test", DNSNames: []string{"client-only.eku.test"}, RequestedEKUs: []string{"clientAuth"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	h.handler.defaultProfile = "tls-server"
	h.handler.issue = func(context.Context, []byte, time.Duration, crypto.LeafProfile) ([]byte, error) {
		t.Fatal("signing must not be reached for an excluded EKU")
		return nil, nil
	}

	_, err = h.handler.enforceProfile(ctx, h.tenant, csrDER, []string{"client-only.eku.test"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), `extended key usage "clientAuth"`) {
		t.Fatalf("enforceProfile error = %v, want excluded clientAuth before signing", err)
	}
}

func TestProtocolIssuerServedProfileControlsAndRejectsLeafEKUs(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{"acme"},
	})

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Protocol EKU CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var issuedEKUs []string
	called := 0
	issuer := &protocolIssuer{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			called++
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			info, err := certinfo.Inspect(leafDER)
			if err != nil {
				return nil, err
			}
			issuedEKUs = info.ExtKeyUsages
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: h.orch, idem: orchestrator.NewIdempotency(h.store), store: h.store, log: h.log, caID: IssuingCAID(), defaultProfile: "tls-server",
	}

	serverCSR := serverTestCSR(t, "proto.eku.test", nil)
	if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "eku-positive", serverCSR, time.Hour); err != nil {
		t.Fatalf("protocol issue: %v", err)
	}
	if called != 1 {
		t.Fatalf("signing calls = %d, want 1", called)
	}
	if !sameStrings(issuedEKUs, []string{"serverAuth"}) {
		t.Fatalf("protocol issued EKUs = %v, want exactly [serverAuth]", issuedEKUs)
	}

	for _, protocolName := range []string{"acme", "est", "scep", "cmp", "ssh", "spiffe"} {
		t.Run("deny before signing/"+protocolName, func(t *testing.T) {
			profileName := "tls-server-" + protocolName
			storeServerTestProfile(t, h.store, h.tenant, profileName, profile.CertificateProfile{
				Name: profileName, AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{protocolName},
			})
			issuer.defaultProfile = profileName
			before := called
			clientCSR := serverTestCSR(t, "client-only."+protocolName+".proto.test", []string{"clientAuth"})
			if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, protocolName, "eku-negative-"+protocolName, clientCSR, time.Hour); err == nil || !strings.Contains(err.Error(), `extended key usage "clientAuth"`) {
				t.Fatalf("protocol %s excluded EKU error = %v, want clientAuth profile rejection", protocolName, err)
			}
			if called != before {
				t.Fatalf("protocol %s reached signing after rejected CSR: calls %d -> %d", protocolName, before, called)
			}
		})
	}
}

func TestProtocolIssuerRecoversRecordedDERBeforeRetryingSigner(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Protocol Crash Gap CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var firstDER []byte
	signCalls := 0
	issuer := &protocolIssuer{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			signCalls++
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			if firstDER == nil {
				firstDER = append([]byte(nil), leafDER...)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: h.orch, idem: orchestrator.NewIdempotency(h.store), store: h.store, log: h.log, caID: IssuingCAID(),
	}

	injected := errors.New("crash after protocol certificate.recorded before idempotency completion")
	failOnce := true
	issuer.afterIssueSideEffects = func(context.Context) error {
		if !failOnce {
			return nil
		}
		failOnce = false
		return injected
	}

	csrDER := serverTestCSR(t, "correct-001.protocol.test", nil)
	if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "correct-001-protocol", csrDER, time.Hour); !errors.Is(err, injected) {
		t.Fatalf("first protocol issue error = %v, want injected crash gap", err)
	}
	idemKey := "protocol-issue:correct-001-protocol"
	deleteCertificatesByIssuanceKey(t, h, idemKey)

	issuer.afterIssueSideEffects = nil
	raw, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "correct-001-protocol", csrDER, time.Hour)
	if err != nil {
		t.Fatalf("retry protocol issue: %v", err)
	}
	if signCalls != 1 {
		t.Fatalf("protocol signer calls = %d, want 1; retry must not mint another leaf", signCalls)
	}
	if !bytes.Equal(raw, firstDER) {
		t.Fatal("protocol retry did not return the DER from the first recorded certificate")
	}
}

type issuanceDispatcherHarness struct {
	store   *store.Store
	log     *events.Log
	outbox  *orchestrator.Outbox
	orch    *orchestrator.Orchestrator
	handler *issuanceDispatcher
	tenant  string
}

func newIssuanceDispatcherHarness(t *testing.T) *issuanceDispatcherHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Test Issuance Dispatcher CA", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	outbox := orchestrator.NewOutbox(st)
	idem := orchestrator.NewIdempotency(st)
	orch := orchestrator.NewOrchestrator(log, st, outbox)
	handler := &issuanceDispatcher{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: orch, idem: idem, store: st, log: log,
	}
	h := &issuanceDispatcherHarness{
		store: st, log: log, outbox: outbox, orch: orch, handler: handler,
		tenant: "11111111-1111-1111-1111-111111111111",
	}
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: h.tenant, Name: "dispatcher-renewal"}); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	return h
}

func storeServerTestProfile(t *testing.T, s *store.Store, tenant, name string, p profile.CertificateProfile) {
	t.Helper()
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProfileVersion(context.Background(), store.ProfileRecord{
		TenantID: tenant, Name: name, Spec: spec, CreatedBy: "test",
	}); err != nil {
		t.Fatalf("CreateProfileVersion: %v", err)
	}
}

func serverTestCSR(t *testing.T, cn string, requestedEKUs []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: cn, DNSNames: []string{cn}, RequestedEKUs: requestedEKUs,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func dispatchOutbox(t *testing.T, h *issuanceDispatcherHarness, want int) {
	t.Helper()
	n, err := h.outbox.Dispatch(context.Background(), h.handler)
	if err != nil {
		t.Fatalf("dispatch outbox: %v", err)
	}
	if n != want {
		t.Fatalf("dispatched %d outbox rows, want %d", n, want)
	}
}

func pendingOutboxByDestination(t *testing.T, h *issuanceDispatcherHarness, dest string) orchestrator.Record {
	t.Helper()
	pending, err := h.outbox.Pending(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("pending outbox: %v", err)
	}
	for _, r := range pending {
		if r.Destination == dest {
			return r
		}
	}
	t.Fatalf("no pending %s outbox row in %+v", dest, pending)
	return orchestrator.Record{}
}

func dispatcherCertificates(t *testing.T, h *issuanceDispatcherHarness) []store.Certificate {
	t.Helper()
	certs, err := h.store.ListCertificatesPage(context.Background(), h.tenant, store.ZeroUUID, nil, 100, nil)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	return certs
}

func deleteCertificatesByIssuanceKey(t *testing.T, h *issuanceDispatcherHarness, key string) {
	t.Helper()
	if _, err := h.store.SystemPool().Exec(context.Background(),
		`DELETE FROM certificates WHERE tenant_id = $1 AND issuance_idempotency_key = $2`,
		h.tenant, key); err != nil {
		t.Fatalf("delete certificate read-model row for %s: %v", key, err)
	}
}
