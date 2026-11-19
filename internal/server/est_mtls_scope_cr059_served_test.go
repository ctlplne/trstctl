// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The EST mutual-TLS listener serves one tenant's renewals (CR-059, CR-058).
// It trusts the platform issuing CA every tenant shares, so the presented
// certificate is judged by what the platform recorded about it: issued into
// this mount's tenant, in good standing as the OCSP responder reads it, and
// issued by EST enrollment. Initial enrollment and server-side keygen belong on
// the main listener with the bootstrap credential.

const (
	estNotActiveRefusal    = "client certificate is not an active certificate of this mount's tenant"
	estReenrollOnlyRefusal = "the mutual-TLS listener serves re-enrollment only; enroll on the main listener"
)

// estMTLSScope is a served control plane whose EST mount serves the default
// tenant, with the mount's mutual-TLS listener running beside the main one.
type estMTLSScope struct {
	h     *servedHarness
	main  *httptest.Server
	token string
	sc    *mtls.ServerCert
	base  string
}

// estClientLeaf is a certificate with its key, presented as the mutual-TLS
// client certificate.
type estClientLeaf struct {
	der    []byte
	info   certinfo.Info
	client *http.Client
}

// estIssuance counts what an EST request could have produced: issued-serial
// ledger rows and inventory rows per tenant, and allowed issuance audits.
type estIssuance struct {
	ledger    map[string]int
	inventory map[string]int
	allows    int
}

func newESTMTLSScope(t *testing.T, protocols config.Protocols) *estMTLSScope {
	t.Helper()
	h := newOperatingServedHarness(t, protocols)
	main := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(main.Close)
	sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go h.srv.serveESTMTLS(ctx, ln, sc)
	return &estMTLSScope{h: h, main: main, token: seedAPIToken(t, h.store, servedTestTenant), sc: sc,
		base: "https://" + ln.Addr().String() + "/.well-known/est/"}
}

func (s *estMTLSScope) present(t *testing.T, leafDER, keyPKCS8 []byte) estClientLeaf {
	t.Helper()
	src, err := mtls.ClientCertSourceFromDER(leafDER, keyPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.AgentHTTPTransport(src, s.sc.TrustPEM, "localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return estClientLeaf{der: leafDER, info: info, client: &http.Client{Transport: transport}}
}

// enroll obtains an EST leaf for name on the main listener with the tenant's
// bootstrap credential, the way a device first enrolls.
func (s *estMTLSScope) enroll(t *testing.T, name string) estClientLeaf {
	t.Helper()
	key, csr := estScopeCSR(t, name, []string{name})
	leafDER := estEnroll(t, s.main.Client(), s.main.URL+"/.well-known/est/simpleenroll", s.token, csr, http.StatusOK)
	keyPKCS8, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return s.present(t, leafDER, keyPKCS8)
}

// cmpEnroll obtains a leaf from the platform CA through the served CMP mount,
// for whichever tenant that mount serves.
func (s *estMTLSScope) cmpEnroll(t *testing.T, bootDER, keyPKCS8, csrDER []byte, txn string) estClientLeaf {
	t.Helper()
	msg, err := crypto.BuildCMPRequest(csrDER, bootDER, keyPKCS8, []byte(txn), []byte("cr059-nonce-0001"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.h.ts.Client().Post(s.h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CMP enrollment status %d: %s", resp.StatusCode, reply)
	}
	leafDER, err := crypto.ParseCMPResponse(reply)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, s.h.srv.caCertDER); err != nil {
		t.Fatalf("the CMP leaf is not from the platform issuing CA: %v", err)
	}
	return s.present(t, leafDER, keyPKCS8)
}

// estScopeCSR is a PKCS#10 request under a fresh key.
func estScopeCSR(t *testing.T, commonName string, dnsNames []string) (*crypto.LockedSigner, []byte) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, csr
}

// renewalCSR carries exactly the presented leaf's identifiers, as RFC 7030
// re-enrollment must, so only the client certificate gate can refuse it.
func renewalCSR(t *testing.T, leaf estClientLeaf) []byte {
	t.Helper()
	_, csr := estScopeCSR(t, leaf.info.CommonName, leaf.info.DNSNames)
	return csr
}

func (s *estMTLSScope) post(t *testing.T, leaf estClientLeaf, op string, csr []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.base+op, strings.NewReader(base64.StdEncoding.EncodeToString(csr)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	resp, err := leaf.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s on the mutual-TLS listener: %v", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

// refused posts and requires the exact refusal: nothing about the certificate
// is echoed back.
func (s *estMTLSScope) refused(t *testing.T, why string, leaf estClientLeaf, op string, csr []byte, refusal string) {
	t.Helper()
	if status, body := s.post(t, leaf, op, csr); status != http.StatusForbidden || body != refusal {
		t.Fatalf("%s: /%s = %d %q; want 403 %q", why, op, status, body, refusal)
	}
}

// refusedRenewal requires the client certificate gate to refuse a renewal that
// carries the leaf's own identifiers, and that nothing was issued for it.
func (s *estMTLSScope) refusedRenewal(t *testing.T, why string, leaf estClientLeaf, tenants ...string) {
	t.Helper()
	before := s.issuance(t, tenants...)
	s.refused(t, why, leaf, "simplereenroll", renewalCSR(t, leaf), estNotActiveRefusal)
	s.nothingIssuedSince(t, why, before, tenants...)
}

// renew requires a renewal with the leaf's identifiers to issue a certificate
// from the enrollment CA, recorded in the tenant's ledger and inventory.
func (s *estMTLSScope) renew(t *testing.T, why string, leaf estClientLeaf) []byte {
	t.Helper()
	before := s.issuance(t, servedTestTenant)
	status, body := s.post(t, leaf, "simplereenroll", renewalCSR(t, leaf))
	if status != http.StatusOK {
		t.Fatalf("%s: renewal = %d %q; want 200", why, status, body)
	}
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("%s: the renewal reply is not base64: %v", why, err)
	}
	certs, err := crypto.CertsFromPKCS7(der)
	if err != nil || len(certs) != 1 {
		t.Fatalf("%s: the renewal reply holds %d certificates: %v", why, len(certs), err)
	}
	if err := crypto.VerifyLeafSignedByCA(certs[0], s.h.srv.caCertDER); err != nil {
		t.Fatalf("%s: the renewed leaf is not from the enrollment CA: %v", why, err)
	}
	after := s.issuance(t, servedTestTenant)
	if after.ledger[servedTestTenant] != before.ledger[servedTestTenant]+1 || after.allows <= before.allows {
		t.Fatalf("%s: the renewal left ledger %d -> %d and allowed audits %d -> %d", why,
			before.ledger[servedTestTenant], after.ledger[servedTestTenant], before.allows, after.allows)
	}
	info, err := certinfo.Inspect(certs[0])
	if err != nil {
		t.Fatalf("%s: inspect renewed leaf: %v", why, err)
	}
	row, err := s.h.store.GetCertificateByFingerprint(t.Context(), servedTestTenant, info.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("%s: inventory lookup for renewed leaf: %v", why, err)
	}
	if !strings.EqualFold(row.Serial, info.SerialNumber) || row.EnrollmentProtocol != "est" {
		t.Fatalf("%s: the renewed leaf's inventory row must record the same serial and EST enrollment", why)
	}
	return certs[0]
}

// issuance counts, after the projections settle, each tenant's issued-serial
// ledger and inventory rows and every allowed EST issuance audit (the issuance
// record protocol.issued, and the mount's own decisions under either name).
func (s *estMTLSScope) issuance(t *testing.T, tenants ...string) estIssuance {
	t.Helper()
	if err := s.h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	out := estIssuance{ledger: map[string]int{}, inventory: map[string]int{}}
	for _, tenant := range tenants {
		var ledger, inventory int
		if err := s.h.store.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM ca_issued_certs WHERE tenant_id=$1`, tenant).Scan(&ledger); err != nil {
				return err
			}
			return tx.QueryRow(t.Context(), `SELECT count(*) FROM certificates WHERE tenant_id=$1`, tenant).Scan(&inventory)
		}); err != nil {
			t.Fatal(err)
		}
		out.ledger[tenant], out.inventory[tenant] = ledger, inventory
	}
	if err := s.h.log.Replay(t.Context(), 1, func(e events.Event) error {
		if e.Type != "protocol.issued" && !strings.HasPrefix(e.Type, "protocol.est.") {
			return nil
		}
		var decision struct {
			Protocol string `json:"protocol"`
			Decision string `json:"decision"`
		}
		if json.Unmarshal(e.Data, &decision) == nil && decision.Decision == "allow" &&
			(e.Type != "protocol.issued" || decision.Protocol == "est") {
			out.allows++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (s *estMTLSScope) nothingIssuedSince(t *testing.T, why string, before estIssuance, tenants ...string) {
	t.Helper()
	after := s.issuance(t, tenants...)
	for _, tenant := range tenants {
		if after.ledger[tenant] != before.ledger[tenant] || after.inventory[tenant] != before.inventory[tenant] {
			t.Fatalf("%s: tenant %s ledger %d -> %d, inventory %d -> %d; want nothing issued", why, tenant,
				before.ledger[tenant], after.ledger[tenant], before.inventory[tenant], after.inventory[tenant])
		}
	}
	if after.allows != before.allows {
		t.Fatalf("%s: allowed EST issuance audits %d -> %d; want none", why, before.allows, after.allows)
	}
}

// inventoryRow is the tenant's inventory row for a leaf.
func (s *estMTLSScope) inventoryRow(t *testing.T, tenant string, leaf estClientLeaf) store.Certificate {
	t.Helper()
	row, err := s.h.store.GetCertificateByFingerprint(t.Context(), tenant, leaf.info.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("inventory row for %s: %v", leaf.info.CommonName, err)
	}
	return row
}

// recordedBeforeTheEnrollmentPathWasKept rewrites a row to the shape a build
// before the recorded enrollment path (854801f91) left: no enrollment protocol.
func (s *estMTLSScope) recordedBeforeTheEnrollmentPathWasKept(t *testing.T, leaf estClientLeaf) {
	t.Helper()
	if err := s.h.store.WithTenant(t.Context(), servedTestTenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `UPDATE certificates SET enrollment_protocol='' WHERE tenant_id=$1 AND fingerprint=$2`,
			servedTestTenant, leaf.info.SHA256Fingerprint)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("legacy-shaped row rewrite touched %d rows", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// CR-059: another tenant's leaf from the shared platform CA authenticates the
// TLS handshake but renews, enrolls and generates nothing on this tenant's
// listener, also once it is imported into this tenant's inventory under the EST
// source. This tenant's own EST leaf still renews there, and the read-only
// routes still answer.
func TestServedESTMTLSRefusesAnotherTenantsLeafCR059(t *testing.T) {
	const tenantB = "22222222-2222-4222-8222-2222222222c9"
	bootDER, keyB, csrB := newSCEPClient(t, "tenant-b-device")
	s := newESTMTLSScope(t, config.Protocols{
		EST:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: tenantB},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, bootDER),
	})
	registerServedTenantID(t, s.h, tenantB, "CR-059 tenant B")
	leafB := s.cmpEnroll(t, bootDER, keyB, csrB, "cr059-txn-b")
	own := s.enroll(t, "device-a.est.test")
	tenants := []string{servedTestTenant, tenantB}

	s.refusedRenewal(t, "tenant B's leaf", leafB, tenants...)
	before := s.issuance(t, tenants...)
	_, victim := estScopeCSR(t, "victim-device.est.test", []string{"victim-device.est.test"})
	s.refused(t, "tenant B's leaf", leafB, "simpleenroll", victim, estReenrollOnlyRefusal)
	s.refused(t, "tenant B's leaf", leafB, "serverkeygen", victim, estReenrollOnlyRefusal)
	s.nothingIssuedSince(t, "tenant B's leaf enrolling", before, tenants...)

	importer := seedScopedToken(t, s.h.store, servedTestTenant, "certs:write")
	if status, raw := secretsReqKey(t, s.h, http.MethodPost, "/api/v1/certificates", importer, "cr059-import-tenant-b-leaf",
		map[string]any{"pem": certificatePEM(leafB.der), "source": "protocol:est"}); status != http.StatusCreated {
		t.Fatalf("import tenant B's leaf into tenant A: %d %s", status, raw)
	}
	s.issuance(t) // settle the import
	if row := s.inventoryRow(t, servedTestTenant, leafB); row.Source != "protocol:est" || row.EnrollmentProtocol != "" {
		t.Fatalf("imported row source=%q enrollment_protocol=%q", row.Source, row.EnrollmentProtocol)
	}
	s.refusedRenewal(t, "tenant B's leaf imported into tenant A", leafB, tenants...)

	before = s.issuance(t, tenants...)
	_, ownCSR := estScopeCSR(t, "device-a.est.test", []string{"device-a.est.test"})
	s.refused(t, "tenant A's leaf", own, "simpleenroll", ownCSR, estReenrollOnlyRefusal)
	s.refused(t, "tenant A's leaf", own, "serverkeygen", ownCSR, estReenrollOnlyRefusal)
	s.nothingIssuedSince(t, "tenant A's leaf enrolling", before, tenants...)
	for op, want := range map[string]int{"cacerts": http.StatusOK, "csrattrs": http.StatusNoContent} {
		resp, err := own.client.Get(s.base + op)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("GET /%s on the mutual-TLS listener = %d, want %d", op, resp.StatusCode, want)
		}
	}
	s.renew(t, "tenant A's own EST leaf", own)
}

// CR-058: a leaf that is not in good standing renews nothing: revoked through
// the API, held by a pending revocation decision, unknown to the responder, or
// revoked in the inventory without a ledger revocation. A superseded leaf that
// was never revoked still renews (a device that lost its renewal response
// presents the old one again). An EST leaf recorded before the enrollment path
// was kept passes the gate when its CA ledger row records its EST mint, and not
// when the ledger row predates mint records.
func TestServedESTMTLSRefusesLeavesNotInGoodStandingCR058(t *testing.T) {
	s := newESTMTLSScope(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	revoked := s.enroll(t, "revoked.est.test")
	pending := s.enroll(t, "pending.est.test")
	unknown := s.enroll(t, "unknown.est.test")
	inventoryRevoked := s.enroll(t, "inventory-revoked.est.test")
	superseded := s.enroll(t, "superseded.est.test")
	legacy := s.enroll(t, "legacy.est.test")
	legacyUnminted := s.enroll(t, "legacy-unminted.est.test")
	s.issuance(t)

	owner := seedScopedToken(t, s.h.store, servedTestTenant, "certs:issue", "certs:read", "identities:write")
	if status, raw := secretsReqKey(t, s.h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "cr058-revoke",
		map[string]any{"certificate_ids": []string{s.inventoryRow(t, servedTestTenant, revoked).ID}, "reason": "cessationOfOperation"}); status != http.StatusOK {
		t.Fatalf("revoke: %d %s", status, raw)
	}
	s.issuance(t)
	if got := servedOCSPStatus(t, s.h.srv, servedTestTenant, revoked.der, s.h.caPEM); got != crypto.OCSPRevoked {
		t.Fatalf("OCSP for the revoked leaf = %q, want revoked", got)
	}
	s.refusedRenewal(t, "a revoked leaf", revoked, servedTestTenant)

	pendingRow := s.inventoryRow(t, servedTestTenant, pending)
	batch := projections.CertificateRevocationBatchApplied{
		RequestBinding: crypto.SHA256Hex([]byte("cr058 pending revocation")),
		Reason:         "keyCompromise",
		Items: []projections.CertificateRevocationItem{{ID: pendingRow.ID, Matched: true, Status: "revoked",
			CAID: IssuingCAID(), Serial: pendingRow.Serial, Fingerprint: pendingRow.Fingerprint}},
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.h.store.ClaimCertificateRevocationAuthority(t.Context(), store.CertificateRevocationAuthorityCommand{
		Event: events.Event{ID: "cr058-pending-revocation", Type: projections.EventCertificateRevocationBatchApplied,
			TenantID: servedTestTenant, Time: time.Now().UTC().Truncate(time.Microsecond),
			SchemaVersion: events.DefaultSchemaVersion, Data: payload},
		RequestBinding: batch.RequestBinding,
		Targets: []store.CertificateRevocationAuthorityTarget{{
			CAID: IssuingCAID(), Serial: pendingRow.Serial, Fingerprint: pendingRow.Fingerprint}},
	}); err != nil {
		t.Fatal(err)
	}
	s.refusedRenewal(t, "a leaf with a pending revocation decision", pending, servedTestTenant)

	if err := s.h.store.WithTenant(t.Context(), servedTestTenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `DELETE FROM ca_issued_certs WHERE tenant_id=$1 AND ca_id=$2 AND serial=$3`,
			servedTestTenant, IssuingCAID(), unknown.info.SerialNumber)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("ledger delete touched %d rows", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := servedOCSPStatus(t, s.h.srv, servedTestTenant, unknown.der, s.h.caPEM); got != crypto.OCSPUnknown {
		t.Fatalf("OCSP for the leaf the ledger lacks = %q, want unknown", got)
	}
	s.refusedRenewal(t, "a leaf the responder does not know", unknown, servedTestTenant)

	// A certificate.revoked event that carries no CA ID marks only the
	// inventory row (the projection skips the ledger): the responder still
	// answers good, the gate refuses.
	if err := s.h.srv.orch.RevokeCertificate(t.Context(), servedTestTenant, inventoryRevoked.info.SHA256Fingerprint,
		inventoryRevoked.info.SerialNumber, "keyCompromise", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.issuance(t)
	if row := s.inventoryRow(t, servedTestTenant, inventoryRevoked); row.Status != "revoked" {
		t.Fatalf("inventory-only revocation left status %q", row.Status)
	}
	if got := servedOCSPStatus(t, s.h.srv, servedTestTenant, inventoryRevoked.der, s.h.caPEM); got != crypto.OCSPGood {
		t.Fatalf("OCSP for the inventory-only revocation = %q, want good", got)
	}
	s.refusedRenewal(t, "a leaf revoked in the inventory only", inventoryRevoked, servedTestTenant)

	successor, err := certinfo.Inspect(s.renew(t, "a current EST leaf", superseded))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.h.srv.orch.SupersedeCertificate(t.Context(), servedTestTenant, superseded.info.SHA256Fingerprint,
		superseded.info.SerialNumber, successor.SerialNumber, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.issuance(t)
	if row := s.inventoryRow(t, servedTestTenant, superseded); row.Status != "superseded" {
		t.Fatalf("superseded fixture status = %q", row.Status)
	}
	s.renew(t, "a superseded leaf that was never revoked", superseded)

	// Last, because a write outside the projector stops further certificate
	// recording in the tenant until a rebuild: rows shaped as a build before
	// the recorded enrollment path (854801f91) left them. The gate is asked
	// directly for the one it admits, since no renewal can be recorded now.
	s.recordedBeforeTheEnrollmentPathWasKept(t, legacy)
	if row := s.inventoryRow(t, servedTestTenant, legacy); row.EnrollmentProtocol != "" || row.Source != "protocol:est" {
		t.Fatalf("legacy-shaped row enrollment_protocol=%q source=%q", row.EnrollmentProtocol, row.Source)
	}
	if err := s.h.srv.estMTLSClientCertificate(servedTestTenant)(t.Context(), legacy.der); err != nil {
		t.Fatalf("an EST leaf whose ledger row records its EST mint was refused: %v", err)
	}
	s.recordedBeforeTheEnrollmentPathWasKept(t, legacyUnminted)
	if err := s.h.store.WithTenant(t.Context(), servedTestTenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `UPDATE ca_issued_certs SET issuance_event_id=NULL, issuance_event_type=NULL
			WHERE tenant_id=$1 AND ca_id=$2 AND serial=$3`, servedTestTenant, IssuingCAID(), legacyUnminted.info.SerialNumber)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("ledger mint rewrite touched %d rows", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.h.srv.estMTLSClientCertificate(servedTestTenant)(t.Context(), legacyUnminted.der); err == nil {
		t.Fatal("the gate admitted an EST-sourced leaf whose ledger row predates mint records")
	}
	s.refusedRenewal(t, "an EST-sourced leaf whose ledger row predates mint records", legacyUnminted, servedTestTenant)
}

// CR-059: a leaf another enrollment path issued from the same platform CA into
// the same tenant, in good standing, renews nothing here: the gate admits only
// what EST enrollment issued. For a row recorded before the enrollment path was
// kept, the source label proves nothing, since an import may relabel it; the
// CA ledger's mint record decides. A leaf the factory EST route issued renews.
func TestServedESTMTLSRenewsOnlyLeavesESTEnrollmentIssuedCR059(t *testing.T) {
	bootDER, keyCMP, csrCMP := newSCEPClient(t, "cmp-device-a")
	s := newESTMTLSScope(t, config.Protocols{
		EST:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, bootDER),
	})
	cmpLeaf := s.cmpEnroll(t, bootDER, keyCMP, csrCMP, "cr059-txn-a")
	s.issuance(t)
	if row := s.inventoryRow(t, servedTestTenant, cmpLeaf); row.EnrollmentProtocol != "cmp" || row.Status == "revoked" {
		t.Fatalf("CMP fixture row enrollment_protocol=%q status=%q", row.EnrollmentProtocol, row.Status)
	}
	if got := servedOCSPStatus(t, s.h.srv, servedTestTenant, cmpLeaf.der, s.h.caPEM); got != crypto.OCSPGood {
		t.Fatalf("OCSP for the CMP leaf = %q, want good", got)
	}
	s.refusedRenewal(t, "a CMP leaf of this tenant", cmpLeaf, servedTestTenant)
	s.renew(t, "a leaf the factory EST route issued", s.factoryEnroll(t))

	// Last, because a write outside the projector stops further certificate
	// recording in the tenant until a rebuild.
	importer := seedScopedToken(t, s.h.store, servedTestTenant, "certs:write")
	if status, raw := secretsReqKey(t, s.h, http.MethodPost, "/api/v1/certificates", importer, "cr059-relabel-cmp-leaf",
		map[string]any{"pem": certificatePEM(cmpLeaf.der), "source": "protocol:est"}); status != http.StatusCreated {
		t.Fatalf("re-import the CMP leaf: %d %s", status, raw)
	}
	s.issuance(t)
	s.recordedBeforeTheEnrollmentPathWasKept(t, cmpLeaf)
	if row := s.inventoryRow(t, servedTestTenant, cmpLeaf); row.Source != "protocol:est" || row.EnrollmentProtocol != "" {
		t.Fatalf("relabeled row source=%q enrollment_protocol=%q", row.Source, row.EnrollmentProtocol)
	}
	if err := s.h.srv.estMTLSClientCertificate(servedTestTenant)(t.Context(), cmpLeaf.der); err == nil {
		t.Fatal("the gate admitted a CMP leaf relabeled with the EST source")
	}
	s.refusedRenewal(t, "a CMP leaf relabeled with the EST source and recorded before the path was kept", cmpLeaf, servedTestTenant)
}

// factoryEnroll provisions one device through a factory batch and returns the
// operational certificate its first boot obtained on the factory EST route.
func (s *estMTLSScope) factoryEnroll(t *testing.T) estClientLeaf {
	t.Helper()
	station := mintFactoryStation(t, s.h)
	code, body := doBearer(t, s.h.ts, http.MethodPost, "/api/v1/edge/factory-batches", station.operator, "cr059-batch", map[string]any{
		"delegation_id": station.delegationID, "label": "cr059 lot", "quota": 1, "birth_ttl_seconds": 3600,
	})
	var batch struct {
		ID string `json:"id"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &batch) != nil || batch.ID == "" {
		t.Fatalf("create the batch = %d %s", code, body)
	}
	name := "sn-0001." + station.permittedNames
	birthKey, birthCSR := estScopeCSR(t, name, nil)
	birth, err := crypto.IssueEdgeLeafWithKeyHandle(t.Context(), station.delegationPEM, station.handle, station.provider,
		crypto.EdgeLeafRequest{CommonName: name, TTL: time.Hour, CSRDER: birthCSR, ClientAuthOnly: true}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	birthInfo, err := certinfo.Inspect(birth.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	code, body = doBearer(t, s.h.ts, http.MethodPost, "/api/v1/edge/factory-batches/"+batch.ID+"/reconcile", station.operator, "cr059-reconcile",
		map[string]any{"host": "line-1-station", "batch_id": batch.ID, "certificates_pem": []string{certificatePEM(birth.CertificateDER)}})
	if code != http.StatusOK {
		t.Fatalf("reconcile = %d %s", code, body)
	}
	opKey, opCSR := estScopeCSR(t, name, []string{name})
	proof, err := crypto.SignJWT(birthKey, birthInfo.SHA256Fingerprint, FactoryProofClaims{Subject: name, Purpose: factoryPurposeFirstBoot,
		CSRSHA256: crypto.SHA256Hex(opCSR), IssuedAt: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	opDER := estEnroll(t, s.main.Client(), s.main.URL+"/.well-known/est/factory/simpleenroll", proof, opCSR, http.StatusOK)
	opPKCS8, err := opKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	leaf := s.present(t, opDER, opPKCS8)
	s.issuance(t)
	if row := s.inventoryRow(t, servedTestTenant, leaf); row.EnrollmentProtocol != "est" {
		t.Fatalf("factory leaf enrollment_protocol=%q, want est", row.EnrollmentProtocol)
	}
	return leaf
}

// CR-059: the gate fails closed: no tenant, another tenant, an unreadable
// certificate or a store error refuses, and the mount's own active EST leaf
// passes.
func TestServedESTMTLSClientCertificateGateFailsClosedCR059(t *testing.T) {
	s := newESTMTLSScope(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	own := s.enroll(t, "gate.est.test")
	s.issuance(t)
	gate := s.h.srv.estMTLSClientCertificate
	if err := gate(servedTestTenant)(t.Context(), own.der); err != nil {
		t.Fatalf("the mount's own active EST leaf was refused: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for why, check := range map[string]func() error{
		"no tenant":          func() error { return gate("")(t.Context(), own.der) },
		"a blank tenant":     func() error { return gate("  ")(t.Context(), own.der) },
		"another tenant":     func() error { return gate("22222222-2222-4222-8222-2222222222c9")(t.Context(), own.der) },
		"not a certificate":  func() error { return gate(servedTestTenant)(t.Context(), []byte("not a certificate")) },
		"a store read error": func() error { return gate(servedTestTenant)(canceled, own.der) },
	} {
		if err := check(); err == nil {
			t.Errorf("%s: the gate admitted the leaf", why)
		}
	}
}
