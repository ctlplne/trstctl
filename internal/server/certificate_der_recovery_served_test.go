// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// derRecoveryLeaf is a leaf of a tenant CA and the listener that serves it.
type derRecoveryLeaf struct {
	caID     string
	der      []byte
	info     certinfo.Info
	listener *tlsprobe.ServingTestServer
}

// newDERRecoveryLeaf makes an internal CA of the tenant (in reconciliation's
// jurisdiction), records a serial it issued in the CA ledger, and serves the
// leaf with its CA at a loopback listener.
func newDERRecoveryLeaf(t *testing.T, h *servedHarness, cn string) derRecoveryLeaf {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, cn+" CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, crypto.LeafProfile{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := leafKey.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tlsprobe.NewServingTestServerChain([][]byte{leafDER, caDER}, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(listener.Close)
	ca, err := h.store.InsertCAAuthority(t.Context(), store.CAAuthority{
		TenantID: h.tenant, CommonName: cn + " CA", Kind: "root", Status: "active",
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), Serial: "1", MaxPathLen: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RecordIssuedCert(t.Context(), h.tenant, ca.ID, info.SerialNumber, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return derRecoveryLeaf{caID: ca.ID, der: leafDER, info: info, listener: listener}
}

// recordScannedRow records what a network scan records about a certificate:
// its details and where it was seen, without its bytes.
func recordScannedRow(t *testing.T, h *servedHarness, info certinfo.Info, location string) store.Certificate {
	t.Helper()
	row, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
		Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore,
		NotAfter: &info.NotAfter, DeploymentLocation: location, Source: "discovery:network", Status: "active",
	})
	if err != nil {
		t.Fatalf("record scanned row: %v", err)
	}
	return row
}

type derRecoveryAnswer struct {
	Outcome  string `json:"outcome"`
	Method   string `json:"method"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`
}

func recoverDER(t *testing.T, h *servedHarness, token, key, certificateID string, body map[string]any) derRecoveryAnswer {
	t.Helper()
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/"+certificateID+"/der-recovery", token, key, body)
	if status != http.StatusOK {
		t.Fatalf("der recovery = %d %s", status, raw)
	}
	var out derRecoveryAnswer
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A215: a scanned row of an internal CA's leaf records no bytes; recovering
// them from the endpoint it records attaches exactly the served leaf, whose
// issuer name and serial are the identity reconciliation compares (the
// reconcile conformance suite proves the row then joins the comparison). An
// endpoint serving another certificate attaches nothing.
func TestServedCertificateDERRecoveredFromTheEndpoint(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", string(authz.PrivateEgress))
	leaf := newDERRecoveryLeaf(t, h, "recover.a215.example")
	row := recordScannedRow(t, h, leaf.info, leaf.listener.Addr)

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+row.ID, token, nil)
	var before struct {
		CertificateBytesHeld bool `json:"certificate_bytes_held"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &before) != nil || before.CertificateBytesHeld {
		t.Fatalf("scanned row detail = %d %s; want no bytes held", status, body)
	}

	egress := map[string]any{"method": "endpoint", "allow_private_endpoint": true,
		"private_egress_cidrs": []string{serviceNowSinkCIDR(t, "https://"+leaf.listener.Addr)}}
	got := recoverDER(t, h, token, "a215-endpoint", row.ID, egress)
	if got.Outcome != "recovered" || got.Method != "endpoint" || got.Evidence != leaf.listener.Addr {
		t.Fatalf("endpoint recovery = %+v; want recovered from the listener", got)
	}
	if replay := recoverDER(t, h, token, "a215-endpoint", row.ID, egress); replay != got {
		t.Fatalf("replay = %+v; want %+v", replay, got)
	}
	stored, err := h.store.GetCertificate(ctx, h.tenant, row.ID)
	if err != nil || !bytes.Equal(stored.CertificateDER, leaf.der) || stored.Source != "discovery:network" ||
		stored.DeploymentLocation != leaf.listener.Addr {
		t.Fatalf("row after recovery holds %d bytes (%v), source %q; want the served leaf and nothing else changed",
			len(stored.CertificateDER), err, stored.Source)
	}
	if _, serial, err := crypto.CertificateIssuerAndSerial(stored.CertificateDER); err != nil || serial != leaf.info.SerialNumber {
		t.Fatalf("recovered bytes name serial %q (%v); want the CA ledger's %q", serial, err, leaf.info.SerialNumber)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+row.ID, token, nil)
	var detail struct {
		CertificateBytesHeld bool `json:"certificate_bytes_held"`
		DERRecovery          *struct {
			Method   string `json:"method"`
			Evidence string `json:"evidence"`
		} `json:"der_recovery"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &detail) != nil || !detail.CertificateBytesHeld ||
		detail.DERRecovery == nil || detail.DERRecovery.Method != "endpoint" || detail.DERRecovery.Evidence != leaf.listener.Addr {
		t.Fatalf("certificate detail = %d %s; want the bytes held and where they came from", status, body)
	}
	if again := recoverDER(t, h, token, "a215-again", row.ID, egress); again.Outcome != "already_held" {
		t.Fatalf("a second recovery = %+v; want already_held", again)
	}

	other := newDERRecoveryLeaf(t, h, "other.a215.example")
	elsewhere := recordScannedRow(t, h, other.info, leaf.listener.Addr)
	if got := recoverDER(t, h, token, "a215-mismatch", elsewhere.ID, egress); got.Outcome != "mismatch" {
		t.Fatalf("recovery from an endpoint serving another certificate = %+v; want mismatch", got)
	}
	if stored, _ := h.store.GetCertificate(ctx, h.tenant, elsewhere.ID); len(stored.CertificateDER) != 0 {
		t.Fatal("a mismatched endpoint attached bytes")
	}
}

// A215: a mint of the tenant's CA that retained the certificate gives a
// scanned row its bytes by serial, checked against the row's fingerprint; a
// serial no mint retained finds nothing.
func TestServedCertificateDERRecoveredFromTheCALedger(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	leaf := newDERRecoveryLeaf(t, h, "ledger.a215.example")
	// The responder form of a managed CA mint: the public leaf and its serial,
	// with no inventory row of its own.
	payload, err := json.Marshal(map[string]any{
		"ca_id": leaf.caID, "serial": leaf.info.SerialNumber, "issued_at": time.Now().UTC(), "source": "acme",
		"certificate_der": leaf.der, "fingerprint": leaf.info.SHA256Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	mint, err := h.log.Append(ctx, events.Event{TenantID: h.tenant, Type: projections.EventCAEndEntityIssued,
		SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	row := recordScannedRow(t, h, leaf.info, "/etc/nginx/ledger.a215.crt")
	got := recoverDER(t, h, token, "a215-ledger", row.ID, map[string]any{"method": "ca_ledger"})
	if got.Outcome != "recovered" || got.Evidence != mint.ID {
		t.Fatalf("ledger recovery = %+v; want recovered from mint %s", got, mint.ID)
	}
	if stored, err := h.store.GetCertificate(ctx, h.tenant, row.ID); err != nil || !bytes.Equal(stored.CertificateDER, leaf.der) {
		t.Fatalf("row after ledger recovery holds %d bytes (%v)", len(stored.CertificateDER), err)
	}

	unminted := newDERRecoveryLeaf(t, h, "unminted.a215.example")
	bare := recordScannedRow(t, h, unminted.info, "/etc/nginx/unminted.a215.crt")
	if got := recoverDER(t, h, token, "a215-unminted", bare.ID, map[string]any{"method": "ca_ledger"}); got.Outcome != "not_found" {
		t.Fatalf("ledger recovery without a retaining mint = %+v; want not_found", got)
	}
	if got := recoverDER(t, h, token, "a215-no-endpoint", bare.ID, map[string]any{"method": "endpoint"}); got.Outcome != "not_found" {
		t.Fatalf("endpoint recovery for a path location = %+v; want not_found", got)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/"+bare.ID+"/der-recovery", token, "a215-bad",
		map[string]any{"method": "guess"}); status != http.StatusBadRequest {
		t.Fatalf("an unknown method = %d %s; want 400", status, body)
	}
}
