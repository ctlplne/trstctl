// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package conformance

import (
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	eereconcile "trstctl.com/trstctl/internal/reconcile"
	corestore "trstctl.com/trstctl/internal/store"
)

// TestE2E_RecoveredCertificateBytesJoinTheInventoryAuthority is A215's
// acceptance on the production reducers: a scanned inventory row of an
// internal CA's leaf records no bytes, so the inventory authority cannot name
// the serial the CA ledger asserts; once certificate.der.recovered attaches
// the bytes (checked against the row's fingerprint by the projection), the
// inventory authority names the same record the ledger does.
func TestE2E_RecoveredCertificateBytesJoinTheInventoryAuthority(t *testing.T) {
	h := newE2EHarness(t)
	caKey, caCert := e2eStoreCA(t, "a215 internal CA")
	serial := big.NewInt(0x2150)
	leaf := e2eStoreLeaf(t, caCert, caKey, serial, "recovered.internal.example")
	ca, err := h.store.InsertCAAuthority(h.ctx, corestore.CAAuthority{
		TenantID: h.tenant, CommonName: "a215 internal CA", Kind: "root", Status: "active",
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
		Serial:         "1", MaxPathLen: -1,
	})
	if err != nil {
		t.Fatalf("InsertCAAuthority: %v", err)
	}
	if err := h.store.RecordIssuedCert(h.ctx, h.tenant, ca.ID, serial.Text(16), time.Now().UTC()); err != nil {
		t.Fatalf("RecordIssuedCert: %v", err)
	}
	// What a network scan records: the certificate's details, not its bytes.
	project := func(eventType string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		e, err := h.log.Append(h.ctx, events.Event{Type: eventType, TenantID: h.tenant, Data: data})
		if err != nil {
			t.Fatalf("append %s: %v", eventType, err)
		}
		if err := projections.New(h.store).Apply(h.ctx, e); err != nil {
			t.Fatalf("project %s: %v", eventType, err)
		}
	}
	project(projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: "6f6c3b0a-1d2e-4f50-8a21-a215a215a215", Subject: "CN=recovered.internal.example", Serial: serial.Text(16),
		Issuer: "CN=a215 internal CA", Fingerprint: crypto.SHA256Hex(leaf), DeploymentLocation: "10.21.5.1:443",
		Source: "discovery:network",
	})
	row, err := h.store.GetCertificateByFingerprint(h.ctx, h.tenant, crypto.SHA256Hex(leaf))
	if err != nil {
		t.Fatalf("scanned row: %v", err)
	}

	rt, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{Store: h.store, Log: h.log})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	stableIDs := func(authority string) map[string]bool {
		t.Helper()
		observed, err := rt.Reducers.Observe(h.ctx, authority, h.tenant)
		if err != nil {
			t.Fatalf("observe %s: %v", authority, err)
		}
		out := map[string]bool{}
		for _, record := range observed.Set.Records {
			out[record.RecordKey.StableID] = true
		}
		return out
	}
	want := e2eStableID(t, caCert, serial)
	if ledger := stableIDs("trstctl-ca"); !ledger[want] {
		t.Fatalf("the CA ledger does not assert the issued serial: %v", ledger)
	}
	if self := stableIDs("trstctl-self"); self[want] {
		t.Fatal("the inventory authority named a row it holds no bytes for")
	}

	project(projections.EventCertificateDERRecovered, projections.CertificateDERRecovered{CertificateID: row.ID,
		Fingerprint: row.Fingerprint, Method: corestore.DERRecoveredFromEndpoint, Evidence: "10.21.5.1:443", CertificateDER: leaf})
	if self := stableIDs("trstctl-self"); !self[want] {
		t.Fatalf("after recovery the inventory authority names %v; want the ledger's %s", self, want)
	}
}
