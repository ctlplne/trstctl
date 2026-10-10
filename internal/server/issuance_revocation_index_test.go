// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestRevocationOriginIndexedSourceAcrossColdRestart(t *testing.T) {
	ctx := t.Context()
	const tenant = "11111111-1111-4111-8111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Error(err)
		}
	}()
	issued, err := testExternalCACertificate(ca.IssueRequest{
		CSR:      serverTestCSR(t, "revocation-index.example.test", nil),
		DNSNames: []string{"revocation-index.example.test"}}, "Independent revocation CA")
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
	selected := store.Certificate{ID: uuid.NewString(), CertificateDER: der,
		Fingerprint: info.SHA256Fingerprint, Serial: info.SerialNumber}
	appendFact := func(tenantID, authority, key string) {
		t.Helper()
		fact := projections.CertificateRecorded{Source: "external-ca:" + authority,
			Fingerprint: selected.Fingerprint, Serial: selected.Serial,
			CertificateDER: der, IssuanceIdempotencyKey: key,
			IssuanceRequestBinding: strings.Repeat("a", 64)}
		data, err := json.Marshal(fact)
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantID+"\x00certificate.recorded\x00"+key)).String()
		if _, err := log.Append(ctx, events.Event{ID: id, TenantID: tenantID,
			Type: projections.EventCertificateRecorded, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		if _, err := log.Append(ctx, events.Event{TenantID: tenant, Type: "unrelated.event", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	appendFact("22222222-2222-4222-8222-222222222222", "other-tenant-ca", "cross-tenant")
	d := &issuanceDispatcher{log: log}
	if _, err := d.certificateRevocationOrigins(ctx, tenant, []store.Certificate{selected}); err == nil ||
		!strings.Contains(err.Error(), "no verified supported issuing authority") {
		t.Fatalf("cross-tenant fact supplied revocation authority: %v", err)
	}
	appendFact(tenant, "selected-ca", "exact-issuance")
	check := func() {
		t.Helper()
		origins, err := d.certificateRevocationOrigins(ctx, tenant, []store.Certificate{selected})
		if err != nil || origins[selected.Fingerprint] != (certificateRevocationOrigin{ExternalID: "selected-ca"}) {
			t.Fatalf("indexed origin = %+v, error=%v", origins, err)
		}
	}
	check()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.log = log
	check()
	appendFact(tenant, "conflicting-ca", "different-issuance")
	if _, err := d.certificateRevocationOrigins(ctx, tenant, []store.Certificate{selected}); err == nil ||
		!strings.Contains(err.Error(), "conflicting retained issuing authorities") {
		t.Fatalf("conflicting retained issuer was accepted: %v", err)
	}
}
