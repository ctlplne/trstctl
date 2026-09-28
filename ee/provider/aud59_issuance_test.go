// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// Invoice restart proof needs actual certificate facts, not SQL rows claiming
// that an identity entered issued. Event timestamps are fixture data only.
func aud59IssuanceRecorder(t *testing.T, st *corestore.Store, tenant string) func(time.Time) {
	t.Helper()
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registration, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenant, Data: []byte(`{"name":"invoice-restart-fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, registration); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil)
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	root, err := crypto.SelfSignedCACert(ca, "invoice-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return func(at time.Time) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "invoice.example.test"}, key)
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.SignLeafFromCSR(root, ca, csr, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(der)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(projections.CertificateRecorded{
			ID: uuid.NewString(), Source: "issued", Fingerprint: info.SHA256Fingerprint,
			Subject: info.Subject, Issuer: info.Issuer, Serial: info.SerialNumber,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
			CertificateDER: der, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			IssuanceIdempotencyKey: "issue:transition:" + uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := orch.RecordCertificateEvent(ctx, events.Event{ID: events.NewID(),
			Type: projections.EventCertificateRecorded, TenantID: tenant, Time: at, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
}
