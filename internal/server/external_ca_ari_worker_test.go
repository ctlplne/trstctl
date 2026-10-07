// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/store"
)

func TestExternalARIWorkerBindsExactLeafAndReplaysCanonicalOutcome(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	issued, err := testExternalCACertificate(ca.IssueRequest{
		CSR:      serverTestCSR(t, "ari-worker.example.test", nil),
		DNSNames: []string{"ari-worker.example.test"}, TTL: 24 * time.Hour,
	}, "ARI worker test CA")
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
	ariID, err := certinfo.ARICertID(der)
	if err != nil {
		t.Fatal(err)
	}
	externalKey := "ari-worker-upstream-issue"
	externalFact := projections.CertificateRecorded{
		ID: uuid.NewString(), Subject: info.Subject, SANs: info.DNSNames,
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		Source: "external-ca:pebble", CertificateDER: der, CertificatePEM: issued.CertificatePEM,
		IssuanceIdempotencyKey: externalKey, IssuanceRequestBinding: strings.Repeat("a", 64),
	}
	data, err := json.Marshal(externalFact)
	if err != nil {
		t.Fatal(err)
	}
	externalEvent, err := h.log.Append(ctx, events.Event{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(h.tenant+"\x00certificate.recorded\x00"+externalKey)).String(),
		Type: projections.EventCertificateRecorded, TenantID: h.tenant, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(h.store)
	if err := projector.Apply(ctx, externalEvent); err != nil {
		t.Fatal(err)
	}
	// The endpoint lifecycle now records the same leaf under mutable source
	// "issued". That second event must not erase the authenticated issuer.
	endpointFact := externalFact
	endpointFact.ID = uuid.NewString()
	endpointFact.Source = "issued"
	endpointFact.IssuanceIdempotencyKey = "issue:transition:ari-worker"
	endpointFact.IssuanceRequestBinding = ""
	data, err = json.Marshal(endpointFact)
	if err != nil {
		t.Fatal(err)
	}
	endpointEvent, err := h.log.Append(ctx, events.Event{
		Type: projections.EventCertificateRecorded, TenantID: h.tenant, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, endpointEvent); err != nil {
		t.Fatal(err)
	}
	cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint)
	if err != nil || cert.Source != "issued" || cert.IssuingExternalCAID != "pebble" {
		t.Fatalf("external issuer did not survive endpoint recording: %+v err=%v", cert, err)
	}
	request := projections.ACMEUpstreamARIRequested{
		CertificateID: cert.ID, AuthorityID: "pebble",
		ARICertificateID: ariID, Fingerprint: cert.Fingerprint,
	}
	data, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	event, err := h.log.Append(ctx, events.Event{
		Type: projections.EventACMEUpstreamARIRequested, TenantID: h.tenant, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	readMessage := func(after int64) orchestrator.Message {
		t.Helper()
		var m orchestrator.Message
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT id, destination, payload, idempotency_key,
				required_agent_role FROM outbox WHERE tenant_id=$1 AND destination=$2
				AND id>$3 ORDER BY id LIMIT 1`, h.tenant, store.ACMEUpstreamARIFetchDestination, after).
				Scan(&m.ID, &m.Destination, &m.Payload, &m.IdempotencyKey, &m.RequiredAgentRole)
		}); err != nil {
			t.Fatal(err)
		}
		m.TenantID, m.Attempts = h.tenant, 1
		return m
	}
	first := readMessage(0)
	if first.RequiredAgentRole != "control_plane" {
		t.Fatalf("ARI command role = %q", first.RequiredAgentRole)
	}
	start, end := time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2*time.Hour)
	calls, fail := 0, false
	h.handler.externalCAs = &externalCARegistry{byID: map[string]externalCAEntry{
		"pebble": {
			meta: api.ExternalCA{ID: "pebble", Type: "letsencrypt"}, tenantID: h.tenant,
			ariFetch: func(context.Context, string) (ari.RenewalInfo, time.Duration, error) {
				calls++
				if fail {
					return ari.RenewalInfo{}, 0, errors.New("private upstream diagnostic must not be retained")
				}
				return ari.RenewalInfo{SuggestedWindow: ari.Window{Start: start, End: end}}, 5 * time.Second, nil
			},
		},
	}}
	wrong := first
	wrong.Payload = []byte(`{"certificate_id":"` + cert.ID + `","authority_id":"pebble","ari_certificate_id":"` + ariID + `","fingerprint":"wrong"}`)
	if err := h.handler.deliver(ctx, wrong); err == nil || calls != 0 {
		t.Fatalf("misbound command reached upstream: err=%v calls=%d", err, calls)
	}
	if err := h.handler.deliver(ctx, first); err != nil {
		t.Fatal(err)
	}
	ready, err := h.store.GetACMEUpstreamARI(ctx, h.tenant, cert.ID)
	if err != nil || ready.Status != "ready" || ready.WindowStart == nil || !ready.WindowStart.Equal(start) ||
		ready.WindowEnd == nil || !ready.WindowEnd.Equal(end) ||
		ready.NextPollAt.Sub(ready.UpdatedAt) != time.Minute {
		t.Fatalf("CA result was not bounded/projected: %+v err=%v", ready, err)
	}
	first.Attempts = 2
	if err := h.handler.deliver(ctx, first); err != nil || calls != 1 {
		t.Fatalf("outbox retry did not replay canonical observation: err=%v calls=%d", err, calls)
	}
	second := readMessage(first.ID)
	fail = true
	if err := h.handler.deliver(ctx, second); err != nil {
		t.Fatal(err)
	}
	failed, err := h.store.GetACMEUpstreamARI(ctx, h.tenant, cert.ID)
	if err != nil || failed.Status != "error" || failed.ErrorClass != "upstream_unavailable" ||
		failed.WindowStart == nil || !failed.WindowStart.Equal(start) ||
		failed.WindowEnd == nil || !failed.WindowEnd.Equal(end) {
		t.Fatalf("upstream outage erased safe window or retained raw diagnostic: %+v err=%v", failed, err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.SetCertificateRevokedTx(ctx, tx, h.tenant, cert.Fingerprint, "compromised", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	third := readMessage(second.ID)
	if err := h.handler.deliver(ctx, third); err != nil || calls != 2 {
		t.Fatalf("revoked leaf initiated another upstream GET: err=%v calls=%d", err, calls)
	}
}
