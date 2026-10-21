// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
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

// A51: a discovered leaf with no authenticated issuer is matched to a
// configured ACME authority by its Authority Key Identifier against the
// authority's declared issuer key ids. The match queues the same upstream ARI
// fetch, the worker re-matches before the GET, the observation and posture
// carry the issuer_key_id provenance, a discovered leaf from an undeclared
// issuer is never polled, and a command that claims an authenticated issuer
// for a discovered leaf is refused.
func TestExternalARIDiscoveredLeafIsPolledByDeclaredIssuerKeyID(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	projector := projections.New(h.store)
	recordDiscovered := func(name, issuer string) (store.Certificate, string) {
		t.Helper()
		issued, err := testExternalCACertificate(ca.IssueRequest{
			CSR: serverTestCSR(t, name, nil), DNSNames: []string{name}, TTL: 24 * time.Hour,
		}, issuer)
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
		fact := projections.CertificateRecorded{
			ID: uuid.NewString(), Subject: info.Subject, SANs: info.DNSNames,
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
			Source: "discovery:network", CertificateDER: der, CertificatePEM: issued.CertificatePEM,
		}
		data, err := json.Marshal(fact)
		if err != nil {
			t.Fatal(err)
		}
		event, err := h.log.Append(ctx, events.Event{Type: projections.EventCertificateRecorded, TenantID: h.tenant, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
		cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint)
		if err != nil || cert.IssuingExternalCAID != "" {
			t.Fatalf("discovered leaf must carry no authenticated issuer: %+v err=%v", cert, err)
		}
		if info.AuthorityKeyID == "" {
			t.Fatal("fixture leaf carries no Authority Key Identifier")
		}
		return cert, info.AuthorityKeyID
	}
	matched, issuerKeyID := recordDiscovered("matched.discovered.test", "Declared Public Issuer")
	stranger, _ := recordDiscovered("stranger.discovered.test", "Undeclared Issuer")

	start, end := time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2*time.Hour)
	calls := 0
	h.handler.externalCAs = &externalCARegistry{byID: map[string]externalCAEntry{
		"public-acme": {
			meta: api.ExternalCA{ID: "public-acme", Type: "letsencrypt"}, tenantID: h.tenant,
			ariIssuerKeyIDs: map[string]struct{}{issuerKeyID: {}},
			ariFetch: func(context.Context, string) (ari.RenewalInfo, time.Duration, error) {
				calls++
				return ari.RenewalInfo{SuggestedWindow: ari.Window{Start: start, End: end}}, 0, nil
			},
		},
	}}
	server := &Server{store: h.store, log: h.log, proj: projector, externalCAs: h.handler.externalCAs}

	// Discovery matches the declared issuer and only it; a second sweep is quiet.
	for _, want := range []int{1, 0} {
		queued, err := server.discoverExternalARICandidates(ctx, time.Now().UTC())
		if err != nil || queued != want {
			t.Fatalf("discovered-leaf ARI discovery queued %d, want %d: %v", queued, want, err)
		}
	}
	requested, err := h.store.GetACMEUpstreamARI(ctx, h.tenant, matched.ID)
	if err != nil || requested.Status != "queued" || requested.AuthorityID != "public-acme" || requested.Provenance != store.ACMEUpstreamARIProvenanceIssuerKeyID {
		t.Fatalf("matched leaf request = %+v err=%v; want queued under public-acme with issuer_key_id provenance", requested, err)
	}
	if _, err := h.store.GetACMEUpstreamARI(ctx, h.tenant, stranger.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a discovered leaf from an undeclared issuer must not be polled: err=%v", err)
	}

	var m orchestrator.Message
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, destination, payload, idempotency_key, required_agent_role
			FROM outbox WHERE tenant_id=$1 AND destination=$2 ORDER BY id LIMIT 1`, h.tenant, store.ACMEUpstreamARIFetchDestination).
			Scan(&m.ID, &m.Destination, &m.Payload, &m.IdempotencyKey, &m.RequiredAgentRole)
	}); err != nil {
		t.Fatal(err)
	}
	m.TenantID, m.Attempts = h.tenant, 1
	var payload externalARIFetchPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil || payload.Provenance != projections.ACMEUpstreamARIProvenanceIssuerKeyID {
		t.Fatalf("outbox command payload = %s err=%v; want issuer_key_id provenance", m.Payload, err)
	}
	// A command that claims an authenticated issuer for this discovered leaf
	// is refused before any upstream GET.
	claimed := m
	payload.Provenance = ""
	claimed.Payload, _ = json.Marshal(payload)
	if err := h.handler.deliver(ctx, claimed); err == nil || calls != 0 {
		t.Fatalf("a discovered leaf under an authenticated-issuer claim reached upstream: err=%v calls=%d", err, calls)
	}
	// With the declaration withdrawn, the worker refuses the queued command.
	h.handler.externalCAs.byID["public-acme"] = func(e externalCAEntry) externalCAEntry { e.ariIssuerKeyIDs = nil; return e }(h.handler.externalCAs.byID["public-acme"])
	if err := h.handler.deliver(ctx, m); err == nil || calls != 0 {
		t.Fatalf("a withdrawn issuer key id still let the fetch through: err=%v calls=%d", err, calls)
	}
	h.handler.externalCAs.byID["public-acme"] = func(e externalCAEntry) externalCAEntry {
		e.ariIssuerKeyIDs = map[string]struct{}{issuerKeyID: {}}
		return e
	}(h.handler.externalCAs.byID["public-acme"])
	if err := h.handler.deliver(ctx, m); err != nil || calls != 1 {
		t.Fatalf("deliver matched command: err=%v calls=%d", err, calls)
	}
	ready, err := h.store.GetACMEUpstreamARI(ctx, h.tenant, matched.ID)
	if err != nil || ready.Status != "ready" || ready.WindowStart == nil || !ready.WindowStart.Equal(start) || ready.Provenance != store.ACMEUpstreamARIProvenanceIssuerKeyID {
		t.Fatalf("observation = %+v err=%v; want ready with the CA window and issuer_key_id provenance", ready, err)
	}

	posture, _, err := server.ACMEARIPosture(ctx, h.tenant, "", 100, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var seenMatched, seenStranger bool
	for _, item := range posture.Items {
		switch item.CertificateID {
		case matched.ID:
			seenMatched = true
			if item.UpstreamAuthorityID != "public-acme" || item.UpstreamProvenance != api.ACMEARIProvenanceIssuerKeyID ||
				item.UpstreamStatus != api.ACMEARIUpstreamReady || item.WindowSource != api.ACMEARIWindowUpstreamCA ||
				item.SuggestedWindow == nil || !item.SuggestedWindow.Start.Equal(start) {
				t.Fatalf("matched leaf posture = %+v; want the CA window labeled by issuer key id", item)
			}
		case stranger.ID:
			seenStranger = true
		}
	}
	// The ARI posture lists leaves with an upstream binding; a discovered leaf
	// no authority declares has none and stays off it rather than appearing
	// with an invented upstream state.
	if !seenMatched || seenStranger {
		t.Fatalf("posture listed matched=%v stranger=%v; want the matched leaf only", seenMatched, seenStranger)
	}
}
