// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/ca/awspca/awspcafake"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/ca/gcpcas"
	"trstctl.com/trstctl/internal/ca/gcpcas/gcpcasfake"
	"trstctl.com/trstctl/internal/ca/sectigo"
	"trstctl.com/trstctl/internal/ca/sectigo/sectigofake"
	"trstctl.com/trstctl/internal/ca/smallstep"
	"trstctl.com/trstctl/internal/ca/smallstep/smallstepfake"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/ca/venafi/venafifake"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// vendorRevocation is one upstream issuer under test: its plugin, and how many
// certificates its stand-in has revoked.
type vendorRevocation struct {
	id, typ string
	plugin  ca.CA
	revoked func() int
}

func vendorRevocationStandIns(t *testing.T) []vendorRevocation {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	sc, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	vn, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vn.Close)
	ss, err := smallstepfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Close)
	aws, err := awspcafake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	cas, err := gcpcasfake.NewAPI()
	if err != nil {
		t.Fatal(err)
	}
	return []vendorRevocation{
		{"rev-digicert", "digicert", digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(client)),
			func() int { return len(dc.Revocations()) }},
		{"rev-sectigo", "sectigo", sectigo.New(sectigo.Config{Name: "sectigo", BaseURL: sc.URL(), Login: sc.Login(), Password: []byte(sc.Password()), CustomerURI: sc.CustomerURI()}, sectigo.WithHTTPClient(client)),
			func() int { return len(sc.Revocations()) }},
		{"rev-venafi", "venafi", venafi.New(venafi.Config{Name: "venafi", BaseURL: vn.URL(), AccessToken: []byte(vn.Token()), PolicyDN: vn.PolicyDN()}, venafi.WithHTTPClient(client)),
			func() int { return len(vn.Revocations()) }},
		{"rev-smallstep", "smallstep", smallstep.New(smallstep.Config{Name: "smallstep", BaseURL: ss.URL(), ProvisionerName: ss.ProvisionerName(), ProvisionerKey: ss.ProvisionerKey()}, smallstep.WithHTTPClient(client)),
			func() int { return ss.RevokedCount() }},
		{"rev-awspca", "awspca", awspca.New(awspca.Config{Name: "aws-private-ca", CertificateAuthorityArn: aws.CAArn()}, aws),
			func() int { return len(aws.Revocations()) }},
		{"rev-gcpcas", "gcpcas", gcpcas.New(gcpcas.Config{Name: "gcp-cas", CaPool: cas.CaPool()}, cas),
			func() int { return len(cas.Revocations()) }},
	}
}

// recordVendorIssuedLeaf records a certificate an upstream issuer issued, the
// way an issuance through that external CA records it.
func recordVendorIssuedLeaf(t *testing.T, h *issuanceDispatcherHarness, authorityID, owner string, issued ca.Certificate) store.Certificate {
	t.Helper()
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	der, err := certinfo.LeafDER(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	key := "a164:" + authorityID
	c := store.Certificate{OwnerID: &owner, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		Source: "external-ca:" + authorityID, CertificateDER: der, CertificatePEM: issued.CertificatePEM, IssuanceIdempotencyKey: "external-test:" + key}
	fact := projections.CertificateRecorded{ID: uuid.NewString(), Source: c.Source, Subject: c.Subject, SANs: c.SANs, Issuer: c.Issuer,
		Serial: c.Serial, Fingerprint: c.Fingerprint, KeyAlgorithm: c.KeyAlgorithm, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
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
	c.Source, c.IssuanceIdempotencyKey = "issued", "agentcsr:"+key
	recorded, err := h.orch.RecordCertificate(t.Context(), h.tenant, c)
	if err != nil {
		t.Fatal(err)
	}
	return recorded
}

// A164 / P2 Done-when: for each issuer, a revoke with a reason reaches the
// vendor's API and the certificate shows revoked in inventory; retrying the
// same revoke changes nothing.
func TestServedRevocationReachesEachVendorAndShowsInInventory(t *testing.T) {
	vendors := vendorRevocationStandIns(t)
	h, token, _ := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		for _, v := range vendors {
			d.ExternalCAs = append(d.ExternalCAs, ExternalCA{ID: v.id, Type: v.typ, Name: v.typ + " (stand-in)", CA: v.plugin})
		}
	})
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	ctx := t.Context()
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "Vendor revocation", "")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(vendors))
	byID := map[string]vendorRevocation{}
	for _, v := range vendors {
		name := "svc." + v.typ + ".test"
		issued, err := v.plugin.Issue(ctx, ca.IssueRequest{TenantID: h.tenant, CSR: serverTestCSR(t, name, nil), DNSNames: []string{name}, TTL: 24 * time.Hour})
		if err != nil {
			t.Fatalf("%s issue: %v", v.typ, err)
		}
		recorded := recordVendorIssuedLeaf(t, i, v.id, owner.ID, issued)
		ids = append(ids, recorded.ID)
		byID[recorded.ID] = v
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "a164-vendors",
		map[string]any{"certificate_ids": ids, "reason": "keyCompromise"})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_queued":6`)) {
		t.Fatalf("bulk revoke across six vendors = %d %s; want all six queued for their issuers", status, raw)
	}
	pending, err := h.srv.outbox.Pending(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	var messages []orchestrator.Message
	for _, row := range pending {
		if row.Destination == "revocation.publish" {
			messages = append(messages, orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey})
		}
	}
	if len(messages) != len(vendors) {
		t.Fatalf("external revocation commands = %d; want one per vendor", len(messages))
	}
	for round := 1; round <= 2; round++ {
		for _, m := range messages {
			if err := dispatcher.Deliver(ctx, m); err != nil {
				t.Fatalf("delivery round %d: %v", round, err)
			}
		}
		for id, v := range byID {
			if n := v.revoked(); n != 1 {
				t.Fatalf("after round %d %s's API revoked %d certificates; want exactly one", round, v.typ, n)
			}
			current, err := h.store.GetCertificate(ctx, h.tenant, id)
			if err != nil || current.Status != "revoked" || current.RevocationReason != "keyCompromise" {
				t.Fatalf("after round %d the %s certificate is %s/%s %v; want revoked/keyCompromise", round, v.typ, current.Status, current.RevocationReason, err)
			}
		}
	}
}
