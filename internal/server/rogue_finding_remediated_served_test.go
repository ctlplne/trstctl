// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A163-L2: when the issuer confirms a rogue certificate's revocation, the CT
// finding it was requested for is resolved as remediated, with the
// confirmation as the evidence of the fix, so an operator no longer resolves
// it by hand. A redelivery of the confirmed revocation changes nothing more,
// and a finding an operator dismissed before the issuer confirmed keeps that
// decision. Before, the finding stayed open after the revocation.
func TestServedConfirmedRogueRevocationRemediatesItsFindingA163L2(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	digi := digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: "corp-digicert", Type: "digicert", Name: "Corp DigiCert", CA: digi}}
	})
	registerServedTenant(t, h, "Rogue remediation tenant")
	ctx := t.Context()
	shadowFinding := func(name string) (string, certinfo.Info) {
		t.Helper()
		shadow, err := digi.Issue(ctx, ca.IssueRequest{TenantID: h.tenant, CSR: serverTestCSR(t, name, nil), DNSNames: []string{name}, TTL: 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(shadow.CertificatePEM)
		if err != nil {
			t.Fatal(err)
		}
		return seedRogueCTFinding(t, h, info), info
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	revoke := func(findingID, key string) orchestrator.Message {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/revocation/rogue-certificates/revoke", token, key,
			map[string]any{"discovery_id": findingID, "authority_id": "corp-digicert", "reason": "keyCompromise"}); status != http.StatusAccepted {
			t.Fatalf("revoke %s at its issuer = %d %s", findingID, status, body)
		}
		pending, err := h.srv.outbox.Pending(ctx, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pending {
			if r.Destination == "revocation.publish" && strings.Contains(string(r.Payload), findingID) {
				return orchestrator.Message{ID: r.ID, TenantID: h.tenant, Destination: r.Destination, Payload: r.Payload, IdempotencyKey: r.IdempotencyKey}
			}
		}
		t.Fatalf("no revocation.publish delivery for %s", findingID)
		return orchestrator.Message{}
	}
	// An open finding: confirmed at the issuer, it reads remediated, by
	// trstctl, with the confirmation as evidence.
	openID, openInfo := shadowFinding("open.corp.example")
	if f, err := h.store.GetDiscoveryFinding(ctx, h.tenant, openID); err != nil || f.TriageStatus != "unmanaged" {
		t.Fatalf("a fresh CT finding's triage = %q %v", f.TriageStatus, err)
	}
	message := revoke(openID, "a163l2-open")
	if f, _ := h.store.GetDiscoveryFinding(ctx, h.tenant, openID); f.TriageStatus != "unmanaged" {
		t.Fatalf("the finding's triage before the issuer confirms = %q; want still unmanaged", f.TriageStatus)
	}
	if err := dispatcher.Deliver(ctx, message); err != nil {
		t.Fatalf("deliver the revocation: %v", err)
	}
	remediated, err := h.store.GetDiscoveryFinding(ctx, h.tenant, openID)
	if err != nil || remediated.TriageStatus != "remediated" || remediated.TriageActor != "trstctl" ||
		!strings.HasPrefix(remediated.TriageEvidenceRef, "rogue.revoked-at-issuer:") ||
		!strings.Contains(remediated.TriageReason, "corp-digicert") || !strings.Contains(remediated.TriageReason, openInfo.SerialNumber) {
		t.Fatalf("after the issuer confirmed, the finding reads %+v (%v); want remediated by trstctl with the confirmation as evidence", remediated, err)
	}
	// The remediation has an identity of its own: a redelivery records
	// nothing more, so the triage keeps its time.
	if err := dispatcher.Deliver(ctx, message); err != nil {
		t.Fatalf("redeliver the confirmed revocation: %v", err)
	}
	if again, err := h.store.GetDiscoveryFinding(ctx, h.tenant, openID); err != nil || again.TriageStatus != "remediated" ||
		again.TriagedAt == nil || remediated.TriagedAt == nil || !again.TriagedAt.Equal(*remediated.TriagedAt) {
		t.Fatalf("after a redelivery the finding reads %+v (%v); want the same remediation", again, err)
	}

	// A finding an operator dismissed keeps the operator's decision.
	dismissedID, _ := shadowFinding("dismissed.corp.example")
	dismissing := revoke(dismissedID, "a163l2-dismissed")
	if _, err := h.srv.orch.DismissDiscoveryFinding(ctx, h.tenant, dismissedID, "a test certificate we expected", nil); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Deliver(ctx, dismissing); err != nil {
		t.Fatalf("deliver the second revocation: %v", err)
	}
	if f, err := h.store.GetDiscoveryFinding(ctx, h.tenant, dismissedID); err != nil || f.TriageStatus != "dismissed" ||
		f.TriageReason != "a test certificate we expected" {
		t.Fatalf("a dismissed finding after its revocation was confirmed = %+v (%v); want the operator's dismissal kept", f, err)
	}
	if got := rogueIssuerRevocationOf(t, h, token, dismissedID); got == nil || got.Status != "revoked" {
		t.Fatalf("the dismissed finding's revocation = %+v; want revoked at the issuer", got)
	}
}
