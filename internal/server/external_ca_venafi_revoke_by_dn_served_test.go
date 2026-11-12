// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/ca/venafi/venafifake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

// OD-7 (A164-L2): under a Venafi policy that revokes only by the certificate
// object's DN, an authority configured with revoke_by certificate_dn revokes
// a certificate it issued: the revocation finds the object by the
// certificate's thumbprint, revokes it by that DN, and inventory shows it
// revoked; retrying changes nothing. The same certificate's revocation
// through a thumbprint-addressed authority is refused by that policy and is
// not counted revoked. The external CA list says how each revokes, and the
// configuration refuses revoke_by anywhere but a Venafi authority.
func TestServedVenafiRevokesByCertificateDNOD7(t *testing.T) {
	for name, bad := range map[string]config.ExternalCAConfig{
		"revoke_by on digicert": {Type: "digicert", RevokeBy: "certificate_dn"},
		"unknown revoke_by":     {Type: "venafi", RevokeBy: "serial"},
	} {
		bad.ID, bad.Name, bad.Endpoint = "x", "x", "https://ca.example.test"
		if err := config.ValidateExternalCAs([]config.ExternalCAConfig{bad}); err == nil || !strings.Contains(err.Error(), "revoke_by") {
			t.Fatalf("%s = %v, want revoke_by refused", name, err)
		}
	}
	vn, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vn.Close)
	vn.RevokeByDNOnly()
	client := &http.Client{Timeout: 5 * time.Second}
	byDN := venafi.New(venafi.Config{Name: "venafi", BaseURL: vn.URL(), AccessToken: []byte(vn.Token()), PolicyDN: vn.PolicyDN(),
		RevokeBy: venafi.RevokeByCertificateDN}, venafi.WithHTTPClient(client))
	byThumbprint := venafi.New(venafi.Config{Name: "venafi", BaseURL: vn.URL(), AccessToken: []byte(vn.Token()), PolicyDN: vn.PolicyDN()},
		venafi.WithHTTPClient(client))
	h, token, _ := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.ExternalCAs = append(d.ExternalCAs,
			ExternalCA{ID: "venafi-dn", Type: "venafi", Name: "Venafi (by DN)", CA: byDN, RevokeBy: "certificate_dn"},
			ExternalCA{ID: "venafi-thumb", Type: "venafi", Name: "Venafi (by thumbprint)", CA: byThumbprint, RevokeBy: "thumbprint"})
	})
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	ctx := t.Context()
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "Venafi DN revocation", "")
	if err != nil {
		t.Fatal(err)
	}

	// The external CA list says how each authority revokes.
	reader := seedScopedToken(t, h.store, h.tenant, "issuers:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/external-cas", reader, nil)
	var list struct {
		Items []struct {
			ID       string `json:"id"`
			RevokeBy string `json:"revoke_by"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &list) != nil {
		t.Fatalf("external CA list: %d %s", status, raw)
	}
	revokeBy := map[string]string{}
	for _, item := range list.Items {
		revokeBy[item.ID] = item.RevokeBy
	}
	if revokeBy["venafi-dn"] != "certificate_dn" || revokeBy["venafi-thumb"] != "thumbprint" {
		t.Fatalf("revoke_by = %v", revokeBy)
	}

	issue := func(authorityID string, plugin ca.CA, host string) string {
		t.Helper()
		issued, err := plugin.Issue(ctx, ca.IssueRequest{TenantID: h.tenant, CSR: serverTestCSR(t, host, nil), DNSNames: []string{host}, TTL: 24 * time.Hour})
		if err != nil {
			t.Fatalf("issue %s: %v", host, err)
		}
		return recordVendorIssuedLeaf(t, i, authorityID, owner.ID, issued).ID
	}
	dnCert := issue("venafi-dn", byDN, "dn.venafi.test")
	thumbCert := issue("venafi-thumb", byThumbprint, "thumb.venafi.test")
	status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "od7-venafi",
		map[string]any{"certificate_ids": []string{dnCert, thumbCert}, "reason": "keyCompromise"})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_queued":2`)) {
		t.Fatalf("bulk revoke = %d %s", status, raw)
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
	if len(messages) != 2 {
		t.Fatalf("external revocation commands = %d, want 2", len(messages))
	}
	for round := 1; round <= 2; round++ {
		refused := 0
		for _, m := range messages {
			if err := dispatcher.Deliver(ctx, m); err != nil {
				// The vendor's answer is not repeated; the revocation is
				// simply not confirmed.
				refused++
				if !strings.Contains(err.Error(), "not confirmed") {
					t.Fatalf("round %d: delivery error %v", round, err)
				}
			}
		}
		if refused != 1 {
			t.Fatalf("round %d: %d deliveries refused, want only the thumbprint-addressed one", round, refused)
		}
		revoked := vn.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("round %d: Venafi revoked %v, want exactly the DN-addressed certificate's object", round, revoked)
		}
		for dn, reason := range revoked {
			if !strings.HasPrefix(dn, vn.PolicyDN()+`\dn.venafi.test`) || reason != 1 {
				t.Fatalf("round %d: revoked %s with reason %d, want the dn.venafi.test object with keyCompromise", round, dn, reason)
			}
		}
		if current, err := h.store.GetCertificate(ctx, h.tenant, dnCert); err != nil || current.Status != "revoked" || current.RevocationReason != "keyCompromise" {
			t.Fatalf("round %d: the DN-revoked certificate is %s/%s %v", round, current.Status, current.RevocationReason, err)
		}
		if current, err := h.store.GetCertificate(ctx, h.tenant, thumbCert); err != nil || current.Status == "revoked" {
			t.Fatalf("round %d: the refused certificate is %s %v; want it not counted revoked", round, current.Status, err)
		}
	}
}
