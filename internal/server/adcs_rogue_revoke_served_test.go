// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A163-L1: a rogue certificate the tenant's own AD CS issued outside trstctl,
// seen only in Certificate Transparency, is revoked at that CA through the
// issuer's revocation relay, by its serial, as an inventory certificate is
// (A162). The authority list offers the AD CS issuer as serial-revocable once
// it names a relay, and a reason certutil cannot take is refused up front. The
// revocation's delivery hands the serial to the relay and waits without
// spending its retry budget; the production relay loop runs certutil to
// revoke, publish a CRL and read the row back; only that checked report lets
// the finding read revoked at the issuer, and the CRL a relying party fetches
// from the CA names the serial with the reason. Before, the API refused an
// AD CS authority with 409.
func TestServedADCSRogueCertificateIsRevokedThroughTheRelayA163L1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("the certutil stand-in drives the CA stand-in with curl")
	}
	certsrvStandIn, certsrv := newADCSCertsrvStandIn(t)
	admin := &adcsCAAdminStandIn{certsrv: certsrvStandIn, issued: map[string]bool{}, revoked: map[string]int{}}
	adminSrv := httptest.NewServer(http.HandlerFunc(admin.serve))
	t.Cleanup(adminSrv.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSRevoke}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, "role-agent")
	})
	ctx := t.Context()
	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	relay.CertutilPath = writeCertutilRevokeStandIn(t, adminSrv.URL)

	// A certificate the AD CS CA issued outside trstctl: trstctl never held it
	// and knows it only from the CT finding (its serial, names, log position).
	shadowDER, err := crypto.SignLeafFromCSR(certsrvStandIn.caDER, certsrvStandIn.caKey, serverTestCSR(t, "shadow.corp.example", nil), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: shadowDER}))
	if err != nil {
		t.Fatal(err)
	}
	admin.issued[strings.ToLower(info.SerialNumber)] = true
	findingID := seedRogueCTFinding(t, h.servedHarness, info)
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write", "issuers:read")

	status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/external-cas", token, nil)
	var authorities struct {
		Items []struct {
			ID              string `json:"id"`
			RevokesBySerial bool   `json:"revokes_by_serial"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &authorities) != nil || len(authorities.Items) != 1 ||
		authorities.Items[0].ID != "corp-adcs-web" || !authorities.Items[0].RevokesBySerial {
		t.Fatalf("external CAs = %d %s; want the AD CS issuer with its relay offered as revoking by serial", status, raw)
	}
	const route = "/api/v1/revocation/rogue-certificates/revoke"
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, route, token, "a163l1-privilege",
		map[string]any{"discovery_id": findingID, "authority_id": "corp-adcs-web", "reason": "privilegeWithdrawn"}); status != http.StatusBadRequest {
		t.Fatalf("a reason certutil cannot take = %d %s; want 400", status, body)
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, route, token, "a163l1-rogue",
		map[string]any{"discovery_id": findingID, "authority_id": "corp-adcs-web", "reason": "keyCompromise"})
	if status != http.StatusAccepted || !strings.Contains(string(raw), `"status":"queued"`) {
		t.Fatalf("revoke the AD CS rogue certificate at its issuer = %d %s", status, raw)
	}

	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	for range 2 {
		if err := dispatcher.Deliver(ctx, message); !orchestrator.IsDeliveryDeferred(err) {
			t.Fatalf("delivery before the relay reports = %v; want a budget-neutral wait", err)
		}
	}
	if n := adcsRevokeAttempts(t, h); n != 1 {
		t.Fatalf("relay revocation attempts = %d; want one while it waits", n)
	}
	if got := rogueIssuerRevocationOf(t, h.servedHarness, token, findingID); got == nil || got.Status != "queued" || len(admin.revoked) != 0 {
		t.Fatalf("before the relay reports the finding reads %+v and the CA revoked %v; want queued and nothing revoked", got, admin.revoked)
	}

	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 {
		t.Fatalf("production relay = %d %v reports %+v", count, err, channel.reports)
	}
	if err := dispatcher.Deliver(ctx, message); err != nil {
		t.Fatalf("delivery after the relay's checked report = %v", err)
	}
	got := rogueIssuerRevocationOf(t, h.servedHarness, token, findingID)
	if got == nil || got.Status != "revoked" || got.RevokedAt == "" || got.Reason != "keyCompromise" {
		t.Fatalf("after the relay's checked report the finding reads %+v; want revoked at the issuer", got)
	}
	resp, err := http.Get(adminSrv.URL + "/CertEnroll/Corp-Issuing-CA.crl") // #nosec G107 -- the test's own CA stand-in (CWE-918).
	if err != nil {
		t.Fatal(err)
	}
	crlDER, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	crl, err := crypto.ParseCRL(crlDER, certsrvStandIn.caDER)
	if err != nil {
		t.Fatalf("the AD CS CRL does not verify under the AD CS issuing CA: %v", err)
	}
	onCRL := false
	for _, entry := range crl.Revoked {
		if entry.Serial == strings.TrimLeft(strings.ToLower(info.SerialNumber), "0") && entry.Reason == 1 {
			onCRL = true
		}
	}
	if !onCRL {
		t.Fatalf("the AD CS CRL does not list serial %s with keyCompromise: %+v", info.SerialNumber, crl.Revoked)
	}
}
