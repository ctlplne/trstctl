// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
)

// P15-L3: an EAB credential scoped to a mail domain admits email orders for
// mailboxes there and nothing else — not a mailbox in another configured
// mail domain, not a DNS name under the same domain. Widening its scope
// through the policy API to the domain and those under it admits the other
// mailbox; a malformed mail entry is refused.
func TestServedEABCredentialsScopedToMailDomainsP15L3(t *testing.T) {
	relay := startP15SMTPRelay(t)
	hmacKey := bytes.Repeat([]byte{0x53}, 32)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "mail-team", HMACKey: hmacKey, AllowedIdentifiers: []string{"@p15l3.test"}},
		}},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l3.test", Domains: []string{"p15l3.test", "partner.p15l3.test"},
			Profile: "smime-signing", RelayAddr: relay.addr},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h", "allowed_ekus": []string{"emailProtection"},
		"allowed_email_domains": []string{"p15l3.test", "partner.p15l3.test"}, "allowed_protocols": []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "smime-signing", spec); err != nil {
		t.Fatal(err)
	}
	startServedDirectOutboxPump(t, h.srv)
	client := registerWithEAB(t, h, "mail-team", hmacKey)
	order := func(id xacme.AuthzID) error {
		_, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{id})
		return err
	}
	if err := order(xacme.AuthzID{Type: "email", Value: "alice@p15l3.test"}); err != nil {
		t.Fatalf("a mailbox inside the credential's mail domain: %v", err)
	}
	for _, id := range []xacme.AuthzID{{Type: "email", Value: "bob@partner.p15l3.test"}, {Type: "dns", Value: "www.p15l3.test"}} {
		if err := order(id); err == nil || !strings.Contains(err.Error(), "outside the scope of external account credential mail-team") {
			t.Fatalf("%s %s under a mail-domain scope: %v", id.Type, id.Value, err)
		}
	}

	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/acme/eab-credentials/mail-team/policy", tok,
		map[string]any{"allowed_identifiers": []string{"@"}}); status != http.StatusUnprocessableEntity && status != http.StatusBadRequest {
		t.Fatalf("a malformed mail entry = %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/acme/eab-credentials/mail-team/policy", tok,
		map[string]any{"allowed_identifiers": []string{"@*.p15l3.test"}}); status != http.StatusOK {
		t.Fatalf("widen the scope = %d %s", status, body)
	}
	if err := order(xacme.AuthzID{Type: "email", Value: "bob@partner.p15l3.test"}); err != nil {
		t.Fatalf("a mailbox under the widened mail domain: %v", err)
	}
	if err := order(xacme.AuthzID{Type: "dns", Value: "www.p15l3.test"}); err == nil {
		t.Fatal("a mail-domain scope admitted a DNS name")
	}
	t.Logf("P15L3_MAIL_SCOPE_OK")
}
