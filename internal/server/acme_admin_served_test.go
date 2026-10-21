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
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
)

// A52 on the assembled binary: the admin surface lists accounts with their
// binding credential and counts, drills one account's orders down to the
// authorizations and challenges a stuck client is waiting on, names the
// issued leaf's inventory record so the governed revocation path can revoke
// it, reflects that revocation, and deactivates an account on the operator's
// authority so its next request is refused and its pending order cancelled.
// Nothing served carries key material, and another tenant's token sees an
// unserved list.
func TestServedACMEAdminListsAccountsOrdersAndDeactivates(t *testing.T) {
	pinnedKey := bytes.Repeat([]byte{0x71}, 32)
	plainKey := bytes.Repeat([]byte{0x72}, 32)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "pinned", HMACKey: pinnedKey, Profile: "internal-acme"},
			{KeyID: "plain", HMACKey: plainKey},
		}},
	}, func(d *Deps) { d.DefaultProfile = "public-acme" })
	storeServerTestProfile(t, h.store, h.tenant, "public-acme", profile.CertificateProfile{
		Name: "public-acme", ACMEAuthMode: profile.ACMEAuthModePublicTrust,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	storeServerTestProfile(t, h.store, h.tenant, "internal-acme", profile.CertificateProfile{
		Name: "internal-acme", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "identities:write", "certs:issue", "certs:read")
	ctx := context.Background()

	// One account issues under the pinned trust-authenticated profile; one
	// public-trust account leaves an order pending on its challenges.
	pinned := registerWithEAB(t, h, "pinned", pinnedKey)
	subject, err := crypto.GenerateHostSubjectKey("issued.admin.test", []string{"issued.admin.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	order, err := pinned.AuthorizeOrder(ctx, xacme.DomainIDs("issued.admin.test"))
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := pinned.CreateOrderCert(ctx, order.FinalizeURL, subject.CSRDER, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("issue under the pinned profile: %v", err)
	}
	plain := registerWithEAB(t, h, "plain", plainKey)
	if _, err := plain.AuthorizeOrder(ctx, xacme.DomainIDs("pending.admin.test")); err != nil {
		t.Fatal(err)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/accounts", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list accounts = %d %s", status, body)
	}
	var accounts struct {
		Served bool `json:"served"`
		Items  []struct {
			ID           string `json:"id"`
			Status       string `json:"status"`
			EABKeyID     string `json:"eab_key_id"`
			Orders       int    `json:"orders"`
			Certificates int    `json:"certificates"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &accounts)
	if !accounts.Served || len(accounts.Items) != 2 {
		t.Fatalf("accounts = %s; want two served accounts", body)
	}
	byKID := map[string]string{}
	for _, item := range accounts.Items {
		byKID[item.EABKeyID] = item.ID
		switch item.EABKeyID {
		case "pinned":
			if item.Status != "valid" || item.Orders != 1 || item.Certificates != 1 {
				t.Fatalf("pinned account = %+v", item)
			}
		case "plain":
			if item.Status != "valid" || item.Orders != 1 || item.Certificates != 0 {
				t.Fatalf("plain account = %+v", item)
			}
		}
	}
	for name, key := range map[string][]byte{"pinned": pinnedKey, "plain": plainKey} {
		if bytes.Contains(body, key) || strings.Contains(string(body), strings.Repeat("71", 32)) || strings.Contains(string(body), strings.Repeat("72", 32)) {
			t.Fatalf("account listing carries the %s MAC key", name)
		}
	}

	// Drilldown: the pending order shows its authorization and challenges; the
	// issued one names its serial, fingerprint and inventory record.
	type orderView struct {
		ID                  string   `json:"id"`
		Status              string   `json:"status"`
		Identifiers         []string `json:"identifiers"`
		Profile             string   `json:"profile"`
		CertificateRecordID string   `json:"certificate_record_id"`
		CertificateSerial   string   `json:"certificate_serial"`
		Revoked             bool     `json:"revoked"`
		Authorizations      []struct {
			Domain     string `json:"domain"`
			Status     string `json:"status"`
			Challenges []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"challenges"`
		} `json:"authorizations"`
	}
	orders := func(accountID string) []orderView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/accounts/"+accountID+"/orders", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("list orders = %d %s", status, body)
		}
		var list struct {
			Served bool        `json:"served"`
			Items  []orderView `json:"items"`
		}
		if err := json.Unmarshal(body, &list); err != nil || !list.Served {
			t.Fatalf("orders = %s err=%v", body, err)
		}
		return list.Items
	}
	pending := orders(byKID["plain"])
	if len(pending) != 1 || pending[0].Status != "pending" || len(pending[0].Authorizations) != 1 ||
		pending[0].Authorizations[0].Domain != "pending.admin.test" || len(pending[0].Authorizations[0].Challenges) == 0 {
		t.Fatalf("pending order drilldown = %+v", pending)
	}
	issued := orders(byKID["pinned"])
	if len(issued) != 1 || issued[0].Status != "valid" || issued[0].Profile != "internal-acme" ||
		issued[0].CertificateRecordID == "" || issued[0].CertificateSerial == "" || issued[0].Revoked {
		t.Fatalf("issued order drilldown = %+v", issued)
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/accounts/nobody/orders", tok, nil); status != http.StatusNotFound {
		t.Fatalf("unknown account = %d %s", status, body)
	}

	// Revocation runs through the governed certificate path with the record
	// id the admin view named, and the view reflects it.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", tok, "a52-revoke", map[string]any{
		"certificate_ids": []string{issued[0].CertificateRecordID}, "reason": "keyCompromise",
	})
	if status != http.StatusOK {
		t.Fatalf("revoke through bulk-revoke = %d %s", status, body)
	}
	if after := orders(byKID["pinned"]); len(after) != 1 || !after[0].Revoked {
		t.Fatalf("issued order after revocation = %+v; want revoked", after)
	}

	// Deactivation: the operator retires the pending account; its next request
	// is refused, its order is cancelled, and the listing says so.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/accounts/"+byKID["plain"]+"/deactivate", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"deactivated"`) {
		t.Fatalf("deactivate = %d %s", status, body)
	}
	if _, err := plain.AuthorizeOrder(ctx, xacme.DomainIDs("another.admin.test")); err == nil {
		t.Fatal("a deactivated account still places orders")
	}
	if cancelled := orders(byKID["plain"]); len(cancelled) != 1 || cancelled[0].Status != "invalid" {
		t.Fatalf("orders after deactivation = %+v; want the pending order cancelled", cancelled)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/accounts/nobody/deactivate", tok, nil); status != http.StatusNotFound {
		t.Fatalf("deactivate unknown = %d %s", status, body)
	}

	// Another tenant's token sees an unserved, empty list.
	const other = "22222222-2222-4222-8222-222222222222"
	registerServedTenantID(t, h, other, "Other tenant")
	otherTok := seedScopedToken(t, h.store, other, "issuers:read")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/acme/accounts", otherTok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"served":false`) || strings.Contains(string(body), byKID["pinned"]) {
		t.Fatalf("other tenant sees = %d %s", status, body)
	}
}
