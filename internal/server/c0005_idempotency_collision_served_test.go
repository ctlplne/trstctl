// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestC0005HTTPKeyCannotClaimInternalReceiver(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	caller := seedScopedTokenSubject(t, h.store, h.tenant, "c0005-caller", "access:write", "certs:read")
	for _, tc := range []struct {
		name, key string
	}{
		{"protocol-revocation", "protocol-revoke:acme:c0005-public-fingerprint"},
		{"protocol-issuance", "protocol-issue:acme:c0005-csr"},
		{"agent-renewal", "agent-renew:c0005-agent:c0005-serial"},
		{"leaf-preparation", "leaf-template:v1:c0005-slot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/bundles", caller, tc.key,
				map[string]any{"name": "c0005-" + tc.name, "permissions": []string{"certs:read"}})
			if status != http.StatusBadRequest || !strings.Contains(string(body), "reserved") {
				t.Fatalf("caller claimed internal receiver key: %d %s", status, body)
			}
			result, err := h.srv.idem.Do(context.Background(), h.tenant, tc.key, func(context.Context) ([]byte, error) {
				return []byte("internal-receiver"), nil
			})
			if err != nil || string(result) != "internal-receiver" {
				t.Fatalf("internal receiver could not claim its key: result=%q err=%v", result, err)
			}
		})
	}
}

func TestC0005HistoricalHTTPClaimCannotBlockProtocolRevocation(t *testing.T) {
	ctx := t.Context()
	clientDER, clientKey, csrDER := newSCEPClient(t, "c0005-device")
	h := newServedHarness(t, config.Protocols{
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: writeCMPAnchorPEM(t, clientDER),
	})
	registerServedTenant(t, h, "C0005 revocation recovery tenant")
	request, err := crypto.BuildCMPRequest(csrDER, clientDER, clientKey, []byte("c0005-transaction"), []byte("c0005-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.ts.Client().Post(h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := readAllClose(response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CMP issue = %d %s", response.StatusCode, packet)
	}
	leafDER, err := crypto.ParseCMPResponse(packet)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	poisonedKey := "protocol-revoke:cmp:" + info.SHA256Fingerprint
	if _, err := h.srv.idem.DoBound(ctx, h.tenant, poisonedKey, "historical-http-binding", func(context.Context) ([]byte, error) {
		return []byte(`{"s":201}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	issuer := h.srv.newProtocolIssuer()
	if err := issuer.RevokeProtocolLeaf(ctx, h.tenant, "cmp", info.SHA256Fingerprint, info.SerialNumber, 1, leafDER); err != nil {
		t.Fatalf("historically poisoned revocation did not recover: %v", err)
	}
	if status := servedOCSPStatus(t, h.srv, h.tenant, leafDER, h.caPEM); status != "revoked" {
		t.Fatalf("recovered revocation OCSP status = %q", status)
	}
	if err := issuer.RevokeProtocolLeaf(ctx, h.tenant, "cmp", info.SHA256Fingerprint, info.SerialNumber, 1, leafDER); err != nil {
		t.Fatalf("exact protocol revocation retry = %v", err)
	}
	revocations := 0
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventCertificateRevoked &&
			bytes.Contains(event.Data, []byte(info.SHA256Fingerprint)) {
			revocations++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if revocations != 1 {
		t.Fatalf("exact retry recorded %d certificate revocations, want one", revocations)
	}
}
