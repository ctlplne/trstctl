// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestCR062ServedDNS01PrivateEgressNeedsDurableGrantAndCurrentCeiling(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		_ = udp.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, peer, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		received <- append([]byte(nil), buf[:n]...)
		response := append([]byte(nil), buf[:12]...)
		response[2] |= 0x80 // DNS response bit; keep the request ID and opcode
		_, _ = udp.WriteTo(response, peer)
	}()
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ACMEDNS01PrivateEgressCIDRs = []string{"127.0.0.1/32"}
	})
	without := seedScopedToken(t, h.store, h.tenant, "issuers:write", "issuers:read")
	with := seedScopedToken(t, h.store, h.tenant, "issuers:write", "issuers:read", "egress:private")
	configBody := func(name string, cidrs []string) map[string]any {
		return map[string]any{"name": name, "provider": "rfc2136", "zone": "example.test",
			"config":                 map[string]any{"server": udp.LocalAddr().String()},
			"allow_private_endpoint": true, "private_egress_cidrs": cidrs}
	}
	path := "/api/v1/acme/dns-01/provider-configs"
	if status, body := secretsReq(t, h, http.MethodPost, path, without, configBody("cr062-denied", []string{"127.0.0.1/32"})); status != http.StatusForbidden {
		t.Fatalf("private DNS config without egress:private = HTTP %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, path, with, configBody("cr062-wide", []string{"127.0.0.0/8"})); status != http.StatusBadRequest {
		t.Fatalf("private DNS config wider than operator ceiling = HTTP %d %s", status, body)
	}
	status, body := secretsReq(t, h, http.MethodPost, path, with, configBody("cr062-approved", []string{"127.0.0.1/32"}))
	var created struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.ID == "" {
		t.Fatalf("narrow private DNS config = HTTP %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPut, path+"/"+created.ID, without,
		configBody("cr062-approved", []string{"127.0.0.1/32"})); status != http.StatusForbidden {
		t.Fatalf("private DNS config update without egress:private = HTTP %d %s", status, body)
	}
	rec, err := h.store.GetACMEDNS01ProviderConfig(t.Context(), h.tenant, created.ID)
	if err != nil || !rec.AllowPrivateEndpoint || rec.PrivateEgressAdmissionVersion != 1 {
		t.Fatalf("projected private DNS authority = %+v, %v", rec, err)
	}
	payload := acmeDNS01OutboxPayload{ConfigID: rec.ID, Provider: rec.Provider, Zone: rec.Zone, Config: rec.Config, CredentialRefs: rec.CredentialRefs,
		AllowPrivateEndpoint: rec.AllowPrivateEndpoint, PrivateEgressCIDRs: append([]string(nil), rec.PrivateEgressCIDRs...),
		PrivateEgressAdmissionVersion: rec.PrivateEgressAdmissionVersion}
	stale := payload
	stale.AllowPrivateEndpoint = false
	stale.PrivateEgressCIDRs = nil
	stale.PrivateEgressAdmissionVersion = 0
	if _, err := h.srv.acmeDNS01.providerForPayload(t.Context(), h.tenant, stale); err == nil {
		t.Fatal("queued public DNS intent borrowed a later private egress grant")
	}
	provider, err := h.srv.acmeDNS01.providerForPayload(t.Context(), h.tenant, payload)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := provider.PresentTXT(ctx, "_acme-challenge.example.test", "probe"); err != nil {
		t.Fatalf("approved private UDP update: %v", err)
	}
	select {
	case msg := <-received:
		if len(msg) < 12 {
			t.Fatal("approved provider sent a short DNS packet")
		}
	default:
		t.Fatal("approved provider never reached the private DNS server")
	}
	h.srv.acmeDNS01.privateEgressCeiling = nil
	if _, err := h.srv.acmeDNS01.providerForPayload(t.Context(), h.tenant, payload); err == nil {
		t.Fatal("queued provider kept private egress after operator revoked its ceiling")
	}
	legacy := store.ACMEDNS01ProviderConfig{ID: "ab620000-0000-4000-8000-000000000001", TenantID: h.tenant,
		Name: "cr062-legacy", Provider: "rfc2136", Zone: "example.test", Config: rec.Config,
		AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"}}
	seedDNS01Config(t, t.Context(), h, legacy)
	h.srv.acmeDNS01.privateEgressCeiling = []string{"127.0.0.1/32"}
	if _, err := h.srv.acmeDNS01.providerForPayload(t.Context(), h.tenant, acmeDNS01OutboxPayload{
		ConfigID: legacy.ID, Provider: legacy.Provider, Config: legacy.Config, CredentialRefs: json.RawMessage(`{}`),
	}); err == nil {
		t.Fatal("legacy row with forged private flag acquired egress without an admission event")
	}
}
