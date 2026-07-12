// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

const evalProtocolTenant = "11111111-1111-4111-8111-111111111111"

func TestEvalProfileEnablesEveryServedProtocolForOneTenant(t *testing.T) {
	cfg := config.Default()
	cfg.Protocols.Profile = config.ProtocolProfileEval
	cfg.Protocols.EvalTenantID = evalProtocolTenant

	got, err := evalProtocolProfileFromConfig(cfg)
	if err != nil {
		t.Fatalf("evalProtocolProfileFromConfig: %v", err)
	}

	for name, toggle := range map[string]config.ProtocolToggle{
		"acme": got.ACME,
		"est":  got.EST,
		"scep": got.SCEP,
		"cmp":  got.CMP,
		"tsa":  got.TSA,
		"ssh":  got.SSH,
	} {
		if !toggle.Enabled || toggle.TenantID != evalProtocolTenant {
			t.Errorf("%s = %+v, want enabled and tenant %s", name, toggle, evalProtocolTenant)
		}
	}
	if !got.SPIFFE.Enabled || got.SPIFFE.TenantID != evalProtocolTenant {
		t.Errorf("spiffe = %+v, want enabled and tenant %s", got.SPIFFE, evalProtocolTenant)
	}
	if got.SPIFFE.TrustDomain != config.DefaultEvalSPIFFETrustDomain {
		t.Errorf("spiffe trust domain = %q, want %q", got.SPIFFE.TrustDomain, config.DefaultEvalSPIFFETrustDomain)
	}
	if got.KMIP.Enabled {
		t.Fatal("eval enrollment profile must not silently enable the separately gated KMIP listener")
	}
}

func TestProductionDefaultsKeepProtocolsDisabled(t *testing.T) {
	cfg := config.Default()
	got, err := evalProtocolProfileFromConfig(cfg)
	if err != nil {
		t.Fatalf("evalProtocolProfileFromConfig: %v", err)
	}

	if got.ACME.Enabled || got.EST.Enabled || got.SCEP.Enabled || got.CMP.Enabled || got.TSA.Enabled || got.SPIFFE.Enabled || got.SSH.Enabled || got.KMIP.Enabled {
		t.Fatalf("default protocols = %+v, want every protocol disabled", got)
	}
}

func TestEvalProfileActivationReplaysAndStaysTenantBound(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	protocols := config.Default().Protocols
	protocols.Profile = config.ProtocolProfileEval
	protocols.EvalTenantID = evalProtocolTenant
	firstServed := &servedProtocols{names: append([]string(nil), evalProtocolNames...)}
	first, err := newEvalProtocolProfileControl(ctx, protocols, firstServed, log)
	if err != nil {
		t.Fatalf("new control: %v", err)
	}
	if first.gate.Active() {
		t.Fatal("fresh eval profile must wait for the first-run activation action")
	}
	if _, err := first.Activate(ctx, "22222222-2222-4222-8222-222222222222", "wrong-tenant"); !errors.Is(err, api.ErrProtocolProfileTenantMismatch) {
		t.Fatalf("cross-tenant activation error = %v, want tenant mismatch", err)
	}
	if _, err := first.Activate(ctx, evalProtocolTenant, "activate-once"); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	secondServed := &servedProtocols{names: append([]string(nil), evalProtocolNames...)}
	second, err := newEvalProtocolProfileControl(ctx, protocols, secondServed, log)
	if err != nil {
		t.Fatalf("replay control: %v", err)
	}
	if !second.gate.Active() {
		t.Fatal("restart replay did not restore eval protocol activation")
	}
}

func TestEvalProfileProtocolsEnabledInAssembledServer(t *testing.T) {
	cfg := config.Default()
	cfg.Protocols.Profile = config.ProtocolProfileEval
	cfg.Protocols.EvalTenantID = servedTestTenant
	cfg.Protocols.SPIFFE.SocketPath = t.TempDir() + "/workload.sock"
	cfg.Protocols.RAKeyFile = t.TempDir() + "/protocol-ra.key"
	cfg.Protocols.TSACertFile = t.TempDir() + "/tsa.crt"
	protocols, err := evalProtocolProfileFromConfig(cfg)
	if err != nil {
		t.Fatalf("evalProtocolProfileFromConfig: %v", err)
	}

	h := newServedHarness(t, protocols)
	if got := h.srv.ServedProtocols(); len(got) != 0 {
		t.Fatalf("ServedProtocols() before wizard activation = %v, want none", got)
	}
	response, err := h.ts.Client().Get(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("pre-activation ACME directory: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("pre-activation ACME directory status = %d, want 503", response.StatusCode)
	}

	token := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/setup/protocols/activate", token, "activate-eval-protocols", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"active":true`)) {
		t.Fatalf("activate eval protocols: status=%d body=%s", status, body)
	}
	if !h.hasEvent(t, protocolEvalProfileActivatedEvent) {
		t.Fatal("wizard activation did not append the tenant-bound protocol profile event")
	}
	want := []string{"acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"}
	if got := h.srv.ServedProtocols(); !slices.Equal(got, want) {
		t.Fatalf("ServedProtocols() = %v, want %v", got, want)
	}
	response, err = h.ts.Client().Get(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("active ACME directory: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("active ACME directory status = %d, want 200", response.StatusCode)
	}
}
