// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/rmm/datto"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
	"trstctl.com/trstctl/internal/store"
)

// servedRMMDrain drains the outbox until no entry of the destination is
// pending for the customer.
func servedRMMDrain(t *testing.T, h *servedHarness, tenant, destination, what string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := h.srv.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		var pending int
		_ = h.store.SystemPool().QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2 AND status = 'pending'`,
			tenant, destination).Scan(&pending)
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was never delivered", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func servedRMMDevices(t *testing.T, h *servedHarness, tenant string) map[string]store.RMMDevice {
	t.Helper()
	list, err := h.store.RMMDevices(context.Background(), tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.RMMDevice{}
	for _, d := range list {
		out[d.DeviceID] = d
	}
	return out
}

// MSP-10 Done-when (served, Datto RMM stand-in written from the public API
// description): each customer's devices are listed under its own site only
// (a site UID mapped in another letter case still matches) and mapped to its
// own agents, with each agent's health written to the configured
// user-defined field; an install runs the install component as a quick job
// whose token enrolls only an agent of that device's identity, only into the
// customer's own tenant, once; customer A cannot act on B's device, and a
// device moved to B's site after the inventory runs nothing; neither the API
// secret nor the token reaches the debug log or the outbox.
func TestServedDattoInventoryAndInstallEnrollOnlyIntoTheCustomersTenantMSP10(t *testing.T) {
	logs := captureDebugLog(t)
	ctx := context.Background()
	const apiKey, secret = "TRSTCTL-DATTO-KEY", "datto-served-api-secret" // #nosec G101 -- test-only values (CWE-798)
	const (
		install, upgrade, remove = "c0c0c0c0-0000-4000-8000-0000000000c1", "c0c0c0c0-0000-4000-8000-0000000000c2", "c0c0c0c0-0000-4000-8000-0000000000c3"
		siteA, siteB             = "6f0b6f1e-5a4c-4a43-9a8f-0b1c2d3e4f50", "7a1c7e2f-6b5d-4b54-8b9e-1c2d3e4f5061"
		devA1, devA2, devB1      = "a1a1a1a1-0000-4000-8000-000000000001", "a2a2a2a2-0000-4000-8000-000000000002", "b1b1b1b1-0000-4000-8000-000000000001"
	)
	dt := rmmtest.NewDatto(apiKey, secret)
	t.Cleanup(dt.Close)
	for _, c := range []string{install, upgrade, remove} {
		dt.AddComponent(c)
	}
	dt.AddDevice(rmmtest.DattoDevice{UID: devA1, SiteUID: siteA, Hostname: "ALPHA-DC01", Online: true})
	dt.AddDevice(rmmtest.DattoDevice{UID: devA2, SiteUID: siteA, Hostname: "ALPHA-NEW01"})
	dt.AddDevice(rmmtest.DattoDevice{UID: devB1, SiteUID: siteB, Hostname: "BETA-APP01", Online: true})
	target := config.ProviderBillingTarget{ID: "datto", Type: "datto", Endpoint: dt.URL(), AllowInsecureLoopback: true,
		Datto: &config.DattoTarget{APIKeyRef: writeServedCredentialFile(t, "datto-key", apiKey), APISecretRef: writeServedCredentialFile(t, "datto-secret", secret),
			InstallComponentUID: install, UpgradeComponentUID: upgrade, RemoveComponentUID: remove, HealthUDF: 12}}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
		d.AgentChannelPublicAddress, d.AgentChannelServerName = "agents.msp.example.test:8443", "agents.msp.example.test"
	})
	const customerB = "6c1d8e3a-4b2f-4e5a-9c7d-1f2e3d4c5b6a"
	registerServedTenant(t, h, "datto customer A")
	registerServedTenantID(t, h, customerB, "datto customer B")
	for tenant, site := range map[string]string{h.tenant: strings.ToUpper(siteA), customerB: siteB} {
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'datto', $2, 'operator@example.test', now())`, tenant, site); err != nil {
			t.Fatal(err)
		}
	}
	n := ninjaHarness{h: h}
	now := time.Now().UTC()
	dcAgent := n.addAgent(t, h.tenant, "ALPHA-DC01", "1.4.2", &now)
	betaAgent := n.addAgent(t, customerB, "BETA-APP01", "1.3.0", &now)
	bucket := now.Truncate(10 * time.Minute)
	for _, tenant := range []string{h.tenant, customerB} {
		if queued, err := h.srv.orch.QueueRMMInventory(ctx, tenant, "datto", bucket); err != nil || !queued {
			t.Fatalf("queue inventory = %v %v", queued, err)
		}
		servedRMMDrain(t, h, tenant, orchestrator.DestinationRMMInventory, "the inventory")
	}
	a := servedRMMDevices(t, h, h.tenant)
	if len(a) != 2 || a[devB1].DeviceID != "" || a[devA1].AgentID != dcAgent || a[devA1].AgentMatch != "hostname" || a[devA2].AgentID != "" {
		t.Fatalf("A's devices = %+v, want its two and never B's", a)
	}
	if b := servedRMMDevices(t, h, customerB); len(b) != 1 || b[devB1].AgentID != betaAgent {
		t.Fatalf("B's devices = %+v", b)
	}
	if f := dt.UDFs(devA1); f["udf12"] != "trstctl agent healthy (version 1.4.2)" {
		t.Fatalf("ALPHA-DC01 UDFs = %+v", f)
	}
	if f := dt.UDFs(devB1); f["udf12"] != "trstctl agent healthy (version 1.3.0)" {
		t.Fatalf("BETA-APP01 UDFs = %+v", f)
	}
	if f := dt.UDFs(devA2); len(f) != 0 {
		t.Fatalf("an unmatched device got health: %+v", f)
	}

	// Install on A's new device: one quick job of the install component, its
	// token pinned to the device's identity and A's tenant.
	act := func(tenant, device, action, key string) {
		t.Helper()
		if _, err := h.srv.orch.QueueRMMAction(ctx, tenant, "datto", device, action, "operator@msp.example.test", key); err != nil {
			t.Fatalf("queue %s on %s = %v", action, device, err)
		}
		servedRMMDrain(t, h, tenant, orchestrator.DestinationRMMAction, "the "+action)
	}
	act(h.tenant, devA2, "install", "install-a2")
	jobs := dt.Jobs()
	if len(jobs) != 1 || jobs[0].DeviceUID != devA2 || jobs[0].ComponentUID != install ||
		jobs[0].Variables[datto.VarServer] != "agents.msp.example.test:8443" || jobs[0].Variables[datto.VarServerName] != "agents.msp.example.test" ||
		jobs[0].Variables[datto.VarIdentity] != RMMInstalledIdentity("datto", devA2) || jobs[0].Variables[datto.VarToken] == "" {
		t.Fatalf("install jobs = %+v", jobs)
	}
	token := []byte(jobs[0].Variables[datto.VarToken])
	if d := servedRMMDevices(t, h, h.tenant)[devA2]; d.ActionStatus != store.RMMActionDone {
		t.Fatalf("the installed device = %+v", d)
	}
	tenant, err := enrollAs(t, h, token, RMMInstalledIdentity("datto", devA2))
	if err != nil || tenant != h.tenant {
		t.Fatalf("the install token enrolled into %q (%v), want customer A %q", tenant, err, h.tenant)
	}
	if _, err := enrollAs(t, h, token, RMMInstalledIdentity("datto", devA2)); err == nil {
		t.Fatal("the install token enrolled twice")
	}

	// A cannot act on B's device; a device moved to B's site runs nothing.
	if _, err := h.srv.orch.QueueRMMAction(ctx, h.tenant, "datto", devB1, "install", "operator@msp.example.test", "install-b1"); !errors.Is(err, orchestrator.ErrRMMDeviceUnknown) {
		t.Fatalf("A acting on B's device = %v, want refused", err)
	}
	dt.MoveDevice(devA1, siteB)
	act(h.tenant, devA1, "upgrade", "upgrade-a1")
	if len(dt.Jobs()) != 1 {
		t.Fatalf("a device moved to another site ran: %+v", dt.Jobs())
	}
	if d := servedRMMDevices(t, h, h.tenant)[devA1]; d.ActionStatus != store.RMMActionFailed || !strings.Contains(d.ActionReason, "another organization") {
		t.Fatalf("the moved device = %+v", d)
	}

	for _, leak := range []string{secret, string(token)} {
		if strings.Contains(logs.String(), leak) {
			t.Fatal("the debug log carries the API secret or the install token")
		}
		var leaked int
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE position($1 in payload::text) > 0 OR position($1 in coalesce(last_error, '')) > 0`,
			leak).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatalf("the outbox carries a secret (%d, %v)", leaked, err)
		}
	}
	if _, _, refused := dt.Counts(); refused != 0 {
		t.Fatalf("Datto refused %d requests", refused)
	}
}
