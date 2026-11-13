// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/rmm/rmmtest"
	"trstctl.com/trstctl/internal/store"
)

// ninjaHarness is a served harness with a NinjaOne stand-in, customer A
// mapped to organization 11 and customer B to organization 22.
type ninjaHarness struct {
	h         *servedHarness
	ninja     *rmmtest.NinjaOne
	customerB string
	secret    string
	logs      *p6MoveLog
}

func newNinjaHarness(t *testing.T, opts ...func(*Deps)) ninjaHarness {
	t.Helper()
	logs := captureDebugLog(t)
	const clientID, secret = "trstctl-ninja-client", "ninja-served-client-secret" // #nosec G101 -- test-only values (CWE-798)
	ninja := rmmtest.NewNinjaOne(clientID, secret)
	t.Cleanup(ninja.Close)
	for _, id := range []int64{31, 32, 33} {
		ninja.AddScript(id)
	}
	ninja.AddDevice(rmmtest.NinjaDevice{ID: 1001, OrgID: 11, SystemName: "ALPHA-DC01"})
	ninja.AddDevice(rmmtest.NinjaDevice{ID: 1002, OrgID: 11, SystemName: "ALPHA-WEB01"})
	ninja.AddDevice(rmmtest.NinjaDevice{ID: 1003, OrgID: 11, SystemName: "ALPHA-NEW01"})
	ninja.AddDevice(rmmtest.NinjaDevice{ID: 2001, OrgID: 22, SystemName: "BETA-APP01"})
	target := config.ProviderBillingTarget{ID: "ninja", Type: "ninjaone", Endpoint: ninja.URL(), AllowInsecureLoopback: true,
		NinjaOne: &config.NinjaOneTarget{ClientID: clientID, ClientSecretRef: writeServedCredentialFile(t, "ninja-secret", secret),
			InstallScriptID: 31, UpgradeScriptID: 32, RemoveScriptID: 33, HealthField: "trstctlAgent"}}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
		for _, opt := range opts {
			opt(d)
		}
	})
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b09"
	registerServedTenant(t, h, "ninja customer A")
	registerServedTenantID(t, h, customerB, "ninja customer B")
	for tenant, org := range map[string]string{h.tenant: "11", customerB: "22"} {
		if _, err := h.store.SystemPool().Exec(context.Background(), `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'ninja', $2, 'operator@example.test', now())`, tenant, org); err != nil {
			t.Fatal(err)
		}
	}
	return ninjaHarness{h: h, ninja: ninja, customerB: customerB, secret: secret, logs: logs}
}

func (n ninjaHarness) addAgent(t *testing.T, tenant, name, version string, lastSeen *time.Time) string {
	t.Helper()
	id := uuid.NewString()
	if err := n.h.store.WithTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at) VALUES ($1, $2, $3, 'connected', $4, $5)`,
			id, tenant, name, version, lastSeen)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (n ninjaHarness) inventory(t *testing.T, tenant string, bucket time.Time) {
	t.Helper()
	if queued, err := n.h.srv.orch.QueueRMMInventory(context.Background(), tenant, "ninja", bucket); err != nil || !queued {
		t.Fatalf("queue inventory = %v %v", queued, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := n.h.srv.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		var pending int
		_ = n.h.store.SystemPool().QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'provider.rmm_inventory' AND status = 'pending'`,
			tenant).Scan(&pending)
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the inventory was never delivered")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (n ninjaHarness) devices(t *testing.T, tenant string) map[string]store.RMMDevice {
	t.Helper()
	list, err := n.h.store.RMMDevices(context.Background(), tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.RMMDevice{}
	for _, d := range list {
		out[d.DeviceID] = d
	}
	return out
}

// MSP-9 Done-when (inventory, served, NinjaOne stand-in written from the
// public API description): each customer's devices are listed under its own
// organization only and mapped to its own agents — an agent installed
// through the RMM by its pinned identity, another by its host name, never an
// agent of the same name in another customer — each mapped device's agent
// health is written to its custom field, an unchanged inventory writes and
// records nothing, a device deleted in the RMM is recorded gone, and the
// client secret never appears in the debug log.
func TestServedNinjaOneInventoryMapsDevicesAndReportsHealthMSP9(t *testing.T) {
	n := newNinjaHarness(t)
	now := time.Now().UTC()
	stale := now.Add(-72 * time.Hour)
	dcAgent := n.addAgent(t, n.h.tenant, "ALPHA-DC01", "1.4.2", &now)
	webAgent := n.addAgent(t, n.h.tenant, "rmm-ninja-1002", "1.4.2", &stale)
	n.addAgent(t, n.h.tenant, "BETA-APP01", "1.4.2", &now) // A's agent named like B's device
	betaAgent := n.addAgent(t, n.customerB, "BETA-APP01", "1.3.0", &now)
	bucket := now.Truncate(10 * time.Minute)
	n.inventory(t, n.h.tenant, bucket)
	n.inventory(t, n.customerB, bucket)

	a := n.devices(t, n.h.tenant)
	if len(a) != 3 || a["2001"].DeviceID != "" {
		t.Fatalf("A's devices = %+v, want its three and never B's", a)
	}
	if d := a["1001"]; d.AgentID != dcAgent || d.AgentMatch != "hostname" || d.Health != "trstctl agent healthy (version 1.4.2)" || d.OrgID != "11" {
		t.Fatalf("ALPHA-DC01 = %+v", d)
	}
	if d := a["1002"]; d.AgentID != webAgent || d.AgentMatch != "installed" || !strings.HasPrefix(d.Health, "trstctl agent not seen since ") {
		t.Fatalf("ALPHA-WEB01 = %+v", d)
	}
	if d := a["1003"]; d.AgentID != "" || d.Health != "" || !d.Present {
		t.Fatalf("an unmatched device = %+v", d)
	}
	b := n.devices(t, n.customerB)
	if len(b) != 1 || b["2001"].AgentID != betaAgent || b["2001"].Health != "trstctl agent healthy (version 1.3.0)" {
		t.Fatalf("B's devices = %+v, want its one device mapped to its own agent", b)
	}
	if f := n.ninja.Fields(1001); f["trstctlAgent"] != "trstctl agent healthy (version 1.4.2)" {
		t.Fatalf("ALPHA-DC01 custom fields = %+v", f)
	}
	if f := n.ninja.Fields(2001); f["trstctlAgent"] != "trstctl agent healthy (version 1.3.0)" {
		t.Fatalf("BETA-APP01 custom fields = %+v", f)
	}
	if f := n.ninja.Fields(1003); len(f) != 0 {
		t.Fatalf("an unmatched device got health: %+v", f)
	}

	// Nothing changed: the next interval writes no field and records nothing.
	_, writes, _ := n.ninja.Counts()
	before := a["1001"].EventSequence
	n.inventory(t, n.h.tenant, bucket.Add(10*time.Minute))
	if _, after, _ := n.ninja.Counts(); after != writes {
		t.Fatalf("an unchanged inventory wrote %d times", after-writes)
	}
	if n.devices(t, n.h.tenant)["1001"].EventSequence != before {
		t.Fatal("an unchanged inventory recorded an event")
	}

	// A device deleted in NinjaOne is recorded gone.
	n.ninja.RemoveDevice(1003)
	n.inventory(t, n.h.tenant, bucket.Add(20*time.Minute))
	if d := n.devices(t, n.h.tenant)["1003"]; d.Present {
		t.Fatalf("a deleted device = %+v, want gone", d)
	}
	if strings.Contains(n.logs.String(), n.secret) {
		t.Fatal("the debug log carries the client secret")
	}
	if _, _, refused := n.ninja.Counts(); refused != 0 {
		t.Fatalf("NinjaOne refused %d requests", refused)
	}
}

// act queues an agent action and drains the outbox until it was delivered.
func (n ninjaHarness) act(t *testing.T, tenant, device, action, key string) string {
	t.Helper()
	id, err := n.h.srv.orch.QueueRMMAction(context.Background(), tenant, "ninja", device, action, "operator@msp.example.test", key)
	if err != nil {
		t.Fatalf("queue %s on %s = %v", action, device, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := n.h.srv.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		var pending int
		_ = n.h.store.SystemPool().QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'provider.rmm_action' AND status = 'pending'`,
			tenant).Scan(&pending)
		if pending == 0 {
			return id
		}
		if time.Now().After(deadline) {
			t.Fatalf("the %s on %s was never delivered", action, device)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// installToken reads the one-time token an install run carried.
func installToken(t *testing.T, run rmmtest.NinjaRun) []byte {
	t.Helper()
	_, after, found := strings.Cut(run.Parameters, `-Token "`)
	token, _, closed := strings.Cut(after, `"`)
	if !found || !closed || token == "" {
		t.Fatalf("the install run carries no token: %q", run.Parameters)
	}
	return []byte(token)
}

// enrollAs redeems a bootstrap token for an agent of the given identity and
// returns the tenant its certificate is issued to.
func enrollAs(t *testing.T, h *servedHarness, token []byte, cn string) (string, error) {
	t.Helper()
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := h.srv.agentEnroll.EnrollBootstrap(context.Background(), token, csr)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatalf("enrollment answered no certificate: %q", chain)
	}
	info, err := mtls.PeerCertInfoFromDER(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return info.TenantID, nil
}

// MSP-9 Done-when (agent actions, served, NinjaOne stand-in): an install
// runs the install script on the customer's own device with a one-time
// token that enrolls only an agent of that device's identity, only into the
// customer's own tenant, and only once; a retried request runs nothing more;
// customer A cannot act on customer B's device, and a device moved to
// another organization after the inventory runs nothing; upgrade and remove
// run their scripts; and the token never reaches the debug log, the outbox
// or the event payloads.
func TestServedNinjaOneAgentActionsEnrollOnlyIntoTheCustomersTenantMSP9(t *testing.T) {
	n := newNinjaHarness(t, func(d *Deps) {
		d.AgentChannelPublicAddress, d.AgentChannelServerName = "agents.msp.example.test:8443", "agents.msp.example.test"
	})
	ctx := context.Background()
	now := time.Now().UTC()
	n.addAgent(t, n.h.tenant, "ALPHA-DC01", "1.4.2", &now)
	bucket := now.Truncate(10 * time.Minute)
	n.inventory(t, n.h.tenant, bucket)
	n.inventory(t, n.customerB, bucket)

	// Install on A's new device: one run of the install script, its token
	// pinned to the device's identity and A's tenant.
	request := n.act(t, n.h.tenant, "1003", "install", "install-1003-a")
	runs := n.ninja.Runs()
	if len(runs) != 1 || runs[0].DeviceID != 1003 || runs[0].ScriptID != 31 || runs[0].RunAs != "system" ||
		!strings.Contains(runs[0].Parameters, `-Server "agents.msp.example.test:8443" -ServerName "agents.msp.example.test" -Identity "rmm-ninja-1003" -Token "`) {
		t.Fatalf("install runs = %+v", runs)
	}
	token := installToken(t, runs[0])
	if d := n.devices(t, n.h.tenant)["1003"]; d.Action != "install" || d.ActionStatus != store.RMMActionDone || d.ActionEventID != request || d.ActionBy != "operator@msp.example.test" {
		t.Fatalf("the installed device = %+v", d)
	}
	tenant, err := enrollAs(t, n.h, token, RMMInstalledIdentity("ninja", "1003"))
	if err != nil || tenant != n.h.tenant {
		t.Fatalf("the install token enrolled into %q (%v), want customer A %q", tenant, err, n.h.tenant)
	}
	if _, err := enrollAs(t, n.h, token, RMMInstalledIdentity("ninja", "1003")); err == nil {
		t.Fatal("the install token enrolled twice")
	}

	// The same request again queues and runs nothing more.
	if again, err := n.h.srv.orch.QueueRMMAction(ctx, n.h.tenant, "ninja", "1003", "install", "operator@msp.example.test", "install-1003-a"); err != nil || again != request {
		t.Fatalf("the retried request = %q %v, want %q", again, err, request)
	}
	if err := n.h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if len(n.ninja.Runs()) != 1 {
		t.Fatalf("a retried request ran again: %+v", n.ninja.Runs())
	}

	// A second install's token enrolls no agent of another identity: not B's
	// device's, which would land B's device in A's tenant.
	n.act(t, n.h.tenant, "1003", "install", "install-1003-b")
	second := installToken(t, n.ninja.Runs()[1])
	if _, err := enrollAs(t, n.h, second, RMMInstalledIdentity("ninja", "2001")); err == nil {
		t.Fatal("an install token enrolled an agent of another device's identity")
	}

	// A cannot act on B's device, and a device moved to B's organization
	// after the inventory runs nothing.
	if _, err := n.h.srv.orch.QueueRMMAction(ctx, n.h.tenant, "ninja", "2001", "install", "operator@msp.example.test", "install-2001-a"); !errors.Is(err, orchestrator.ErrRMMDeviceUnknown) {
		t.Fatalf("A acting on B's device = %v, want refused", err)
	}
	n.ninja.MoveDevice(1002, 22)
	n.act(t, n.h.tenant, "1002", "install", "install-1002-a")
	if len(n.ninja.Runs()) != 2 {
		t.Fatalf("a device moved to another organization ran: %+v", n.ninja.Runs())
	}
	if d := n.devices(t, n.h.tenant)["1002"]; d.ActionStatus != store.RMMActionFailed || !strings.Contains(d.ActionReason, "another organization") {
		t.Fatalf("the moved device = %+v", d)
	}

	// Upgrade and remove run their scripts with no token; one action at a time.
	n.act(t, n.h.tenant, "1001", "upgrade", "upgrade-1001-a")
	if _, err := n.h.srv.orch.QueueRMMAction(ctx, n.h.tenant, "ninja", "1001", "remove", "operator@msp.example.test", "remove-1001-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.h.srv.orch.QueueRMMAction(ctx, n.h.tenant, "ninja", "1001", "upgrade", "operator@msp.example.test", "upgrade-1001-b"); !errors.Is(err, orchestrator.ErrRMMActionInFlight) {
		t.Fatalf("a second action in flight = %v, want refused", err)
	}
	n.act(t, n.h.tenant, "1001", "remove", "remove-1001-a")
	runs = n.ninja.Runs()
	if len(runs) != 4 || runs[2].ScriptID != 32 || runs[3].ScriptID != 33 || runs[2].Parameters != "" || runs[3].Parameters != "" {
		t.Fatalf("upgrade and remove runs = %+v", runs[2:])
	}

	// No token anywhere it could be read back.
	for _, tok := range [][]byte{token, second} {
		if strings.Contains(n.logs.String(), string(tok)) {
			t.Fatal("the debug log carries an install token")
		}
		var leaked int
		if err := n.h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE position($1 in payload::text) > 0 OR position($1 in coalesce(last_error, '')) > 0`,
			string(tok)).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatalf("the outbox carries an install token (%d, %v)", leaked, err)
		}
		var events int
		if err := n.h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM provider_rmm_devices WHERE position($1 in action_reason) > 0`, string(tok)).Scan(&events); err != nil || events != 0 {
			t.Fatalf("the device record carries an install token (%d, %v)", events, err)
		}
	}
	if strings.Contains(n.logs.String(), n.secret) {
		t.Fatal("the debug log carries the client secret")
	}
}
