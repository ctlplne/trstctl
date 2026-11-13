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
	"trstctl.com/trstctl/internal/store"
)

// rmmProofRun is one agent action an RMM stand-in ran on a device.
type rmmProofRun struct {
	Device     string
	Action     string // install, upgrade or remove
	Server     string
	ServerName string
	Identity   string
	Token      string
}

// rmmProofCase is one RMM connector under the shared served proof: its
// target (ID set, endpoint the stand-in) and the stand-in's view of three
// devices, two under customer A's organization and one under B's.
type rmmProofCase struct {
	target     config.ProviderBillingTarget
	secret     string
	orgA, orgB string
	// mapA is what the operator mapped A to (orgA, possibly in another
	// form the RMM accepts).
	mapA          string
	a1, a2, b1    string
	a1Host        string
	b1Host        string
	health        func(device string) string
	runs          func() []rmmProofRun
	move          func(device, org string)
	refused       func() int
	reportsHealth bool
}

// runRMMConnectorProof is the MSP-9 Done-when for one RMM connector, served
// against its stand-in: each customer's devices are listed under its own
// organization only and mapped to its own agents; health reaches only the
// customer's own mapped devices; an install's token enrolls only an agent
// of that device's identity, only into the customer's own tenant, once; A
// cannot act on B's device; a device moved to B's organization after the
// inventory runs nothing; upgrade and remove run; neither the RMM credential
// nor the token reaches the debug log or the outbox.
func runRMMConnectorProof(t *testing.T, c rmmProofCase) {
	t.Helper()
	logs := captureDebugLog(t)
	ctx := context.Background()
	target := c.target
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
		d.AgentChannelPublicAddress, d.AgentChannelServerName = "agents.msp.example.test:8443", "agents.msp.example.test"
	})
	const customerB = "3e5f7a9b-1c2d-4e6f-8a0b-2c4d6e8f0a1b"
	registerServedTenant(t, h, target.ID+" customer A")
	registerServedTenantID(t, h, customerB, target.ID+" customer B")
	for tenant, org := range map[string]string{h.tenant: c.mapA, customerB: c.orgB} {
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, $2, $3, 'operator@example.test', now())`, tenant, target.ID, org); err != nil {
			t.Fatal(err)
		}
	}
	n := ninjaHarness{h: h}
	now := time.Now().UTC()
	aAgent := n.addAgent(t, h.tenant, c.a1Host, "1.4.2", &now)
	n.addAgent(t, h.tenant, c.b1Host, "1.4.2", &now) // A's agent named like B's device
	bAgent := n.addAgent(t, customerB, c.b1Host, "1.3.0", &now)
	bucket := now.Truncate(10 * time.Minute)
	for _, tenant := range []string{h.tenant, customerB} {
		if queued, err := h.srv.orch.QueueRMMInventory(ctx, tenant, target.ID, bucket); err != nil || !queued {
			t.Fatalf("queue inventory = %v %v", queued, err)
		}
		servedRMMDrain(t, h, tenant, orchestrator.DestinationRMMInventory, "the inventory")
	}
	a := servedRMMDevices(t, h, h.tenant)
	if len(a) != 2 || a[c.b1].DeviceID != "" || a[c.a1].AgentID != aAgent || a[c.a1].AgentMatch != "hostname" || a[c.a2].AgentID != "" {
		t.Fatalf("A's devices = %+v, want its two and never B's", a)
	}
	if b := servedRMMDevices(t, h, customerB); len(b) != 1 || b[c.b1].AgentID != bAgent {
		t.Fatalf("B's devices = %+v, want its one mapped to its own agent", b)
	}
	if c.reportsHealth {
		if got := c.health(c.a1); got != "trstctl agent healthy (version 1.4.2)" {
			t.Fatalf("A's device health = %q", got)
		}
		if got := c.health(c.b1); got != "trstctl agent healthy (version 1.3.0)" {
			t.Fatalf("B's device health = %q", got)
		}
		if got := c.health(c.a2); got != "" {
			t.Fatalf("an unmatched device got health %q", got)
		}
	}

	act := func(tenant, device, action, key string) {
		t.Helper()
		if _, err := h.srv.orch.QueueRMMAction(ctx, tenant, target.ID, device, action, "operator@msp.example.test", key); err != nil {
			t.Fatalf("queue %s on %s = %v", action, device, err)
		}
		servedRMMDrain(t, h, tenant, orchestrator.DestinationRMMAction, "the "+action)
	}
	act(h.tenant, c.a2, "install", "install-a2")
	runs := c.runs()
	identity := RMMInstalledIdentity(target.ID, c.a2)
	if len(runs) != 1 || runs[0].Device != c.a2 || runs[0].Action != "install" || runs[0].Server != "agents.msp.example.test:8443" ||
		runs[0].ServerName != "agents.msp.example.test" || runs[0].Identity != identity || runs[0].Token == "" {
		t.Fatalf("install runs = %+v", runs)
	}
	token := []byte(runs[0].Token)
	if d := servedRMMDevices(t, h, h.tenant)[c.a2]; d.ActionStatus != store.RMMActionDone {
		t.Fatalf("the installed device = %+v", d)
	}
	tenant, err := enrollAs(t, h, token, identity)
	if err != nil || tenant != h.tenant {
		t.Fatalf("the install token enrolled into %q (%v), want customer A %q", tenant, err, h.tenant)
	}
	if _, err := enrollAs(t, h, token, identity); err == nil {
		t.Fatal("the install token enrolled twice")
	}
	act(h.tenant, c.a2, "install", "install-a2-again")
	if runs := c.runs(); len(runs) != 2 || runs[1].Token == "" {
		t.Fatalf("second install runs = %+v", runs)
	} else if _, err := enrollAs(t, h, []byte(runs[1].Token), RMMInstalledIdentity(target.ID, c.b1)); err == nil {
		t.Fatal("an install token enrolled an agent of another device's identity")
	}

	if _, err := h.srv.orch.QueueRMMAction(ctx, h.tenant, target.ID, c.b1, "install", "operator@msp.example.test", "install-b1"); !errors.Is(err, orchestrator.ErrRMMDeviceUnknown) {
		t.Fatalf("A acting on B's device = %v, want refused", err)
	}
	act(h.tenant, c.a1, "upgrade", "upgrade-a1")
	act(h.tenant, c.a1, "remove", "remove-a1")
	if runs := c.runs(); len(runs) != 4 || runs[2].Action != "upgrade" || runs[3].Action != "remove" || runs[2].Token != "" || runs[3].Token != "" {
		t.Fatalf("upgrade and remove runs = %+v", runs)
	}
	c.move(c.a1, c.orgB)
	act(h.tenant, c.a1, "upgrade", "upgrade-a1-moved")
	if runs := c.runs(); len(runs) != 4 {
		t.Fatalf("a device moved to another organization ran: %+v", runs)
	}
	if d := servedRMMDevices(t, h, h.tenant)[c.a1]; d.ActionStatus != store.RMMActionFailed || !strings.Contains(d.ActionReason, "another organization") {
		t.Fatalf("the moved device = %+v", d)
	}

	for _, leak := range []string{c.secret, string(token)} {
		if strings.Contains(logs.String(), leak) {
			t.Fatal("the debug log carries the RMM credential or an install token")
		}
		var leaked int
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE position($1 in payload::text) > 0 OR position($1 in coalesce(last_error, '')) > 0`,
			leak).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatalf("the outbox carries a secret (%d, %v)", leaked, err)
		}
	}
	if refused := c.refused(); refused != 0 {
		t.Fatalf("the RMM refused %d requests", refused)
	}
}
