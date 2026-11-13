// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rmm"
	"trstctl.com/trstctl/internal/rmm/ninjaone"
	"trstctl.com/trstctl/internal/store"
)

// rmmAgentHealthFresh is how recently an agent must have connected to be
// reported healthy.
const rmmAgentHealthFresh = 30 * time.Minute

// RMMInstalledIdentity is the identity an agent installed through an RMM
// enrolls as: its one-time token is pinned to it, so the agent maps to its
// device exactly.
func RMMInstalledIdentity(targetID, deviceID string) string {
	return "rmm-" + targetID + "-" + deviceID
}

// rmmAgentHealth summarizes an agent for the RMM, coarse enough that it
// changes only when the agent's state does.
func rmmAgentHealth(a store.RMMAgent, now time.Time) string {
	version := strings.TrimSpace(a.Version)
	if version == "" {
		version = "unknown"
	}
	switch {
	case a.LastSeenAt == nil:
		return "trstctl agent enrolled, not yet connected"
	case now.Sub(*a.LastSeenAt) <= rmmAgentHealthFresh:
		return "trstctl agent healthy (version " + version + ")"
	default:
		return "trstctl agent not seen since " + a.LastSeenAt.UTC().Format("2006-01-02")
	}
}

// matchRMMDevices maps devices to the customer's agents: the agent installed
// through this target on this device (its pinned identity), else the one
// agent whose name is the device's host name; a host name two agents share
// maps neither.
func matchRMMDevices(targetID string, devices []rmm.Device, agents []store.RMMAgent, now time.Time) []projections.RMMDeviceEvent {
	byName := map[string][]store.RMMAgent{}
	byIdentity := map[string]store.RMMAgent{}
	for _, a := range agents {
		byIdentity[a.Name] = a
		key := strings.ToLower(strings.TrimSpace(a.Name))
		byName[key] = append(byName[key], a)
	}
	used := map[string]bool{}
	out := make([]projections.RMMDeviceEvent, 0, len(devices))
	for _, d := range devices {
		if a, ok := byIdentity[RMMInstalledIdentity(targetID, d.ID)]; ok {
			used[a.ID] = true
		}
	}
	for _, d := range devices {
		ev := projections.RMMDeviceEvent{TargetID: targetID, DeviceID: d.ID, DeviceName: truncateText(d.Name, 255), OrgID: d.OrgID, Present: true}
		if a, ok := byIdentity[RMMInstalledIdentity(targetID, d.ID)]; ok {
			ev.AgentID, ev.AgentMatch, ev.Health = a.ID, "installed", rmmAgentHealth(a, now)
		} else if candidates := byName[strings.ToLower(strings.TrimSpace(d.Name))]; d.Name != "" && len(candidates) == 1 && !used[candidates[0].ID] {
			a := candidates[0]
			used[a.ID] = true
			ev.AgentID, ev.AgentMatch, ev.Health = a.ID, "hostname", rmmAgentHealth(a, now)
		}
		out = append(out, ev)
	}
	return out
}

func truncateText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// handleRMMInventory lists a customer's devices under its mapped
// organization, maps them to its agents, reports changed health back to the
// RMM, and records what changed (MSP-9). Only devices the RMM lists under
// the customer's own organization are ever recorded or written to.
func (d *issuanceDispatcher) handleRMMInventory(ctx context.Context, m orchestrator.Message) error {
	var req orchestrator.RMMInventoryRequest
	if err := json.Unmarshal(m.Payload, &req); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode RMM inventory: %w", err))
	}
	if m.IdempotencyKey != orchestrator.RMMInventoryKey(req.TargetID, req.Bucket) {
		return orchestrator.DefiniteNoEffect(errors.New("server: RMM inventory key does not name its target and interval"))
	}
	target, ok := d.billingSync.Target(req.TargetID)
	if !ok || !target.IsRMM() {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: RMM target %q is no longer configured", req.TargetID))
	}
	if d.store == nil {
		return errors.New("server: RMM inventories need the store")
	}
	org, mapped, err := d.store.BillingCompanyFor(ctx, m.TenantID, target.ID)
	if err != nil {
		return err
	}
	if !mapped {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: the customer is no longer mapped in RMM target %q", target.ID))
	}
	agents, err := d.store.AgentsForRMM(ctx, m.TenantID)
	if err != nil {
		return err
	}
	recorded, err := d.store.RMMDevices(ctx, m.TenantID, 2000)
	if err != nil {
		return err
	}
	health := map[string]string{}
	for _, dev := range recorded {
		if dev.TargetID == target.ID && dev.Present {
			health[dev.DeviceID] = dev.Health
		}
	}
	now := time.Now().UTC()
	err = d.withRMMClient(target, func(c rmm.Client) error {
		devices, err := c.ListDevices(ctx, org)
		if err != nil {
			return err
		}
		own := devices[:0]
		for _, dev := range devices {
			if dev.OrgID == org {
				own = append(own, dev)
			}
		}
		observed := matchRMMDevices(target.ID, own, agents, now)
		for _, ev := range observed {
			if ev.Health == "" || ev.Health == health[ev.DeviceID] {
				continue
			}
			if err := c.ReportHealth(ctx, ev.DeviceID, ev.Health); err != nil {
				return err
			}
		}
		_, err = d.orch.RecordRMMInventory(ctx, m.TenantID, target.ID, observed)
		return err
	})
	if errors.Is(err, rmm.ErrBeforeWrite) {
		return orchestrator.DefiniteNoEffect(err)
	}
	return err
}

// withRMMClient resolves an RMM target's credentials for one delivery,
// hands fn its client, and wipes the credentials afterwards.
func (d *issuanceDispatcher) withRMMClient(target config.ProviderBillingTarget, fn func(rmm.Client) error) error {
	client, err := d.billingSyncHTTPClient(target)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: RMM target endpoint rejected: %w", err))
	}
	switch {
	case target.Type == "ninjaone" && target.NinjaOne != nil:
		n := target.NinjaOne
		secretValue, err := resolveDeploymentCredentialRef(n.ClientSecretRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the ninjaone target's client_secret_ref"))
		}
		defer secretValue.Destroy()
		c, err := ninjaone.New(ninjaone.Config{BaseURL: target.Endpoint, ClientID: n.ClientID, RunAs: n.RunAs, HealthField: n.HealthField,
			Scripts: map[rmm.Action]int64{rmm.ActionInstall: n.InstallScriptID, rmm.ActionUpgrade: n.UpgradeScriptID, rmm.ActionRemove: n.RemoveScriptID}},
			client, ninjaone.Credentials{ClientSecret: secretValue.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(c)
	default:
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: RMM target %q has no %s settings", target.ID, target.Type))
	}
}
