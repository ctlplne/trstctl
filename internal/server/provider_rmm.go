// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
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
	"trstctl.com/trstctl/internal/rmm/datto"
	"trstctl.com/trstctl/internal/rmm/ncentral"
	"trstctl.com/trstctl/internal/rmm/ninjaone"
	"trstctl.com/trstctl/internal/store"
)

// rmmAgentHealthFresh is how recently an agent must have connected to be
// reported healthy.
const rmmAgentHealthFresh = 30 * time.Minute

// rmmIdentityMax is the longest agent identity an install pins: the common
// name an agent's certificate carries is at most 64 characters.
const rmmIdentityMax = 64

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
			if strings.EqualFold(dev.OrgID, org) {
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

// rmmActionRefusal is a reason an action is refused before anything runs on
// the device.
type rmmActionRefusal struct{ reason string }

func (r rmmActionRefusal) Error() string { return "server: " + r.reason }

// handleRMMAction runs the agent action an operator requested on one of a
// customer's devices and records its outcome (MSP-9). It runs only the
// request still in flight, and only on a device the RMM lists under the
// customer's own organization at the moment of delivery: a device moved to
// another customer's organization never runs it. An install's one-time
// enrollment token is minted only then, for the customer's own tenant and
// pinned to the device's identity, handed to the RMM and wiped.
func (d *issuanceDispatcher) handleRMMAction(ctx context.Context, m orchestrator.Message) error {
	var req projections.RMMDeviceEvent
	if err := json.Unmarshal(m.Payload, &req); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode RMM action: %w", err))
	}
	eventID, ok := strings.CutPrefix(m.IdempotencyKey, "rmm-action:")
	if !ok || eventID == "" || projections.ValidateRMMDeviceEvent(projections.EventRMMDeviceActionRequested, req) != nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: RMM action key or payload does not name its request"))
	}
	if d.store == nil || d.orch == nil {
		return errors.New("server: RMM actions need the store and the orchestrator")
	}
	cur, found, err := d.store.RMMDeviceFor(ctx, m.TenantID, req.TargetID, req.DeviceID)
	if err != nil {
		return err
	}
	if !found || cur.ActionEventID != eventID || cur.ActionStatus != store.RMMActionRequested {
		return nil
	}
	record := func(ok bool, reason string) error {
		return d.orch.RecordRMMActionOutcome(ctx, m.TenantID, projections.RMMDeviceEvent{TargetID: req.TargetID, DeviceID: req.DeviceID,
			Action: req.Action, Request: eventID, OK: ok, Reason: reason})
	}
	target, ok := d.billingSync.Target(req.TargetID)
	if !ok || !target.IsRMM() {
		return record(false, "the RMM target is no longer configured")
	}
	org, mapped, err := d.store.BillingCompanyFor(ctx, m.TenantID, target.ID)
	if err != nil {
		return err
	}
	if !mapped {
		return record(false, "the customer is no longer mapped to an organization in this RMM")
	}
	action := rmm.Action(req.Action)
	identity := RMMInstalledIdentity(target.ID, req.DeviceID)
	if action == rmm.ActionInstall && (d.agentEnroll == nil || strings.TrimSpace(d.agentServer) == "") {
		return record(false, "the agent channel has no public address, so an installed agent would have nowhere to enroll")
	}
	if action == rmm.ActionInstall && len(identity) > rmmIdentityMax {
		return record(false, "the device's agent identity "+identity+" is longer than a certificate name allows; use a shorter target ID")
	}
	var token []byte
	defer func() { zeroBytes(token) }()
	err = d.withRMMClient(target, func(c rmm.Client) error {
		dev, listed, err := c.Device(ctx, req.DeviceID)
		if err != nil {
			return err
		}
		if !listed {
			return rmmActionRefusal{"the RMM no longer lists the device"}
		}
		if !strings.EqualFold(dev.OrgID, org) {
			return rmmActionRefusal{"the RMM lists the device under another organization than the customer's"}
		}
		var params *rmm.InstallParams
		if action == rmm.ActionInstall {
			if token, err = d.agentEnroll.IssueBootstrapTokenWithRoles(ctx, m.TenantID, identity, nil); err != nil {
				return err
			}
			params = &rmm.InstallParams{Server: d.agentServer, ServerName: d.agentServerName, Identity: identity, Token: token}
		}
		_, err = c.RunAction(ctx, req.DeviceID, action, params)
		return err
	})
	var refused rmmActionRefusal
	switch {
	case err == nil:
		return record(true, "")
	case errors.As(err, &refused):
		return record(false, refused.reason)
	case errors.Is(err, rmm.ErrBeforeWrite), errors.Is(err, rmm.ErrRefused), orchestrator.IsDefiniteNoEffect(err):
		return record(false, rmmActionErrorText(err, token))
	default:
		// The RMM's answer was lost or it is unavailable: retry. A retried
		// install mints a new one-time token; the script is expected to be
		// idempotent.
		return errors.New(rmmActionErrorText(err, token))
	}
}

// rmmActionErrorText is an action's error as recorded: bounded, with any echo
// of the install token removed.
func rmmActionErrorText(err error, token []byte) string {
	text := []byte(err.Error())
	if len(token) > 0 {
		text = bytes.ReplaceAll(text, token, []byte("[redacted]"))
	}
	return truncateText(string(text), 2000)
}

// withRMMClient resolves an RMM target's credentials for one delivery,
// hands fn its client, and wipes the credentials afterwards.
func (d *issuanceDispatcher) withRMMClient(target config.ProviderBillingTarget, fn func(rmm.Client) error) error {
	client, err := d.billingSyncHTTPClient(target)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: RMM target endpoint rejected: %w", err))
	}
	switch {
	case target.Type == "ncentral" && target.NCentral != nil:
		nc := target.NCentral
		jwt, err := resolveDeploymentCredentialRef(nc.UserJWTRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the ncentral target's user_jwt_ref"))
		}
		defer jwt.Destroy()
		c, err := ncentral.New(ncentral.Config{BaseURL: target.Endpoint, CredentialType: nc.CredentialType, HealthPropertyID: nc.HealthPropertyID,
			Scripts: map[rmm.Action]int64{rmm.ActionInstall: nc.InstallScriptID, rmm.ActionUpgrade: nc.UpgradeScriptID, rmm.ActionRemove: nc.RemoveScriptID}},
			client, ncentral.Credentials{UserJWT: jwt.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(c)
	case target.Type == "datto" && target.Datto != nil:
		dt := target.Datto
		keyValue, err := resolveDeploymentCredentialRef(dt.APIKeyRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the datto target's api_key_ref"))
		}
		defer keyValue.Destroy()
		secretValue, err := resolveDeploymentCredentialRef(dt.APISecretRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the datto target's api_secret_ref"))
		}
		defer secretValue.Destroy()
		c, err := datto.New(datto.Config{BaseURL: target.Endpoint, HealthUDF: dt.HealthUDF,
			Components: map[rmm.Action]string{rmm.ActionInstall: dt.InstallComponentUID, rmm.ActionUpgrade: dt.UpgradeComponentUID,
				rmm.ActionRemove: dt.RemoveComponentUID}},
			client, datto.Credentials{APIKey: keyValue.Bytes(), APISecret: secretValue.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(c)
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
