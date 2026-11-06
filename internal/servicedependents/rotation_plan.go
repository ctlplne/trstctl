// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"unicode"
	"unicode/utf8"
)

const RotationPlanVersion = 1
const MaxRotationPlanBytes = 1 << 20
const RotationInventoryMaxAge = 15 * time.Minute

// RotationHostInput is admission evidence, read from retained signed scans.
// The durable plan stores references and public native summaries, not report copies.
type RotationHostInput struct {
	Binding         HostBinding
	Inventory       InventoryReport
	InventoryDigest string
}
type DependentRef struct {
	AgentID string `json:"agent_id"`
	Family  string `json:"family"`
	Name    string `json:"name"`
}
type RotationHost struct {
	Binding         HostBinding    `json:"binding"`
	InventoryRunID  string         `json:"inventory_run_id"`
	InventoryDigest string         `json:"inventory_digest"`
	ObservedAt      time.Time      `json:"observed_at"`
	Dependents      []DependentRef `json:"dependents"`
}
type RotationPlan struct {
	Version    int            `json:"version"`
	ID         string         `json:"id"`
	Account    AccountBinding `json:"account"`
	SecretName string         `json:"secret_name"`
	Hosts      []RotationHost `json:"hosts"`
	Order      []DependentRef `json:"order"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Digest     string         `json:"digest"`
}

func dependentKey(ref DependentRef) string {
	return ref.AgentID + "\x00" + ref.Family + "\x00" + ref.Name
}
func inventoryReferences(binding HostBinding, report InventoryReport) []DependentRef {
	refs := make([]DependentRef, 0, len(report.Services)+len(report.Tasks)+len(report.Pools))
	for _, target := range report.Services {
		refs = append(refs, DependentRef{binding.AgentID, "services", target.Name})
	}
	for _, target := range report.Tasks {
		refs = append(refs, DependentRef{binding.AgentID, "tasks", target.Path})
	}
	for _, target := range report.Pools {
		refs = append(refs, DependentRef{binding.AgentID, "iis", target.Name})
	}
	sort.Slice(refs, func(i, j int) bool { return dependentKey(refs[i]) < dependentKey(refs[j]) })
	return refs
}
func NewRotationPlan(id string, account AccountBinding, secretName string, inputs []RotationHostInput, order []DependentRef, now time.Time) (RotationPlan, error) {
	plan := RotationPlan{Version: RotationPlanVersion, ID: id, Account: account, SecretName: secretName, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(RotationInventoryMaxAge)}
	if now.IsZero() || len(inputs) == 0 {
		return RotationPlan{}, errors.New("service dependents: bounded complete host inventory required")
	}
	for _, input := range inputs {
		if input.Binding.Account != account || !input.Binding.Enabled {
			return RotationPlan{}, errors.New("service dependents: another or disabled host/account binding")
		}
		intent, err := NewInventoryIntent(input.Inventory.RunID, input.Binding)
		if err != nil {
			return RotationPlan{}, err
		}
		if err = input.Inventory.Validate(intent); err != nil {
			return RotationPlan{}, err
		}
		if !input.Inventory.Complete() {
			return RotationPlan{}, errors.New("service dependents: all three native families must be observed before a reset")
		}
		if input.Inventory.ObservedAt.Before(now.Add(-RotationInventoryMaxAge)) || input.Inventory.ObservedAt.After(now.Add(time.Minute)) {
			return RotationPlan{}, errors.New("service dependents: native inventory is stale or from a future clock")
		}
		raw, err := json.Marshal(input.Inventory)
		if err != nil || crypto.SHA256Hex(raw) != input.InventoryDigest {
			return RotationPlan{}, errors.New("service dependents: retained native inventory digest differs")
		}
		expires := input.Inventory.ObservedAt.Add(RotationInventoryMaxAge)
		if expires.Before(plan.ExpiresAt) {
			plan.ExpiresAt = expires
		}
		plan.Hosts = append(plan.Hosts, RotationHost{Binding: input.Binding, InventoryRunID: input.Inventory.RunID, InventoryDigest: input.InventoryDigest, ObservedAt: input.Inventory.ObservedAt, Dependents: inventoryReferences(input.Binding, input.Inventory)})
	}
	sort.Slice(plan.Hosts, func(i, j int) bool { return plan.Hosts[i].Binding.AgentID < plan.Hosts[j].Binding.AgentID })
	plan.Order = append([]DependentRef(nil), order...)
	digest, err := plan.contentDigest()
	if err != nil {
		return RotationPlan{}, err
	}
	plan.Digest = digest
	if err = plan.Validate(); err != nil {
		return RotationPlan{}, err
	}
	return plan, nil
}
func (p RotationPlan) contentDigest() (string, error) {
	p.Digest = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxRotationPlanBytes {
		return "", errors.New("service dependents: reviewed plan exceeds bounded request size")
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-account.rotation-plan.v1\x00"), raw...)), nil
}
func (p RotationPlan) Validate() error {
	if p.Version != RotationPlanVersion || !canonicalID(p.ID) || p.Account.Validate() != nil || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.After(p.CreatedAt.Add(RotationInventoryMaxAge)) || len(p.Hosts) == 0 {
		return errors.New("service dependents: incomplete reviewed rotation plan")
	}
	if len(p.SecretName) == 0 || len(p.SecretName) > 512 || strings.TrimSpace(p.SecretName) != p.SecretName || !utf8.ValidString(p.SecretName) {
		return errors.New("service dependents: exact application secret reference required")
	}
	for _, c := range p.SecretName {
		if unicode.IsControl(c) {
			return errors.New("service dependents: invalid application secret reference")
		}
	}
	hosts := map[string]bool{}
	expected := map[string]bool{}
	previous := ""
	for _, host := range p.Hosts {
		if host.Binding.Validate() != nil || !host.Binding.Enabled || host.Binding.Account != p.Account || hosts[host.Binding.AgentID] || (previous != "" && previous >= host.Binding.AgentID) || !canonicalID(host.InventoryRunID) || !rotationDigestValid(host.InventoryDigest) || host.ObservedAt.IsZero() || host.ObservedAt.Before(p.CreatedAt.Add(-RotationInventoryMaxAge)) || host.ObservedAt.After(p.CreatedAt.Add(time.Minute)) || p.ExpiresAt.After(host.ObservedAt.Add(RotationInventoryMaxAge)) {
			return errors.New("service dependents: host inventory source binding differs")
		}
		hosts[host.Binding.AgentID] = true
		previous = host.Binding.AgentID
		if len(host.Dependents) > 768 {
			return errors.New("service dependents: native reference count exceeds per-host bound")
		}
		for _, ref := range host.Dependents {
			if ref.AgentID != host.Binding.AgentID || (ref.Family != "services" && ref.Family != "tasks" && ref.Family != "iis") || len(ref.Name) == 0 || len(ref.Name) > 4096 || !utf8.ValidString(ref.Name) {
				return errors.New("service dependents: native object reference differs")
			}
			key := dependentKey(ref)
			if expected[key] {
				return errors.New("service dependents: duplicate native dependent")
			}
			expected[key] = true
		}
	}
	if len(expected) == 0 || len(p.Order) != len(expected) {
		return errors.New("service dependents: reviewed order must cover every discovered native dependent")
	}
	for _, ref := range p.Order {
		key := dependentKey(ref)
		if !expected[key] {
			return errors.New("service dependents: reviewed order omits or substitutes a dependent")
		}
		delete(expected, key)
	}
	digest, err := p.contentDigest()
	if err != nil {
		return err
	}
	if digest != p.Digest {
		return errors.New("service dependents: reviewed rotation plan digest differs")
	}
	return nil
}

func rotationDigestValid(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == strings.ToLower(value)
}
