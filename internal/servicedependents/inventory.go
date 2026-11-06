// SPDX-License-Identifier: BUSL-1.1
// Package servicedependents binds account-dependent inventory and effects to
// exact directory and enrolled-host identities. Its wire values contain public
// metadata and configuration hashes, never credentials or private arguments.
package servicedependents

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"unicode/utf8"
)

const InventoryDestination = "host.windows_dependents.inventory"
const MaxInventoryReportBytes = 1 << 20

type AccountBinding struct {
	AccountID  string `json:"account_id"`
	ProviderID string `json:"provider_id"`
	Name       string `json:"name"`
	DN         string `json:"dn"`
	SID        string `json:"sid"`
	GUID       string `json:"guid"`
}
type HostBinding struct {
	Account  AccountBinding `json:"account"`
	AgentID  string         `json:"agent_id"`
	Revision int64          `json:"revision"`
	Enabled  bool           `json:"enabled"`
}
type InventoryIntent struct {
	RunID         string      `json:"run_id"`
	Binding       HostBinding `json:"binding"`
	BindingDigest string      `json:"binding_digest"`
}
type FamilyCoverage struct {
	Family  string `json:"family"`
	Status  string `json:"status"`
	Failure string `json:"failure,omitempty"`
}
type InventoryReport struct {
	RunID         string                  `json:"run_id"`
	BindingDigest string                  `json:"binding_digest"`
	ObservedAt    time.Time               `json:"observed_at"`
	Coverage      []FamilyCoverage        `json:"coverage"`
	Services      []windependents.Service `json:"services,omitempty"`
	Tasks         []windependents.Task    `json:"tasks,omitempty"`
	Pools         []windependents.Pool    `json:"pools,omitempty"`
}

func canonicalID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func (binding AccountBinding) Validate() error {
	if !canonicalID(binding.AccountID) || len(binding.ProviderID) == 0 || len(binding.ProviderID) > 256 || strings.TrimSpace(binding.ProviderID) != binding.ProviderID || !utf8.ValidString(binding.ProviderID) || len(binding.DN) > 4096 {
		return errors.New("service dependents: exact account source required")
	}
	for _, r := range binding.ProviderID {
		if r < 32 || r == 127 {
			return errors.New("service dependents: invalid provider identity")
		}
	}
	return pamdiscovery.ValidateNativeADIdentity(pamdiscovery.Account{Key: "user:" + strings.ToLower(binding.Name), Name: binding.Name, Details: map[string]string{"dn": binding.DN, "native_sid": binding.SID, "native_guid": binding.GUID}})
}
func (binding HostBinding) Validate() error {
	if err := binding.Account.Validate(); err != nil {
		return err
	}
	if !canonicalID(binding.AgentID) || binding.Revision <= 0 {
		return errors.New("service dependents: exact enrolled host revision required")
	}
	return nil
}
func (binding HostBinding) Digest() (string, error) {
	if err := binding.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl/service-dependents/host-binding/v1\x00"), raw...)), nil
}
func NewInventoryIntent(runID string, binding HostBinding) (InventoryIntent, error) {
	digest, err := binding.Digest()
	if err != nil {
		return InventoryIntent{}, err
	}
	intent := InventoryIntent{RunID: runID, Binding: binding, BindingDigest: digest}
	return intent, intent.Validate()
}
func (intent InventoryIntent) Validate() error {
	digest, err := intent.Binding.Digest()
	if err != nil {
		return err
	}
	if !canonicalID(intent.RunID) || !intent.Binding.Enabled || intent.BindingDigest != digest {
		return errors.New("service dependents: stale or incomplete inventory authority")
	}
	return nil
}
func (report InventoryReport) Validate(intent InventoryIntent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if report.RunID != intent.RunID || report.BindingDigest != intent.BindingDigest || report.ObservedAt.IsZero() || len(report.Coverage) != 3 || len(report.Services) > 256 || len(report.Tasks) > 256 || len(report.Pools) > 256 {
		return errors.New("service dependents: report does not match exact inventory authority")
	}
	seen := map[string]bool{}
	for _, coverage := range report.Coverage {
		if seen[coverage.Family] {
			return errors.New("service dependents: duplicate family coverage")
		}
		seen[coverage.Family] = true
		count := 0
		switch coverage.Family {
		case "services":
			count = len(report.Services)
		case "tasks":
			count = len(report.Tasks)
		case "iis":
			count = len(report.Pools)
		default:
			return errors.New("service dependents: unknown family coverage")
		}
		switch coverage.Status {
		case "complete":
			if coverage.Failure != "" {
				return errors.New("service dependents: completed family reports a failure")
			}
		case "unavailable":
			if count != 0 {
				return errors.New("service dependents: unavailable family carries incomplete native rows")
			}
			switch coverage.Failure {
			case "not_installed", "permission_denied", "unsupported_os", "native_read_failed", "cancelled", "limit_exceeded":
			default:
				return errors.New("service dependents: missing bounded coverage failure")
			}
		default:
			return errors.New("service dependents: missing family completion state")
		}
	}
	sid := intent.Binding.Account.SID
	names := map[string]bool{}
	for _, service := range report.Services {
		key := strings.ToLower(service.Name)
		if windependents.ValidateServiceSnapshot(service) != nil || service.AccountSID != sid || names[key] {
			return errors.New("service dependents: invalid or foreign native service")
		}
		names[key] = true
	}
	names = map[string]bool{}
	for _, task := range report.Tasks {
		key := strings.ToLower(task.Path)
		if windependents.ValidateTaskSnapshot(task) != nil || task.AccountSID != sid || names[key] {
			return errors.New("service dependents: invalid or foreign native task")
		}
		names[key] = true
	}
	names = map[string]bool{}
	for _, pool := range report.Pools {
		key := strings.ToLower(pool.Name)
		if windependents.ValidatePoolSnapshot(pool) != nil || pool.AccountSID != sid || names[key] {
			return errors.New("service dependents: invalid or foreign native pool")
		}
		names[key] = true
	}
	raw, err := json.Marshal(report)
	if err != nil || len(raw) > MaxInventoryReportBytes {
		return errors.New("service dependents: inventory report exceeds wire bound")
	}
	return nil
}
func (report InventoryReport) Complete() bool {
	if len(report.Coverage) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range report.Coverage {
		if value.Status != "complete" || value.Failure != "" || seen[value.Family] {
			return false
		}
		if value.Family != "services" && value.Family != "tasks" && value.Family != "iis" {
			return false
		}
		seen[value.Family] = true
	}
	return true
}
