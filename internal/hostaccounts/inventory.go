// SPDX-License-Identifier: BUSL-1.1
// Package hostaccounts binds public local-SAM observations to one enrolled host.
package hostaccounts

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

const InventoryDestination = "host.windows_local_accounts.inventory"
const MaxInventoryReportBytes = 1 << 20

type InventoryIntent struct {
	RunID         string `json:"run_id"`
	TenantID      string `json:"tenant_id"`
	AgentID       string `json:"agent_id"`
	BindingDigest string `json:"binding_digest"`
}
type InventoryReport struct {
	RunID         string                 `json:"run_id"`
	BindingDigest string                 `json:"binding_digest"`
	ObservedAt    time.Time              `json:"observed_at"`
	Status        string                 `json:"status"`
	Failure       string                 `json:"failure,omitempty"`
	Inventory     *winaccounts.Inventory `json:"inventory,omitempty"`
}

func canonicalID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func (i InventoryIntent) digest() string {
	return crypto.SHA256Hex([]byte("trstctl/windows-local-accounts/inventory/v1\x00" + i.TenantID + "\x00" + i.AgentID + "\x00" + i.RunID))
}
func NewInventoryIntent(runID, tenantID, agentID string) (InventoryIntent, error) {
	value := InventoryIntent{RunID: runID, TenantID: tenantID, AgentID: agentID}
	value.BindingDigest = value.digest()
	return value, value.Validate()
}
func (i InventoryIntent) Validate() error {
	if !canonicalID(i.RunID) || !canonicalID(i.TenantID) || !canonicalID(i.AgentID) || i.BindingDigest != i.digest() {
		return errors.New("host accounts: exact enrolled-host inventory authority required")
	}
	return nil
}
func (r InventoryReport) Validate(i InventoryIntent) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if r.RunID != i.RunID || r.BindingDigest != i.BindingDigest || r.ObservedAt.IsZero() {
		return errors.New("host accounts: report differs from inventory authority")
	}
	switch r.Status {
	case "complete":
		if r.Inventory == nil || r.Failure != "" {
			return errors.New("host accounts: complete inventory required")
		}
		if err := r.Inventory.Validate(); err != nil {
			return err
		}
	case "unavailable":
		if r.Inventory != nil {
			return errors.New("host accounts: failed read must carry no partial accounts")
		}
		switch r.Failure {
		case "unsupported_os", "permission_denied", "native_read_failed", "cancelled", "limit_exceeded":
		default:
			return errors.New("host accounts: bounded native failure class required")
		}
	default:
		return errors.New("host accounts: explicit inventory completion state required")
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxInventoryReportBytes {
		return errors.New("host accounts: report exceeds wire bound")
	}
	return nil
}
