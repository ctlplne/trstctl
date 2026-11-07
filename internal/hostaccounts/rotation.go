// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

const RotationDestination = "host.windows_local_accounts.rotate"
const RotationOldCredentialName = "windows_local_account_old_password"
const RotationNewCredentialName = "windows_local_account_new_password"
const MaxRotationIntentBytes = 16 << 10
const MaxRotationReportBytes = 32 << 10

// RotationIntent contains public authority only. Queued time is not a native
// deadline: an offline host must execute this same generation on its return.
// A live delivery lease bounds credential redemption and native execution.
type RotationIntent struct {
	RotationID              string                      `json:"rotation_id"`
	AccountID               string                      `json:"account_id"`
	TenantID                string                      `json:"tenant_id"`
	AgentID                 string                      `json:"agent_id"`
	InventoryRunID          string                      `json:"inventory_run_id"`
	PredecessorGenerationID string                      `json:"predecessor_generation_id"`
	Native                  winaccounts.RotationBinding `json:"native"`
	BindingDigest           string                      `json:"binding_digest"`
}

func (i RotationIntent) digest() string {
	i.BindingDigest = ""
	raw, _ := json.Marshal(i)
	return crypto.SHA256Hex(append([]byte("trstctl/windows-local-accounts/rotation/v1\x00"), raw...))
}
func NewRotationIntent(i RotationIntent) (RotationIntent, error) {
	i.BindingDigest = i.digest()
	return i, i.Validate()
}
func (i RotationIntent) Validate() error {
	if !canonicalID(i.RotationID) || !canonicalID(i.AccountID) || !canonicalID(i.TenantID) || !canonicalID(i.AgentID) || !canonicalID(i.InventoryRunID) || i.PredecessorGenerationID == i.RotationID || i.PredecessorGenerationID != "" && !canonicalID(i.PredecessorGenerationID) || i.Native.Validate() != nil || i.BindingDigest != i.digest() {
		return errors.New("host accounts: exact enrolled-host native rotation authority required")
	}
	return nil
}

// RotationGrant is operator-owned and local. No wildcard, remote SAM, domain
// account or inventory-read permission can imply this password-write authority.
type RotationGrant struct {
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	MachineSID string `json:"machine_sid"`
	AccountSID string `json:"account_sid"`
}

func (g RotationGrant) Validate() error {
	b := winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "local", SID: g.MachineSID, Role: 3}, Account: winaccounts.Account{Name: "local", SID: g.AccountSID, Enabled: true, PasswordRequired: true}}
	if !canonicalID(g.TenantID) || !canonicalID(g.AgentID) || b.Validate() != nil {
		return errors.New("host accounts: one exact tenant, enrolled host and local SAM SID are required for a write grant")
	}
	return nil
}
func (g RotationGrant) Allows(i RotationIntent) bool {
	return g.Validate() == nil && i.Validate() == nil && g.TenantID == i.TenantID && g.AgentID == i.AgentID && g.MachineSID == i.Native.Machine.SID && g.AccountSID == i.Native.Account.SID
}

type RotationReport struct {
	RotationID    string                     `json:"rotation_id"`
	BindingDigest string                     `json:"binding_digest"`
	ObservedAt    time.Time                  `json:"observed_at"`
	Status        string                     `json:"status"`
	Failure       string                     `json:"failure,omitempty"`
	Proof         *winaccounts.RotationProof `json:"proof,omitempty"`
}

func (r RotationReport) validShape() bool {
	if !canonicalID(r.RotationID) || len(r.BindingDigest) != 64 || r.ObservedAt.IsZero() {
		return false
	}
	switch r.Status {
	case "succeeded":
		return r.Failure == "" && r.Proof != nil && r.Proof.Binding.Validate() == nil && r.Proof.GenerationID == r.RotationID && r.Proof.NewAuthenticated && r.Proof.OldRefused && r.Proof.ObservedAt.Equal(r.ObservedAt)
	case "uncertain":
		return r.Proof == nil && (r.Failure == "execution_uncertain" || r.Failure == "journal_unavailable" || r.Failure == "native_operation_failed")
	case "refused":
		if r.Proof != nil {
			return false
		}
		switch r.Failure {
		case "local_grant_absent", "identity_mismatch", "unsupported_os", "credential_unavailable", "native_precondition_refused", "worker_busy", "cancelled":
			return true
		}
	}
	return false
}
func (r RotationReport) Validate(i RotationIntent) error {
	if i.Validate() != nil || r.RotationID != i.RotationID || r.BindingDigest != i.BindingDigest || !r.validShape() || r.Proof != nil && r.Proof.Binding != i.Native {
		return errors.New("host accounts: native rotation report differs from exact authority or proof")
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxRotationReportBytes {
		return errors.New("host accounts: native rotation report exceeds wire bound")
	}
	return nil
}

// RotationObservationSourceID preserves one signed result per real claim attempt.
func RotationObservationSourceID(tenantID string, jobID int64, attempt int) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("trstctl/windows-local-rotation/observed/%s/%d/%d", tenantID, jobID, attempt))).String()
}
