// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Key Vault disables (N2): a disable of one certificate version requested, and
// the vault's readback that the version is disabled. Neither is a revocation.
const (
	EventKeyVaultDisableRequested = "certificate.key_vault_disable_requested"
	EventKeyVaultDisabled         = "certificate.key_vault_disabled"
)

// KeyVaultDisableRequested is the payload of certificate.key_vault_disable_requested.
type KeyVaultDisableRequested struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	ResourceID    string `json:"resource_id"`
	SourceID      string `json:"source_id"`
	Reason        string `json:"reason"`
	RequestedBy   string `json:"requested_by"`
}

// KeyVaultDisabled is the payload of certificate.key_vault_disabled.
type KeyVaultDisabled struct {
	ID             string     `json:"id"`
	VaultUpdatedAt *time.Time `json:"vault_updated_at,omitempty"`
}

// ValidateKeyVaultDisableRequested checks a requested disable's closed shape.
func ValidateKeyVaultDisableRequested(r KeyVaultDisableRequested) error {
	if r.ID == "" || r.CertificateID == "" || r.ResourceID == "" || r.SourceID == "" || r.RequestedBy == "" {
		return errors.New("projections: a Key Vault disable names its id, certificate, version, discovery source and requester")
	}
	return nil
}

func init() {
	for _, typ := range []string{EventKeyVaultDisableRequested, EventKeyVaultDisabled} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applyKeyVaultDisableTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventKeyVaultDisableRequested:
		var r KeyVaultDisableRequested
		if err := json.Unmarshal(e.Data, &r); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := ValidateKeyVaultDisableRequested(r); err != nil {
			return true, err
		}
		return true, p.store.ApplyKeyVaultDisableRequestedTx(ctx, tx, e.TenantID, store.KeyVaultDisable{ID: r.ID,
			CertificateID: r.CertificateID, ResourceID: r.ResourceID, SourceID: r.SourceID, Reason: r.Reason,
			RequestedBy: r.RequestedBy, RequestedAt: e.Time}, e.Sequence)
	case EventKeyVaultDisabled:
		var d KeyVaultDisabled
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return true, p.store.ApplyKeyVaultDisabledTx(ctx, tx, e.TenantID, d.ID, d.VaultUpdatedAt, e.Time, e.Sequence)
	}
	return false, nil
}

func addKeyVaultDisablePrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		clear  = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventKeyVaultDisableRequested, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/certificate_id", opaque), privacyRule("/resource_id", opaque),
		privacyRule("/source_id", opaque), privacyRule("/reason", clear), privacyRule("/requested_by", exact))
	policies[privacyEventPolicyKey{EventKeyVaultDisabled, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/vault_updated_at", opaque))
}

func addKeyVaultDisablePrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventKeyVaultDisableRequested, 1}] = privacyPayloadShape[KeyVaultDisableRequested]()
	shapes[privacyEventPolicyKey{EventKeyVaultDisabled, 1}] = privacyPayloadShape[KeyVaultDisabled]()
}
