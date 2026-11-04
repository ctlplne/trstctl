// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Renewal waves of a switching import (A265): a wave cut over, naming the one
// identity trstctl keeps for each of its rows, and a wave rolled back.
const (
	EventSwitchingWaveCutOver    = "switching.wave.cut_over"
	EventSwitchingWaveRolledBack = "switching.wave.rolled_back"
)

// SwitchingWaveCutOver is the payload of switching.wave.cut_over.
type SwitchingWaveCutOver struct {
	WaveID        string                   `json:"wave_id"`
	ImportID      string                   `json:"import_id"`
	Name          string                   `json:"name"`
	IssuerID      string                   `json:"issuer_id"`
	PreviewDigest string                   `json:"preview_digest"`
	Rows          []store.SwitchingWaveRow `json:"rows"`
	CreatedBy     string                   `json:"created_by"`
}

// SwitchingWaveRolledBack is the payload of switching.wave.rolled_back.
type SwitchingWaveRolledBack struct {
	WaveID       string `json:"wave_id"`
	Reason       string `json:"reason"`
	RolledBackBy string `json:"rolled_back_by"`
}

func init() {
	for _, typ := range []string{EventSwitchingWaveCutOver, EventSwitchingWaveRolledBack} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applySwitchingWaveTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventSwitchingWaveCutOver:
		var d SwitchingWaveCutOver
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return true, p.store.ApplySwitchingWaveCutOverTx(ctx, tx, e.TenantID, store.SwitchingWave{
			ID: d.WaveID, ImportID: d.ImportID, Name: d.Name, IssuerID: d.IssuerID,
			PreviewDigest: d.PreviewDigest, CreatedBy: d.CreatedBy, CreatedAt: e.Time,
		}, d.Rows, e.Sequence)
	case EventSwitchingWaveRolledBack:
		var d SwitchingWaveRolledBack
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return true, p.store.ApplySwitchingWaveRolledBackTx(ctx, tx, e.TenantID, d.WaveID, d.RolledBackBy, d.Reason, e.Time, e.Sequence)
	}
	return false, nil
}

func addSwitchingWavePrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		text   = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventSwitchingWaveCutOver, 1}] = privacyRules(
		privacyRule("/wave_id", opaque), privacyRule("/import_id", opaque), privacyRule("/name", text),
		privacyRule("/issuer_id", opaque), privacyRule("/preview_digest", opaque), privacyRule("/rows/*/row_number", opaque),
		privacyRule("/rows/*/identity_id", opaque), privacyRule("/rows/*/target_id", opaque),
		privacyRule("/rows/*/imported_fingerprint", opaque), privacyRule("/created_by", exact))
	policies[privacyEventPolicyKey{EventSwitchingWaveRolledBack, 1}] = privacyRules(
		privacyRule("/wave_id", opaque), privacyRule("/reason", text), privacyRule("/rolled_back_by", exact))
}

func addSwitchingWavePrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSwitchingWaveCutOver, 1}] = privacyPayloadShape[SwitchingWaveCutOver]()
	shapes[privacyEventPolicyKey{EventSwitchingWaveRolledBack, 1}] = privacyPayloadShape[SwitchingWaveRolledBack]()
}
