// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Switching imports (A265): an import started with its mapping report's
// counts, its rows recorded in batches, the rows that became certificates and
// owners, and its completion. A row carries the export's metadata only.
const (
	EventSwitchingImportStarted      = "switching.import.started"
	EventSwitchingImportRowsRecorded = "switching.import.rows_recorded"
	EventSwitchingImportRowsApplied  = "switching.import.rows_applied"
	EventSwitchingImportCompleted    = "switching.import.completed"
	// The endpoint watch: a round started, and one batch of its observations.
	EventSwitchingWatchRequested = "switching.import.watch_requested"
	EventSwitchingWatchObserved  = "switching.import.watch_observed"
	SwitchingImportRowsPerEvent  = 250
)

// SwitchingImportStarted is the payload of switching.import.started.
type SwitchingImportStarted struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Format        string         `json:"format"`
	PreviewDigest string         `json:"preview_digest"`
	RowsTotal     int            `json:"rows_total"`
	Counts        map[string]int `json:"counts"`
	GapCounts     map[string]int `json:"gap_counts"`
	CreatedBy     string         `json:"created_by"`
}

// SwitchingImportRowsRecorded is the payload of switching.import.rows_recorded.
type SwitchingImportRowsRecorded struct {
	ImportID string                     `json:"import_id"`
	Rows     []store.SwitchingImportRow `json:"rows"`
}

// SwitchingImportRowsApplied is the payload of switching.import.rows_applied.
type SwitchingImportRowsApplied struct {
	ImportID string                      `json:"import_id"`
	Rows     []store.SwitchingRowApplied `json:"rows"`
}

// SwitchingImportCompleted is the payload of switching.import.completed.
type SwitchingImportCompleted struct {
	ImportID string    `json:"import_id"`
	At       time.Time `json:"at"`
}

// SwitchingWatchRequested is the payload of switching.import.watch_requested.
type SwitchingWatchRequested struct {
	ImportID             string   `json:"import_id"`
	Round                int      `json:"round"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
	RequestedBy          string   `json:"requested_by"`
}

// SwitchingWatchObserved is the payload of switching.import.watch_observed.
type SwitchingWatchObserved struct {
	ImportID string                       `json:"import_id"`
	Round    int                          `json:"round"`
	Rows     []store.SwitchingWatchResult `json:"rows"`
}

func init() {
	for _, typ := range []string{EventSwitchingImportStarted, EventSwitchingImportRowsRecorded, EventSwitchingImportRowsApplied,
		EventSwitchingImportCompleted, EventSwitchingWatchRequested, EventSwitchingWatchObserved} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applySwitchingImportTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	decode := func(v any) error {
		if err := json.Unmarshal(e.Data, v); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return nil
	}
	switch e.Type {
	case EventSwitchingImportStarted:
		var d SwitchingImportStarted
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySwitchingImportStartedTx(ctx, tx, e.TenantID, store.SwitchingImport{
			ID: d.ID, Name: d.Name, Format: d.Format, PreviewDigest: d.PreviewDigest, RowsTotal: d.RowsTotal,
			Counts: d.Counts, GapCounts: d.GapCounts, CreatedBy: d.CreatedBy, CreatedAt: e.Time,
		}, e.Sequence)
	case EventSwitchingImportRowsRecorded:
		var d SwitchingImportRowsRecorded
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySwitchingImportRowsRecordedTx(ctx, tx, e.TenantID, d.ImportID, d.Rows, e.Sequence)
	case EventSwitchingImportRowsApplied:
		var d SwitchingImportRowsApplied
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySwitchingImportRowsAppliedTx(ctx, tx, e.TenantID, d.ImportID, d.Rows, e.Time, e.Sequence)
	case EventSwitchingImportCompleted:
		var d SwitchingImportCompleted
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySwitchingImportCompletedTx(ctx, tx, e.TenantID, d.ImportID, e.Time, e.Sequence)
	case EventSwitchingWatchRequested:
		var d SwitchingWatchRequested
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySwitchingWatchRequestedTx(ctx, tx, e.TenantID, d.ImportID, d.Round, d.AllowPrivateEndpoint,
			d.PrivateEgressCIDRs, d.RequestedBy, e.Time, e.Sequence)
	case EventSwitchingWatchObserved:
		var d SwitchingWatchObserved
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySwitchingWatchObservedTx(ctx, tx, e.TenantID, d.ImportID, d.Round, d.Rows, e.Time, e.Sequence)
	}
	return false, nil
}

func addSwitchingImportPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		text   = events.PrivacyFieldFreeTextClear
		token  = events.PrivacyFieldSubjectToken
	)
	policies[privacyEventPolicyKey{EventSwitchingImportStarted, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", text), privacyRule("/format", opaque), privacyRule("/preview_digest", opaque),
		privacyRule("/rows_total", opaque), privacyRule("/counts/*", opaque), privacyRule("/gap_counts/*", opaque),
		privacyRule("/created_by", exact))
	policies[privacyEventPolicyKey{EventSwitchingImportRowsRecorded, 1}] = privacyRules(
		privacyRule("/import_id", opaque), privacyRule("/rows/*/row_number", opaque), privacyRule("/rows/*/outcome", opaque),
		privacyRule("/rows/*/gaps/*", text), privacyRule("/rows/*/reason", text), privacyRule("/rows/*/duplicate_of", opaque),
		privacyRule("/rows/*/fingerprint", opaque), privacyRule("/rows/*/common_name", token), privacyRule("/rows/*/sans/*", token),
		privacyRule("/rows/*/key_algorithm", opaque), privacyRule("/rows/*/serial", opaque), privacyRule("/rows/*/issuer", opaque),
		privacyRule("/rows/*/certificate_der", opaque), privacyRule("/rows/*/not_after", opaque), privacyRule("/rows/*/folder", text),
		privacyRule("/rows/*/profile", opaque), privacyRule("/rows/*/application", text), privacyRule("/rows/*/owner_email", exact),
		privacyRule("/rows/*/endpoints/*", text))
	policies[privacyEventPolicyKey{EventSwitchingImportRowsApplied, 1}] = privacyRules(
		privacyRule("/import_id", opaque), privacyRule("/rows/*/row_number", opaque), privacyRule("/rows/*/certificate_id", opaque),
		privacyRule("/rows/*/owner_id", opaque), privacyRule("/rows/*/linked", opaque))
	policies[privacyEventPolicyKey{EventSwitchingImportCompleted, 1}] = privacyRules(
		privacyRule("/import_id", opaque), privacyRule("/at", opaque))
	policies[privacyEventPolicyKey{EventSwitchingWatchRequested, 1}] = privacyRules(
		privacyRule("/import_id", opaque), privacyRule("/round", opaque), privacyRule("/allow_private_endpoint", opaque),
		privacyRule("/private_egress_cidrs/*", opaque), privacyRule("/requested_by", exact))
	policies[privacyEventPolicyKey{EventSwitchingWatchObserved, 1}] = privacyRules(
		privacyRule("/import_id", opaque), privacyRule("/round", opaque), privacyRule("/rows/*/row_number", opaque),
		privacyRule("/rows/*/status", opaque), privacyRule("/rows/*/endpoint", text), privacyRule("/rows/*/served_fingerprint", opaque),
		privacyRule("/rows/*/detail", text))
}

func addSwitchingImportPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSwitchingImportStarted, 1}] = privacyPayloadShape[SwitchingImportStarted]()
	shapes[privacyEventPolicyKey{EventSwitchingImportRowsRecorded, 1}] = privacyPayloadShape[SwitchingImportRowsRecorded]()
	shapes[privacyEventPolicyKey{EventSwitchingImportRowsApplied, 1}] = privacyPayloadShape[SwitchingImportRowsApplied]()
	shapes[privacyEventPolicyKey{EventSwitchingImportCompleted, 1}] = privacyPayloadShape[SwitchingImportCompleted]()
	shapes[privacyEventPolicyKey{EventSwitchingWatchRequested, 1}] = privacyPayloadShape[SwitchingWatchRequested]()
	shapes[privacyEventPolicyKey{EventSwitchingWatchObserved, 1}] = privacyPayloadShape[SwitchingWatchObserved]()
}
