// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventTLSFindingCompleted         = "licensed_crypto.migration.tls_finding_completed"
	EventTLSFindingRollbackCompleted = "licensed_crypto.migration.tls_finding_rollback_completed"
	EventTLSFindingFailed            = "licensed_crypto.migration.tls_finding_failed"
)

const (
	TLSFindingQueued         = "queued"
	TLSFindingApplied        = "applied"
	TLSFindingFailed         = "failed"
	TLSFindingRolledBack     = "rolled_back"
	TLSFindingRollbackFailed = "rollback_failed"
)

type TLSFindingCompleted struct {
	Intent  projections.LicensedCryptoMigrationTLSPosture `json:"intent"`
	Receipt connector.TLSPostureReceipt                   `json:"receipt"`
}

type TLSAssetRestore struct {
	RunID             string   `json:"run_id"`
	AssetID           string   `json:"asset_id"`
	Kind              string   `json:"kind"`
	Location          string   `json:"location"`
	Algorithm         string   `json:"algorithm,omitempty"`
	KeyBits           int      `json:"key_bits,omitempty"`
	Protocol          string   `json:"protocol,omitempty"`
	Cipher            string   `json:"cipher,omitempty"`
	Library           string   `json:"library,omitempty"`
	Strength          string   `json:"strength"`
	QuantumVulnerable bool     `json:"quantum_vulnerable"`
	OutOfPolicy       bool     `json:"out_of_policy"`
	Reasons           []string `json:"reasons,omitempty"`
	FindingKind       string   `json:"finding_kind"`
	TargetID          string   `json:"target_id"`
}

type TLSFindingRollbackCompleted struct {
	RunID    string                      `json:"run_id"`
	Restores []TLSAssetRestore           `json:"restores"`
	Receipt  connector.TLSPostureReceipt `json:"receipt"`
}

type TLSFindingFailure struct {
	RunID       string `json:"run_id"`
	AssetID     string `json:"asset_id"`
	FindingKind string `json:"finding_kind"`
	TargetID    string `json:"target_id"`
	Connector   string `json:"connector"`
	Reason      string `json:"reason"`
	Status      string `json:"status,omitempty"`
}

type FindingProgress struct {
	RunID          string                `json:"run_id"`
	AssetID        string                `json:"asset_id"`
	FindingKind    string                `json:"finding_kind"`
	TargetID       string                `json:"target_id"`
	TargetRevision string                `json:"target_revision"`
	Connector      string                `json:"connector"`
	Desired        connector.TLSPosture  `json:"desired"`
	Previous       *connector.TLSPosture `json:"previous,omitempty"`
	Observed       *connector.TLSPosture `json:"observed,omitempty"`
	Status         string                `json:"status"`
	Failure        string                `json:"failure,omitempty"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

type progressKey struct {
	tenantID string
	runID    string
	assetID  string
}

// ProgressProjection is the per-finding serving projection. It rebuilds its
// memory index from the immutable event log on every boot and projects the same
// completion/rollback events onto core CBOM rows under tenant RLS.
type ProgressProjection struct {
	store *store.Store
	mu    sync.RWMutex
	items map[progressKey]FindingProgress
}

func NewProgressProjection(st *store.Store) *ProgressProjection {
	return &ProgressProjection{store: st, items: map[progressKey]FindingProgress{}}
}

func WithProgressProjection(p *ProgressProjection) projections.Option {
	return projections.WithEventProjection(p)
}

func (p *ProgressProjection) Name() string { return "pqc.tls_finding_progress" }

func (p *ProgressProjection) Reset(context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.items = map[progressKey]FindingProgress{}
	p.mu.Unlock()
	return nil
}

func (p *ProgressProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if p == nil {
		return nil
	}
	switch ev.Type {
	case projections.EventLicensedCryptoMigrationStarted:
		var started projections.LicensedCryptoMigrationStarted
		if err := json.Unmarshal(ev.Data, &started); err != nil {
			return err
		}
		p.applyStarted(ev, started)
	case EventTLSFindingCompleted:
		var completed TLSFindingCompleted
		if err := json.Unmarshal(ev.Data, &completed); err != nil {
			return err
		}
		if err := p.projectCompleted(ctx, ev, completed); err != nil {
			return err
		}
		p.applyCompleted(ev, completed)
	case EventTLSFindingRollbackCompleted:
		var completed TLSFindingRollbackCompleted
		if err := json.Unmarshal(ev.Data, &completed); err != nil {
			return err
		}
		if err := p.projectRollback(ctx, ev, completed); err != nil {
			return err
		}
		p.applyRollback(ev, completed)
	case EventTLSFindingFailed:
		var failed TLSFindingFailure
		if err := json.Unmarshal(ev.Data, &failed); err != nil {
			return err
		}
		p.applyFailed(ev, failed)
	}
	return nil
}

func (p *ProgressProjection) applyStarted(ev eventspec.Event, started projections.LicensedCryptoMigrationStarted) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, intent := range started.TLSPostures {
		key := progressKey{tenantID: ev.TenantID, runID: intent.RunID, assetID: intent.AssetID}
		if _, exists := p.items[key]; exists {
			continue
		}
		p.items[key] = FindingProgress{
			RunID: intent.RunID, AssetID: intent.AssetID, FindingKind: intent.FindingKind,
			TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, Connector: intent.Connector,
			Desired: clonePosture(intent.Desired), Status: TLSFindingQueued, UpdatedAt: eventTime(ev),
		}
	}
}

func (p *ProgressProjection) projectCompleted(ctx context.Context, ev eventspec.Event, completed TLSFindingCompleted) error {
	intent := completed.Intent
	if p.store == nil || intent.RunID == "" || intent.AssetID == "" {
		return fmt.Errorf("pqcmigration: TLS completion requires store, run_id, and asset_id")
	}
	protocol, cipher := intent.AssetProtocol, intent.Cipher
	switch intent.FindingKind {
	case "protocol":
		protocol = completed.Receipt.Observed.MinimumVersion
	case "cipher":
		cipher = strings.Join(completed.Receipt.Observed.CipherSuites, ",")
	default:
		return fmt.Errorf("pqcmigration: unsupported TLS finding kind %q", intent.FindingKind)
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return p.store.ApplyCryptoAssetMigratedTx(ctx, tx, store.CryptoAsset{
			ID: intent.AssetID, TenantID: ev.TenantID, Kind: intent.Kind, Location: intent.Location,
			Algorithm: intent.Algorithm, KeyBits: intent.KeyBits, Protocol: protocol, Cipher: cipher,
			Library: intent.Library, Strength: "strong", QuantumVulnerable: false, OutOfPolicy: false,
			Reasons: []string{"PQC TLS posture read back from " + intent.Connector + " target " + intent.TargetID + " in run " + intent.RunID},
		}, eventTime(ev))
	})
}

func (p *ProgressProjection) applyCompleted(ev eventspec.Event, completed TLSFindingCompleted) {
	intent := completed.Intent
	previous := clonePosture(completed.Receipt.Previous)
	observed := clonePosture(completed.Receipt.Observed)
	p.mu.Lock()
	p.items[progressKey{tenantID: ev.TenantID, runID: intent.RunID, assetID: intent.AssetID}] = FindingProgress{
		RunID: intent.RunID, AssetID: intent.AssetID, FindingKind: intent.FindingKind,
		TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, Connector: intent.Connector,
		Desired: clonePosture(intent.Desired), Previous: &previous, Observed: &observed,
		Status: TLSFindingApplied, UpdatedAt: eventTime(ev),
	}
	p.mu.Unlock()
}

func (p *ProgressProjection) projectRollback(ctx context.Context, ev eventspec.Event, completed TLSFindingRollbackCompleted) error {
	if p.store == nil || completed.RunID == "" || len(completed.Restores) == 0 {
		return fmt.Errorf("pqcmigration: TLS rollback completion requires store, run_id, and restores")
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		for _, restore := range completed.Restores {
			if err := p.store.ApplyCryptoAssetRolledBackTx(ctx, tx, store.CryptoAsset{
				ID: restore.AssetID, TenantID: ev.TenantID, Kind: restore.Kind, Location: restore.Location,
				Algorithm: restore.Algorithm, KeyBits: restore.KeyBits, Protocol: restore.Protocol,
				Cipher: restore.Cipher, Library: restore.Library, Strength: restore.Strength,
				QuantumVulnerable: restore.QuantumVulnerable, OutOfPolicy: restore.OutOfPolicy,
				Reasons: append([]string(nil), restore.Reasons...),
			}, eventTime(ev)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *ProgressProjection) applyRollback(ev eventspec.Event, completed TLSFindingRollbackCompleted) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, restore := range completed.Restores {
		key := progressKey{tenantID: ev.TenantID, runID: completed.RunID, assetID: restore.AssetID}
		item := p.items[key]
		item.RunID, item.AssetID = completed.RunID, restore.AssetID
		item.FindingKind, item.TargetID = restore.FindingKind, restore.TargetID
		observed := clonePosture(completed.Receipt.Observed)
		item.Observed = &observed
		item.Status, item.Failure, item.UpdatedAt = TLSFindingRolledBack, "", eventTime(ev)
		p.items[key] = item
	}
}

func (p *ProgressProjection) applyFailed(ev eventspec.Event, failed TLSFindingFailure) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := progressKey{tenantID: ev.TenantID, runID: failed.RunID, assetID: failed.AssetID}
	item := p.items[key]
	item.RunID, item.AssetID, item.FindingKind = failed.RunID, failed.AssetID, failed.FindingKind
	item.TargetID, item.Connector = failed.TargetID, failed.Connector
	status := failed.Status
	if status != TLSFindingRollbackFailed {
		status = TLSFindingFailed
	}
	item.Status, item.Failure, item.UpdatedAt = status, failed.Reason, eventTime(ev)
	p.items[key] = item
}

func (p *ProgressProjection) Snapshot(tenantID, runID string) []FindingProgress {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	out := make([]FindingProgress, 0)
	for key, item := range p.items {
		if key.tenantID == tenantID && key.runID == runID {
			out = append(out, cloneFindingProgress(item))
		}
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID < out[j].AssetID })
	return out
}

func cloneFindingProgress(item FindingProgress) FindingProgress {
	item.Desired = clonePosture(item.Desired)
	if item.Previous != nil {
		previous := clonePosture(*item.Previous)
		item.Previous = &previous
	}
	if item.Observed != nil {
		observed := clonePosture(*item.Observed)
		item.Observed = &observed
	}
	return item
}

func eventTime(ev eventspec.Event) time.Time {
	if ev.Time.IsZero() {
		return time.Now().UTC()
	}
	return ev.Time.UTC()
}
