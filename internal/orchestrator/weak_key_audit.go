// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/weakkey"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// WeakKeyFindingKind is the discovery finding kind the weak-key audit records
// for a key that shares a prime with another key in the tenant's inventory
// (eMudhra, Part 4).
const WeakKeyFindingKind = "weak-key"

var weakKeyAuditSourceNamespace = uuid.MustParse("07310acd-a320-50c4-9601-0d8f6e0c9e39")

// WeakKeyAuditSourceKind is the discovery source kind of the product's own
// weak-key audit; a run on it runs the audit (AUD-O1).
const WeakKeyAuditSourceKind = "weak_key_audit"

// WeakKeyAuditSourceID is the tenant's one weak-key audit source.
func WeakKeyAuditSourceID(tenantID string) string {
	return uuid.NewSHA1(weakKeyAuditSourceNamespace, []byte(tenantID+"\x00batch-gcd")).String()
}

// EnsureWeakKeyAuditSource records the tenant's weak-key audit source and
// returns its ID.
func (o *Orchestrator) EnsureWeakKeyAuditSource(ctx context.Context, tenantID string) (string, error) {
	sourceID := WeakKeyAuditSourceID(tenantID)
	cfg, err := json.Marshal(map[string]any{"check": weakkey.CheckRSASharedFactor, "max_distinct_keys": weakkey.MaxSharedFactorModuli})
	if err != nil {
		return "", err
	}
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: WeakKeyAuditSourceKind, Name: sourcecatalog.WeakKeyAuditSourcePrefix + "batch-gcd", Config: cfg,
	}); err != nil {
		return "", err
	}
	return sourceID, nil
}

// WeakKeyAuditOutcome is an audit run's status and message: partial, naming
// how many distinct keys the bound left out, when it left any out.
func WeakKeyAuditOutcome(leftOut int) (string, string) {
	if leftOut > 0 {
		return "partial", fmt.Sprintf("%d distinct RSA keys were left out: one run checks at most %d", leftOut, weakkey.MaxSharedFactorModuli)
	}
	return "succeeded", ""
}

// QueueWeakKeyAudit queues the tenant's weak-key audit now, as a run on its
// source that the control plane executes (AUD-O1). A run already queued or
// running is answered instead of queueing another: one audit at a time.
func (o *Orchestrator) QueueWeakKeyAudit(ctx context.Context, tenantID string) (store.DiscoveryRun, bool, error) {
	sourceID, err := o.EnsureWeakKeyAuditSource(ctx, tenantID)
	if err != nil {
		return store.DiscoveryRun{}, false, err
	}
	if latest, err := o.store.GetLatestDiscoveryRunForSource(ctx, tenantID, sourceID); err == nil && (latest.Status == "queued" || latest.Status == "running") {
		return latest, false, nil
	} else if err != nil && !store.IsNotFound(err) {
		return store.DiscoveryRun{}, false, err
	}
	run, err := o.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{SourceID: sourceID})
	return run, err == nil, err
}

// RecordWeakKeyAudit records one batch-GCD audit of a tenant's RSA keys as a
// discovery run under the product's own weak-key-audit source: the distinct
// keys checked, the keys left out by the bound, and one finding per place a
// key that shares a prime appears. A run with no findings is the evidence that
// the audit ran and found none.
func (o *Orchestrator) RecordWeakKeyAudit(ctx context.Context, tenantID string, rep weakkey.SharedFactorReport,
	leftOut int, findings []store.DiscoveryFinding) (store.DiscoveryRun, error) {
	sourceID, err := o.EnsureWeakKeyAuditSource(ctx, tenantID)
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	runID := uuid.NewString()
	requestedBy := "system:weak-key-audit"
	payload, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: requestedBy})
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryRunQueued, tenantID, payload)
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	if err := o.StartDiscoveryRun(ctx, tenantID, runID); err != nil {
		return store.DiscoveryRun{}, err
	}
	recorded := 0
	for _, f := range findings {
		f.Kind = strings.TrimSpace(f.Kind)
		f.Ref = strings.TrimSpace(f.Ref)
		if f.Kind == "" || f.Ref == "" {
			continue
		}
		f.RunID, f.SourceID = runID, sourceID
		if _, err := o.RecordDiscoveryFinding(ctx, tenantID, f); err != nil {
			return store.DiscoveryRun{}, err
		}
		recorded++
	}
	status, msg := WeakKeyAuditOutcome(leftOut)
	if err := o.CompleteDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
		ID: runID, Status: status, Targets: rep.Distinct, Discovered: recorded, Error: msg,
	}); err != nil {
		return store.DiscoveryRun{}, err
	}
	return store.DiscoveryRun{
		ID: runID, TenantID: tenantID, SourceID: sourceID, Status: status, RequestedBy: requestedBy,
		Targets: rep.Distinct, Discovered: recorded, Error: msg, CreatedAt: ev.Time,
	}, nil
}
