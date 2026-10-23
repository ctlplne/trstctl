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

// RecordWeakKeyAudit records one batch-GCD audit of a tenant's RSA keys as a
// discovery run under the product's own weak-key-audit source: the distinct
// keys checked, the keys left out by the bound, and one finding per place a
// key that shares a prime appears. A run with no findings is the evidence that
// the audit ran and found none.
func (o *Orchestrator) RecordWeakKeyAudit(ctx context.Context, tenantID string, rep weakkey.SharedFactorReport,
	leftOut int, findings []store.DiscoveryFinding) (store.DiscoveryRun, error) {
	sourceID := uuid.NewSHA1(weakKeyAuditSourceNamespace, []byte(tenantID+"\x00batch-gcd")).String()
	cfg, err := json.Marshal(map[string]any{"check": weakkey.CheckRSASharedFactor, "max_distinct_keys": weakkey.MaxSharedFactorModuli})
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "weak_key_audit", Name: sourcecatalog.WeakKeyAuditSourcePrefix + "batch-gcd", Config: cfg,
	}); err != nil {
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
	status, msg := "succeeded", ""
	if leftOut > 0 {
		status = "partial"
		msg = fmt.Sprintf("%d distinct RSA keys were left out: one run checks at most %d", leftOut, weakkey.MaxSharedFactorModuli)
	}
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
