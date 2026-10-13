// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcileVerifiedBreakglassBundles is the common event write path for both
// offline-only and online-custody deployments. Callers verify every signature
// against their pinned trust set before entering this function.
func reconcileVerifiedBreakglassBundles(ctx context.Context, tenantID string, bundles []breakglass.Bundle, st *store.Store, log *events.Log) (int, error) {
	if st == nil || log == nil {
		return 0, errors.New("breakglass: reconciliation requires PostgreSQL and the event log")
	}
	// A conflicting repeated request ID must reject the whole batch before its
	// first event. The signature covers the request ID, while the digest below
	// also fences the complete transported bundle, including its signature.
	seen := make(map[string]string, len(bundles))
	for _, bundle := range bundles {
		if bundle.RequestID == "" {
			return 0, fmt.Errorf("%w: bundle request_id is empty", api.ErrBreakglassInvalidBundle)
		}
		raw, err := json.Marshal(bundle)
		if err != nil {
			return 0, err
		}
		digest := crypto.SHA256Hex(raw)
		if prior, ok := seen[bundle.RequestID]; ok && prior != digest {
			return 0, fmt.Errorf("%w: batch contains conflicting bundles for request_id %q", api.ErrBreakglassInvalidBundle, bundle.RequestID)
		}
		seen[bundle.RequestID] = digest
	}

	reconciled := 0
	for _, bundle := range bundles {
		added, err := reconcileVerifiedBreakglassBundle(ctx, tenantID, bundle, seen[bundle.RequestID], st, log)
		if err != nil {
			return reconciled, err
		}
		if added {
			reconciled++
		}
	}
	return reconciled, nil
}

func reconcileVerifiedBreakglassBundle(ctx context.Context, tenantID string, bundle breakglass.Bundle, digest string, st *store.Store, log *events.Log) (bool, error) {
	identity, err := json.Marshal(struct {
		TenantID  string `json:"tenant_id"`
		RequestID string `json:"request_id"`
	}{tenantID, bundle.RequestID})
	if err != nil {
		return false, err
	}
	eventID := "breakglass-reconcile-v1-" + crypto.SHA256Hex(identity)
	data, err := json.Marshal(struct {
		RequestID    string `json:"request_id"`
		Subject      string `json:"subject"`
		Reason       string `json:"reason"`
		IssuedAt     string `json:"issued_at"`
		Approvals    int    `json:"approvals"`
		BundleSHA256 string `json:"bundle_sha256"`
	}{bundle.RequestID, bundle.Subject, bundle.Reason, bundle.IssuedAt.Format(time.RFC3339), len(bundle.Approvals), digest})
	if err != nil {
		return false, err
	}
	schemaVersion := projections.BreakglassReconcileEventSchemaVersion
	if bundle.Version == 2 {
		schemaVersion = projections.BreakglassOfflineEvidenceEventSchemaVersion
		data, err = json.Marshal(struct {
			RequestID     string            `json:"request_id"`
			Subject       string            `json:"subject"`
			Reason        string            `json:"reason"`
			IssuedAt      string            `json:"issued_at"`
			Approvals     int               `json:"approvals"`
			BundleSHA256  string            `json:"bundle_sha256"`
			OfflineBundle breakglass.Bundle `json:"offline_bundle"`
		}{bundle.RequestID, bundle.Subject, bundle.Reason, bundle.IssuedAt.Format(time.RFC3339), len(bundle.Approvals), digest, bundle})
		if err != nil {
			return false, err
		}
	}
	added := false
	err = st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// A tenant-scoped PostgreSQL lock serializes replicas for this signed
		// request ID. The immutable event remains the state of record; this lock
		// is only a short-lived coordination fence, not a mutable status row.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"breakglass-reconcile\x1f"+tenantID+"\x1f"+bundle.RequestID); err != nil {
			return err
		}
		prior, found, err := log.EventByID(ctx, eventID)
		if err != nil {
			return err // An identity projection behind the log fails closed.
		}
		if found {
			if prior.TenantID != tenantID || prior.Type != projections.EventBreakglassIssued ||
				prior.SchemaVersion != schemaVersion || !bytes.Equal(prior.Data, data) {
				return fmt.Errorf("%w: request_id %q has a different reconciliation event", store.ErrIdempotencyConflict, bundle.RequestID)
			}
			return nil
		}
		candidate := events.Event{
			ID: eventID, Type: projections.EventBreakglassIssued, TenantID: tenantID,
			SchemaVersion: schemaVersion, Data: data, Time: time.Now().UTC(),
		}
		canonical, err := log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		if canonical.TenantID != tenantID || canonical.Type != candidate.Type ||
			canonical.SchemaVersion != candidate.SchemaVersion || !bytes.Equal(canonical.Data, data) {
			return fmt.Errorf("%w: request_id %q resolved to a different event", store.ErrIdempotencyConflict, bundle.RequestID)
		}
		// Append can return an existing canonical message when its NATS
		// duplicate window catches a concurrent or retried writer.
		added = canonical.Time.Equal(candidate.Time)
		return nil
	})
	return added, err
}
