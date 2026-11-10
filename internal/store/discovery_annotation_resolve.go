// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Settling an annotation when its finding is resolved (A174-L1).
//
// A third-party finding annotated at its provider (a Slack reply, a Jira
// comment, a CI commit status, an image referrer) keeps telling people there
// that a credential must be rotated. The triage change that resolves the
// finding queues, in its own projection transaction, the control-plane row
// that settles the annotation, so every path that resolves a finding settles
// it and a replay finds the row already queued.

// scanAnnotationResolveDestination and the action names mirror the
// orchestrator's scan annotation row (DestinationScanAnnotation,
// FindingActionResolveAnnotation), which this package cannot import.
const (
	scanAnnotationResolveDestination = "scan.annotation"
	scanAnnotationActionAnnotate     = "annotate"
	scanAnnotationActionResolve      = "resolve_annotation"
)

// resolvesAnnotation reports whether a triage status ends a finding, so its
// annotation is settled.
func resolvesAnnotation(status string) bool {
	return status == "remediated" || status == "dismissed"
}

// QueueResolvedFindingAnnotationTx queues the row that settles a resolved
// finding's annotation, when the provider confirmed one and nothing settled
// it yet. It is called in the triage change's projection transaction.
func (s *Store) QueueResolvedFindingAnnotationTx(ctx context.Context, tx pgx.Tx, tenantID, findingID, status string, at time.Time) error {
	if !resolvesAnnotation(status) {
		return nil
	}
	var (
		sourceID, ref string
		discoveredAt  time.Time
		raw           []byte
	)
	err := tx.QueryRow(ctx, `SELECT source_id::text, ref, discovered_at, metadata FROM discovery_findings WHERE tenant_id = $1 AND id = $2`,
		tenantID, findingID).Scan(&sourceID, &ref, &discoveredAt, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var meta struct {
		RuleID          string            `json:"rule_id"`
		ProviderObject  map[string]string `json:"provider_object"`
		ProviderActions map[string]struct {
			Status      string `json:"status"`
			Provider    string `json:"provider"`
			ProviderRef string `json:"provider_ref"`
			RequestID   string `json:"request_id"`
		} `json:"provider_actions"`
	}
	if json.Unmarshal(raw, &meta) != nil {
		return nil
	}
	annotated, ok := meta.ProviderActions[scanAnnotationActionAnnotate]
	if !ok || (annotated.Status != "confirmed" && annotated.Status != "already_present") || annotated.Provider == "" ||
		annotated.RequestID == "" || len(meta.ProviderObject) == 0 {
		return nil
	}
	if _, settled := meta.ProviderActions[scanAnnotationActionResolve]; settled {
		return nil
	}
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-scan-annotation-resolve\x00"+tenantID+"\x00"+annotated.RequestID)).String()
	payload, err := json.Marshal(map[string]any{
		"request_id": requestID, "finding_id": findingID, "source_id": sourceID, "provider": annotated.Provider,
		"rule": meta.RuleID, "location": ref, "detected_at": discoveredAt.UTC().Format(time.RFC3339),
		"object": meta.ProviderObject, "action": scanAnnotationActionResolve, "provider_ref": annotated.ProviderRef,
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role)
		 SELECT $1, $2, $3, $4, $5, 'control_plane'
		  WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $4)`,
		tenantID, scanAnnotationResolveDestination, payload, "scan-annotation:"+requestID, "scan-annotation:"+annotated.Provider); err != nil {
		return fmt.Errorf("store: queue the annotation's settlement: %w", err)
	}
	return s.ApplyDiscoveryFindingProviderActionTx(ctx, tx, DiscoveryFindingProviderAction{
		TenantID: tenantID, FindingID: findingID, Action: scanAnnotationActionResolve, Status: "queued",
		Provider: annotated.Provider, Detail: "the finding was " + status + "; its annotation is being settled",
		RequestID: requestID, At: at,
	})
}
