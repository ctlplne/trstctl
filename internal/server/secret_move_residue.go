// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// Re-checking moved secrets' history residue (P6-L5). A move records the
// history commits that held the value when it moved; every later completed
// scan of the repository looks again. The clone is deepened to every
// branch's full history, the pinned gitleaks reads it unredacted into memory,
// and each moved value (read from the version the leak moved into) is looked
// for there. What it finds replaces the recorded residue: a commit a history
// rewrite removed drops off, one that brings the value back is added. Only
// locations are recorded; the values are wiped. A failure leaves the residue
// as it was, with its last check time, and never fails the scan run.

// secretResidueRecheckBatch bounds the moves one scan re-checks.
const secretResidueRecheckBatch = 100

// historyResidueScanner finds values in a scan target's git history.
type historyResidueScanner interface {
	HistoryResidueOf(ctx context.Context, dir string, values [][]byte) ([][]secretscan.SecretLocation, error)
}

// recheckMovedSecretResidue re-checks, after a completed scan of a repository
// source, the history residue of every leak moved out of it.
func (d *issuanceDispatcher) recheckMovedSecretResidue(ctx context.Context, tenantID, sourceID, runID string,
	cfg secretscan.RepositoryScanConfig, cred *secretscan.RepositoryCredential, target secretscan.RepositoryTarget) {
	scanner, ok := d.secretRepoScanner.(historyResidueScanner)
	if !ok || d.movedSecretValues == nil || d.store == nil || d.orch == nil {
		return
	}
	warn := func(step string, err error) {
		slog.Default().Warn("moved secrets' history residue was not re-checked; it stays as last recorded",
			"source_id", sourceID, "run_id", runID, "step", step, "error", err.Error())
	}
	moves, err := d.store.SecretMovesForSource(ctx, tenantID, sourceID, secretResidueRecheckBatch)
	if err != nil {
		warn("moves", err)
		return
	}
	if len(moves) == 0 {
		return
	}
	known, err := d.movedSecretValues(ctx, tenantID, moves)
	if err != nil {
		warn("values", err)
		return
	}
	defer secretscan.WipeKnownValues(known)
	if len(known) == 0 {
		return
	}
	if err := secretscan.DeepenClone(ctx, target, cfg, cred); err != nil {
		warn("history", err)
		return
	}
	values := make([][]byte, len(known))
	for i, k := range known {
		values[i] = k.Value
	}
	residues, err := scanner.HistoryResidueOf(ctx, target.Path, values)
	if errors.Is(err, secretscan.ErrNoHistory) {
		return // nothing to look in: the residue stays as recorded
	}
	if err != nil {
		warn("scan", err)
		return
	}
	byFinding := make(map[string]store.DiscoveryFindingSecretMove, len(moves))
	for _, m := range moves {
		byFinding[m.FindingID] = m
	}
	checkedAt := time.Now().UTC()
	for i, k := range known {
		m, ok := byFinding[k.ID]
		if !ok {
			continue
		}
		residue := make([]store.SecretResidueLocation, 0, len(residues[i]))
		for _, loc := range residues[i] {
			residue = append(residue, store.SecretResidueLocation{RuleID: loc.RuleID, File: loc.File, Line: loc.Line, Commit: loc.Commit})
		}
		if err := d.orch.RecordSecretResidueChecked(ctx, tenantID, projections.DiscoveryFindingSecretResidueChecked{
			FindingID: m.FindingID, SecretName: m.SecretName, SecretVersion: m.SecretVersion,
			RunID: runID, CheckedAt: checkedAt, Residue: residue,
		}); err != nil {
			warn("record", err)
		}
	}
}
