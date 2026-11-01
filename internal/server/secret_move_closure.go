// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// Closing moved leaked-secret findings (P6). The leader closes a finding whose
// value moved into the native store as remediated only on evidence: the linked
// secret was rotated (a version newer than the moved one exists), a consumer
// read a rotated version, and a scan of the finding's source completed after
// the rotation without seeing the leak. A failed scan or a provider error is
// no evidence, so the finding stays open; so does a finding a later scan still
// sees (the old value still in the file). The history commits that held the
// value stay listed on the finding after it closes.

const (
	defaultSecretMoveClosureInterval = time.Minute
	secretMoveClosureBatch           = 100
)

// RunSecretMoveClosure closes moved findings on evidence, on the leader.
func (s *Server) RunSecretMoveClosure(ctx context.Context) {
	interval := s.secretMoveClosureInterval
	if interval <= 0 {
		interval = defaultSecretMoveClosureInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.CloseMovedSecretFindingsOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("leaked-secret closure could not evaluate every moved finding", slog.String("error", err.Error()))
			}
		}
	}
}

// CloseMovedSecretFindingsOnce evaluates, once, a bounded batch of every
// tenant's open moved findings and closes those with all the evidence.
func (s *Server) CloseMovedSecretFindingsOnce(ctx context.Context) (int, error) {
	if s.store == nil || s.orch == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithOpenSecretMoves(ctx)
	if err != nil {
		return 0, err
	}
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	closed := 0
	for _, tenantID := range tenants {
		moves, err := s.store.OpenSecretMoves(ctx, tenantID, secretMoveClosureBatch)
		if err != nil {
			note(err)
			continue
		}
		for _, m := range moves {
			reason, evidence, ok, err := s.secretMoveClosureEvidence(ctx, tenantID, m)
			if err != nil {
				note(fmt.Errorf("finding %s: %w", m.FindingID, err))
				continue
			}
			if !ok {
				continue
			}
			if err := s.orch.CloseMovedSecretFinding(ctx, tenantID, m, reason, evidence); err != nil {
				note(fmt.Errorf("finding %s: %w", m.FindingID, err))
				continue
			}
			closed++
		}
	}
	return closed, firstErr
}

// secretMoveClosureEvidence returns the reason and evidence that close a moved
// finding, or false while any of the evidence is missing.
func (s *Server) secretMoveClosureEvidence(ctx context.Context, tenantID string, m store.OpenSecretMove) (string, string, bool, error) {
	current, err := s.store.GetSecret(ctx, tenantID, m.SecretName)
	if errors.Is(err, store.ErrSecretNotFound) {
		return "", "", false, nil // the secret is gone: nothing says the leak was rotated
	}
	if err != nil {
		return "", "", false, err
	}
	if current.Version <= m.SecretVersion || m.ConsumerReadAt == nil || m.ConsumerReadVersion <= m.SecretVersion || m.SourceID == "" {
		return "", "", false, nil
	}
	rotatedAt := current.UpdatedAt
	if rotation, err := s.store.GetSecretVersion(ctx, tenantID, m.SecretName, m.SecretVersion+1); err == nil {
		rotatedAt = rotation.WrittenAt
	} else if !errors.Is(err, store.ErrSecretNotFound) {
		return "", "", false, err
	}
	runID, completedAt, found, err := s.store.LatestCompletedDiscoveryRunAfter(ctx, tenantID, m.SourceID, rotatedAt)
	if err != nil || !found || runID == m.RunID {
		// No completed scan since the rotation, or the latest one still saw the leak.
		return "", "", false, err
	}
	reason := fmt.Sprintf("moved into %s and rotated past v%d; a consumer read v%d; scan run %s completed %s without seeing the leak",
		m.SecretName, m.SecretVersion, m.ConsumerReadVersion, runID, completedAt.UTC().Format(time.RFC3339))
	if n := len(m.Residue); n > 0 {
		reason += fmt.Sprintf("; %d history commit(s) still hold the rotated value", n)
	}
	evidence := fmt.Sprintf("secret:%s@v%d;read:v%d;scan:%s", m.SecretName, current.Version, m.ConsumerReadVersion, runID)
	return reason, evidence, true, nil
}
