// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
)

// deletedSecretRetentionInterval paces the deleted-secret retention sweep
// (A236-L4). The window is days, so an hourly pass keeps nothing materially
// past it.
const deletedSecretRetentionInterval = time.Hour

// deletedSecretPurgeBatch bounds one pass's deletions; a pass that removes a
// full batch runs again at once, up to deletedSecretPurgePasses times, and the
// next tick continues.
const (
	deletedSecretPurgeBatch  = 500
	deletedSecretPurgePasses = 20
)

// deletedSecretRetentionFromConfig is secrets.deleted_retention as validated
// by config.Validate; an unparsable value (unreachable after validation)
// keeps the default.
func deletedSecretRetentionFromConfig(cfg *config.Config) time.Duration {
	d, err := cfg.Secrets.DeletedRetentionDuration()
	if err != nil {
		d, _ = config.Secrets{}.DeletedRetentionDuration()
	}
	return d
}

// RunDeletedSecretRetention removes deleted application secrets kept past the
// retention window on the leader (A236-L4). It sweeps once on start and then
// hourly until ctx is canceled; a failed pass is logged and the next tick
// retries.
func (s *Server) RunDeletedSecretRetention(ctx context.Context) {
	if s.store == nil || s.api == nil || !s.api.SecretsServed() {
		return
	}
	s.purgeDeletedSecretsLogged(ctx)
	t := time.NewTicker(deletedSecretRetentionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.purgeDeletedSecretsLogged(ctx)
		}
	}
}

func (s *Server) purgeDeletedSecretsLogged(ctx context.Context) {
	n, err := s.PurgeDeletedSecretsOnce(ctx, time.Now().UTC())
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("deleted-secret retention sweep failed", slog.String("error", err.Error()))
		}
		return
	}
	if n > 0 && s.logger != nil {
		s.logger.Info("deleted-secret retention sweep purged deleted secrets", slog.Int("purged", n))
	}
}

// PurgeDeletedSecretsOnce removes every deleted secret kept since before
// now minus the retention window, in bounded batches, and audits each purge in
// its own tenant (name only, never a value). It reports how many it removed.
func (s *Server) PurgeDeletedSecretsOnce(ctx context.Context, now time.Time) (int, error) {
	cutoff := now.Add(-s.deletedSecretRetention)
	auditor := audit.NewAuditor(s.log)
	total := 0
	for pass := 0; pass < deletedSecretPurgePasses; pass++ {
		purged, err := s.store.PurgeDeletedSecretsBefore(ctx, cutoff, deletedSecretPurgeBatch)
		if err != nil {
			return total, err
		}
		for _, p := range purged {
			data, err := json.Marshal(map[string]string{"name": p.Name, "reason": "retention"})
			if err != nil {
				return total, err
			}
			_ = auditsink.Emit(ctx, auditor, nil, "secret.deleted_purged", p.TenantID, data)
		}
		total += len(purged)
		if len(purged) < deletedSecretPurgeBatch {
			break
		}
	}
	return total, nil
}
