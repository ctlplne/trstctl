// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

// Decoy database login watch (Q6). A decoy login is a PostgreSQL role with
// CONNECT on its own empty database only, minted by the tenant's dynamic-secret
// provider. trstctl never connects with it, so that database's session counter
// (pg_stat_database.sessions) counts only uses of the bait: the leader reads it
// through the provider's admin connection and the first session raises the
// decoy's critical alert. The counter persists in PostgreSQL, so a login while
// trstctl is down is seen at the next check; a statistics reset reads zero and
// alerts nothing. A probe that never authenticates (a TLS or port scan)
// establishes no session.

const defaultDecoyLoginWatchInterval = 30 * time.Second

type decoySessionReader interface {
	DecoySessions(ctx context.Context, role string) (int64, bool, error)
	// DecoyElsewhere names the other databases the decoy login has a live
	// session in (Q6-L8).
	DecoyElsewhere(ctx context.Context, role string) ([]string, error)
}

type decoyElsewhereReader interface {
	DecoyElsewhere(ctx context.Context, role string) ([]string, error)
}

// DecoySessions reads a decoy login's database session counter through the
// provider's admin connection, opened for this one read.
func (p *configuredDynamicProvider) DecoySessions(ctx context.Context, role string) (int64, bool, error) {
	if p.cfg.Type != "postgresql" {
		return 0, false, fmt.Errorf("dynamic-secret provider %q cannot hold decoy logins", p.id)
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return 0, false, err
	}
	defer closeBackend()
	reader, ok := backend.(decoySessionReader)
	if !ok {
		return 0, false, fmt.Errorf("dynamic-secret provider %q cannot report decoy logins", p.id)
	}
	return reader.DecoySessions(ctx, role)
}

// DecoyElsewhere reads the decoy login's live sessions in other databases
// through the provider's admin connection, opened for this one read.
func (p *configuredDynamicProvider) DecoyElsewhere(ctx context.Context, role string) ([]string, error) {
	if p.cfg.Type != "postgresql" {
		return nil, fmt.Errorf("dynamic-secret provider %q cannot hold decoy logins", p.id)
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return nil, err
	}
	defer closeBackend()
	reader, ok := backend.(decoyElsewhereReader)
	if !ok {
		return nil, fmt.Errorf("dynamic-secret provider %q cannot report decoy logins", p.id)
	}
	return reader.DecoyElsewhere(ctx, role)
}

// RunDecoyLoginWatch checks every active decoy database login on the leader.
func (s *Server) RunDecoyLoginWatch(ctx context.Context) {
	interval := s.decoyLoginWatchInterval
	if interval <= 0 {
		interval = defaultDecoyLoginWatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.WatchDecoyLoginsOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("decoy login watch could not check every decoy", slog.String("error", err.Error()))
			}
		}
	}
}

// WatchDecoyLoginsOnce checks every untriggered decoy database login once. A
// decoy it cannot read is reported in the returned error and checked again at
// the next tick; it never counts as unused.
func (s *Server) WatchDecoyLoginsOnce(ctx context.Context) error {
	if s.store == nil || s.orch == nil || s.secretIntegrations == nil {
		return nil
	}
	tenants, err := s.store.TenantsWithActiveDatabaseDecoys(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, tenantID := range tenants {
		decoys, err := s.store.ListActiveDatabaseDecoys(ctx, tenantID)
		if err != nil {
			note(err)
			continue
		}
		providers := s.secretIntegrations.dynamicProvidersForTenant(tenantID)
		for _, decoy := range decoys {
			// Q6-L9: a decoy lives as long as its lease. Once the lease has
			// ended, its login and database are gone or going: one last read
			// still catches a use before the end, then the decoy retires, so it
			// no longer reads as watching.
			ended, err := s.decoyLeaseEnded(ctx, tenantID, decoy.DBLeaseID)
			if err != nil {
				note(fmt.Errorf("decoy %s: %w", decoy.ID, err))
				continue
			}
			retire := func() {
				if err := s.orch.RevokeHoneyToken(ctx, tenantID, decoy.ID); err != nil {
					note(fmt.Errorf("decoy %s: retire after its lease ended: %w", decoy.ID, err))
				}
			}
			var reader decoySessionReader
			for _, provider := range providers {
				if provider.Name() == decoy.DBProviderID {
					reader, _ = provider.(decoySessionReader)
				}
			}
			if reader == nil {
				if ended {
					retire()
					continue
				}
				note(fmt.Errorf("decoy %s: provider %q is not configured for decoy logins", decoy.ID, decoy.DBProviderID))
				continue
			}
			sessions, exists, err := reader.DecoySessions(ctx, decoy.DBRole)
			if err != nil {
				if ended {
					retire()
					continue
				}
				note(fmt.Errorf("decoy %s: %w", decoy.ID, err))
				continue
			}
			database := dynsecret.DecoyDatabaseName(decoy.DBRole)
			if !exists || sessions == 0 {
				// Q6-L8: a session in another database open to PUBLIC does not
				// count on the decoy's own; the live sessions name it.
				elsewhere, err := reader.DecoyElsewhere(ctx, decoy.DBRole)
				if err != nil {
					note(fmt.Errorf("decoy %s: %w", decoy.ID, err))
					continue
				}
				if len(elsewhere) == 0 {
					if ended {
						retire()
					} else if !exists {
						note(fmt.Errorf("decoy %s: its database is gone while its lease is active", decoy.ID))
					}
					continue
				}
				database = elsewhere[0]
			}
			if err := s.orch.RecordHoneyTokenTrigger(ctx, tenantID, decoy.ID, "LOGIN", "postgres/"+database); err != nil {
				note(fmt.Errorf("decoy %s: %w", decoy.ID, err))
			}
		}
	}
	return firstErr
}

// decoyLeaseEnded reports whether a decoy login's lease has ended: revoked,
// failed, past its hard expiry, or gone from the lease store.
func (s *Server) decoyLeaseEnded(ctx context.Context, tenantID, leaseID string) (bool, error) {
	lease, err := s.store.GetDynamicSecretLease(ctx, tenantID, leaseID)
	if store.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	switch lease.State {
	case store.DynamicSecretLeaseRevoked, store.DynamicSecretLeaseFailed:
		return true, nil
	}
	return !lease.HardExpiresAt.IsZero() && !lease.HardExpiresAt.After(time.Now()), nil
}
