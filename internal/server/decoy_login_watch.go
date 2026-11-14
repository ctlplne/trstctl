// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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

// defaultDecoyWatchGapGrace is how long a decoy login may go unread before
// its monitoring gap is recorded and alerted (Q6-L10): long enough that a
// brief provider restart does not page anyone.
const defaultDecoyWatchGapGrace = 5 * time.Minute

// decoyWatchFailureLog remembers since when the watcher has failed to read
// each decoy login, until it is read again or its gap is recorded.
type decoyWatchFailureLog struct {
	mu    sync.Mutex
	since map[string]time.Time
}

// failing records a failed read of decoy id at now and returns since when the
// reads have failed.
func (l *decoyWatchFailureLog) failing(id string, now time.Time) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.since == nil {
		l.since = map[string]time.Time{}
	}
	first, ok := l.since[id]
	if !ok {
		l.since[id] = now
		first = now
	}
	return first
}

// read forgets decoy id's failures.
func (l *decoyWatchFailureLog) read(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.since, id)
}

type decoySessionReader interface {
	// DecoyCounter reads the decoy database's session counter with its last
	// statistics reset (Q6-L7).
	DecoyCounter(ctx context.Context, role string) (dynsecret.DecoyCounter, bool, error)
	// DecoyElsewhere names the other databases the decoy login has a live
	// session in (Q6-L8).
	DecoyElsewhere(ctx context.Context, role string) ([]string, error)
}

type decoyElsewhereReader interface {
	DecoyElsewhere(ctx context.Context, role string) ([]string, error)
}

// decoyAuthLogReader is a provider that also watches its decoy logins for
// refused sign-ins in the server's jsonlog (Q6-L6, decoy_auth_log).
type decoyAuthLogReader interface {
	DecoyAuthLogEnabled() bool
	DecoyFailedLogins(ctx context.Context, cursor dynsecret.DecoyLogCursor, roles map[string]bool) ([]dynsecret.DecoyFailedLogin, dynsecret.DecoyLogCursor, error)
}

// decoyAuthLogCursors remembers where each provider's log read stopped. It
// starts at the beginning of the current log after a restart; a decoy is
// triggered once, so a refusal read twice alerts once.
type decoyAuthLogCursors struct {
	mu      sync.Mutex
	cursors map[string]dynsecret.DecoyLogCursor
}

func (c *decoyAuthLogCursors) get(key string) dynsecret.DecoyLogCursor {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursors[key]
}

func (c *decoyAuthLogCursors) set(key string, cursor dynsecret.DecoyLogCursor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cursors == nil {
		c.cursors = map[string]dynsecret.DecoyLogCursor{}
	}
	c.cursors[key] = cursor
}

// DecoyAuthLogEnabled reports whether the provider watches its decoy logins'
// refused sign-ins (Q6-L6).
func (p *configuredDynamicProvider) DecoyAuthLogEnabled() bool {
	return p.cfg.Type == "postgresql" && p.cfg.DecoyAuthLog
}

// DecoyFailedLogins reads the refused sign-ins by roles from the server's
// jsonlog through the provider's admin connection, opened for this read.
func (p *configuredDynamicProvider) DecoyFailedLogins(ctx context.Context, cursor dynsecret.DecoyLogCursor, roles map[string]bool) ([]dynsecret.DecoyFailedLogin, dynsecret.DecoyLogCursor, error) {
	if !p.DecoyAuthLogEnabled() {
		return nil, cursor, fmt.Errorf("dynamic-secret provider %q does not watch refused decoy sign-ins", p.id)
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return nil, cursor, err
	}
	defer closeBackend()
	reader, ok := backend.(interface {
		DecoyFailedLogins(context.Context, dynsecret.DecoyLogCursor, map[string]bool) ([]dynsecret.DecoyFailedLogin, dynsecret.DecoyLogCursor, error)
	})
	if !ok {
		return nil, cursor, fmt.Errorf("dynamic-secret provider %q cannot read refused sign-ins", p.id)
	}
	return reader.DecoyFailedLogins(ctx, cursor, roles)
}

// watchDecoyAuthLogs reads, once per provider that watches its decoy logins'
// refused sign-ins, the refusals by those logins since the last read (Q6-L6),
// and triggers each decoy refused there. It returns the decoys it triggered
// and, per decoy, why its provider's log could not be read.
func (s *Server) watchDecoyAuthLogs(ctx context.Context, tenantID string, decoys []store.HoneyToken, providers []dynsecret.Provider) (map[string]bool, map[string]error) {
	triggered, failed := map[string]bool{}, map[string]error{}
	byProvider := map[string][]store.HoneyToken{}
	for _, decoy := range decoys {
		byProvider[decoy.DBProviderID] = append(byProvider[decoy.DBProviderID], decoy)
	}
	for _, provider := range providers {
		watched := byProvider[provider.Name()]
		reader, ok := provider.(decoyAuthLogReader)
		if len(watched) == 0 || !ok || !reader.DecoyAuthLogEnabled() {
			continue
		}
		roles := map[string]bool{}
		byRole := map[string]store.HoneyToken{}
		for _, decoy := range watched {
			roles[decoy.DBRole] = true
			byRole[decoy.DBRole] = decoy
		}
		key := tenantID + "/" + provider.Name()
		refusals, next, err := reader.DecoyFailedLogins(ctx, s.decoyAuthLogs.get(key), roles)
		if err != nil {
			for _, decoy := range watched {
				failed[decoy.ID] = fmt.Errorf("refused sign-ins unreadable: %w", err)
			}
			continue
		}
		for _, refusal := range refusals {
			decoy := byRole[refusal.Role]
			if triggered[decoy.ID] {
				continue
			}
			path := "postgres/" + refusal.Database
			if refusal.RemoteHost != "" {
				path += " from " + refusal.RemoteHost
			}
			if err := s.orch.RecordHoneyTokenTrigger(ctx, tenantID, decoy.ID, "FAILED_LOGIN", path); err != nil {
				failed[decoy.ID] = err
				continue
			}
			triggered[decoy.ID] = true
		}
		s.decoyAuthLogs.set(key, next)
	}
	return triggered, failed
}

// DecoyCounter reads a decoy login's database session counter and its last
// statistics reset through the provider's admin connection, opened for this
// one read.
func (p *configuredDynamicProvider) DecoyCounter(ctx context.Context, role string) (dynsecret.DecoyCounter, bool, error) {
	if p.cfg.Type != "postgresql" {
		return dynsecret.DecoyCounter{}, false, fmt.Errorf("dynamic-secret provider %q cannot hold decoy logins", p.id)
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return dynsecret.DecoyCounter{}, false, err
	}
	defer closeBackend()
	reader, ok := backend.(interface {
		DecoyCounter(context.Context, string) (dynsecret.DecoyCounter, bool, error)
	})
	if !ok {
		return dynsecret.DecoyCounter{}, false, fmt.Errorf("dynamic-secret provider %q cannot report decoy logins", p.id)
	}
	return reader.DecoyCounter(ctx, role)
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
	// Q6-L10: a decoy that stays unreadable past the grace records a
	// monitoring gap (one alert through the outbox); reading it again closes
	// the gap.
	grace := s.decoyWatchGapGrace
	if grace <= 0 {
		grace = defaultDecoyWatchGapGrace
	}
	now := time.Now().UTC()
	for _, tenantID := range tenants {
		decoys, err := s.store.ListActiveDatabaseDecoys(ctx, tenantID)
		if err != nil {
			note(err)
			continue
		}
		providers := s.secretIntegrations.dynamicProvidersForTenant(tenantID)
		// Q6-L6: refused sign-ins first, from the providers that watch them.
		refused, authLogFailed := s.watchDecoyAuthLogs(ctx, tenantID, decoys, providers)
		for _, decoy := range decoys {
			if refused[decoy.ID] {
				s.decoyWatchFailures.read(decoy.ID)
				continue
			}
			unwatched := func(cause error) {
				note(fmt.Errorf("decoy %s: %w", decoy.ID, cause))
				since := s.decoyWatchFailures.failing(decoy.ID, now)
				if decoy.WatchGapSince != nil || now.Sub(since) < grace {
					return
				}
				if err := s.orch.OpenHoneyTokenWatchGap(ctx, tenantID, decoy.ID, cause.Error(), since); err != nil {
					note(fmt.Errorf("decoy %s: record its monitoring gap: %w", decoy.ID, err))
				}
			}
			watched := func() {
				// Q6-L6: a decoy whose refused sign-ins cannot be read is not
				// fully watched, however its session counter reads.
				if cause := authLogFailed[decoy.ID]; cause != nil {
					unwatched(cause)
					return
				}
				s.decoyWatchFailures.read(decoy.ID)
				if decoy.WatchGapSince == nil {
					return
				}
				if err := s.orch.CloseHoneyTokenWatchGap(ctx, tenantID, decoy.ID); err != nil {
					note(fmt.Errorf("decoy %s: close its monitoring gap: %w", decoy.ID, err))
				}
			}
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
				unwatched(fmt.Errorf("provider %q is not configured for decoy logins", decoy.DBProviderID))
				continue
			}
			counter, exists, err := reader.DecoyCounter(ctx, decoy.DBRole)
			if err != nil {
				if ended {
					retire()
					continue
				}
				unwatched(err)
				continue
			}
			sessions := counter.Sessions
			// Q6-L7: a statistics reset during the decoy's life zeroed its
			// counter, so a use before it is not counted: recorded once as a
			// monitoring gap (one warning alert), which the next read closes.
			if exists && counter.StatsReset != nil && counter.StatsReset.After(decoy.CreatedAt) && decoy.WatchGapSince == nil &&
				(decoy.StatsResetSeen == nil || counter.StatsReset.After(*decoy.StatsResetSeen)) {
				if err := s.orch.RecordDecoyStatsReset(ctx, tenantID, decoy.ID, *counter.StatsReset); err != nil {
					note(fmt.Errorf("decoy %s: record its statistics reset: %w", decoy.ID, err))
				}
			}
			database := dynsecret.DecoyDatabaseName(decoy.DBRole)
			if !exists || sessions == 0 {
				// Q6-L8: a session in another database open to PUBLIC does not
				// count on the decoy's own; the live sessions name it.
				elsewhere, err := reader.DecoyElsewhere(ctx, decoy.DBRole)
				if err != nil {
					if ended {
						retire()
						continue
					}
					unwatched(err)
					continue
				}
				if len(elsewhere) == 0 {
					switch {
					case ended:
						retire()
					case !exists:
						unwatched(errors.New("its database is gone while its lease is active"))
					default:
						watched()
					}
					continue
				}
				database = elsewhere[0]
			}
			watched()
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
