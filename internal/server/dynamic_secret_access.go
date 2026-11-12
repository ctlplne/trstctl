// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Dynamic-secret lease access (G2). The leader reads what each active lease's
// login reaches from the target itself — a PostgreSQL role's grants, the IAM
// role an STS lease assumed and that role's policies — through the provider's
// own credentials, opened for that one read. The reads change nothing upstream
// and are bounded: a batch per tenant per pass, one target call at a time, each
// with a timeout. A target that cannot be read is recorded unknown with a
// closed-set reason and read again later; it never reads as "no grants".

const (
	defaultDynamicSecretAccessInterval = time.Minute
	dynamicSecretAccessRefresh         = 6 * time.Hour
	// dynamicSecretAccessHeartbeat is how long an unchanged observation goes
	// unrecorded (G2-L3): a read that finds the access as recorded only stamps
	// it, and the observation is recorded again once this old.
	dynamicSecretAccessHeartbeat   = 24 * time.Hour
	dynamicSecretAccessRetry       = 5 * time.Minute
	dynamicSecretAccessBatch       = 50
	dynamicSecretAccessCallTimeout = 30 * time.Second
)

var dynamicSecretAccessNamespace = uuid.MustParse("a7720c22-ddf5-41bd-99ba-e8515c1c2ddc")

// ResolveAccess reads what a lease's login reaches on the target, through the
// provider's own credentials opened for this one read. Only PostgreSQL and AWS
// providers can say; the others are not opened at all.
func (p *configuredDynamicProvider) ResolveAccess(ctx context.Context, backendRef string) (dynsecret.Access, error) {
	switch p.cfg.Type {
	case "postgresql", "mysql", "mongodb", "redis", "aws-iam", "aws-sts":
	default:
		return dynsecret.Access{}, dynsecret.ErrAccessUnsupported
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return dynsecret.Access{}, err
	}
	defer closeBackend()
	resolver, ok := backend.(dynsecret.AccessResolver)
	if !ok {
		return dynsecret.Access{}, dynsecret.ErrAccessUnsupported
	}
	return resolver.ResolveAccess(ctx, backendRef)
}

// RunDynamicSecretAccessWatch reads lease access on the leader.
func (s *Server) RunDynamicSecretAccessWatch(ctx context.Context) {
	interval := s.dynamicSecretAccessInterval
	if interval <= 0 {
		interval = defaultDynamicSecretAccessInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ResolveDynamicSecretAccessOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("dynamic-secret access worker could not record every lease", slog.String("error", err.Error()))
			}
		}
	}
}

// ResolveDynamicSecretAccessOnce reads, once, the access of every lease that
// has none recorded, a stale one, or an unknown one due for a retry. A read
// that finds the access changed records the observation; one that finds it as
// recorded only stamps the recorded one (G2-L3), unless that is a day old,
// when it is recorded again as the heartbeat.
func (s *Server) ResolveDynamicSecretAccessOnce(ctx context.Context) error {
	if s.store == nil || s.orch == nil || s.secretIntegrations == nil {
		return nil
	}
	now := time.Now().UTC()
	tenants, err := s.store.TenantsWithActiveDynamicSecretLeases(ctx, now)
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
		leases, err := s.store.DynamicSecretLeasesNeedingAccess(ctx, tenantID, now,
			dynamicSecretAccessRefresh, dynamicSecretAccessRetry, dynamicSecretAccessBatch)
		if err != nil {
			note(err)
			continue
		}
		ids := make([]string, 0, len(leases))
		for _, lease := range leases {
			ids = append(ids, lease.ID)
		}
		previous, err := s.store.DynamicSecretLeaseAccessFor(ctx, tenantID, ids)
		if err != nil {
			note(err)
			continue
		}
		providers := s.secretIntegrations.dynamicProvidersForTenant(tenantID)
		for _, lease := range leases {
			observed := observeDynamicSecretLeaseAccess(ctx, providers, lease)
			prior, seen := previous[lease.ID]
			if seen && sameDynamicSecretLeaseAccess(prior, observed) && now.Sub(prior.CheckedAt) < dynamicSecretAccessHeartbeat {
				if _, err := s.store.RecheckDynamicSecretLeaseAccess(ctx, tenantID, lease.ID, prior.CheckedAt, now); err != nil {
					note(fmt.Errorf("lease %s: %w", lease.ID, err))
				}
				continue
			}
			// The observation is named after the one it supersedes, so two
			// leaders reading the same stale row record it once.
			supersedes := "first"
			if seen {
				supersedes = prior.CheckedAt.UTC().Format(time.RFC3339Nano)
			}
			eventID := uuid.NewSHA1(dynamicSecretAccessNamespace, []byte(tenantID+"\x00"+lease.ID+"\x00"+supersedes)).String()
			if err := s.orch.RecordDynamicSecretLeaseAccess(ctx, tenantID, eventID, observed); err != nil {
				note(fmt.Errorf("lease %s: %w", lease.ID, err))
			}
		}
	}
	return firstErr
}

func observeDynamicSecretLeaseAccess(ctx context.Context, providers []dynsecret.Provider, lease store.DynamicSecretLease) projections.DynamicSecretLeaseAccessObserved {
	observed := projections.DynamicSecretLeaseAccessObserved{LeaseID: lease.ID, Provider: lease.Provider}
	var provider dynsecret.Provider
	for _, candidate := range providers {
		if candidate.Name() == lease.Provider {
			provider = candidate
		}
	}
	if provider == nil {
		observed.Status, observed.Reason = store.DynamicSecretAccessUnknown, "provider_not_configured"
		return observed
	}
	resolver, ok := provider.(dynsecret.AccessResolver)
	if !ok {
		observed.Status, observed.Reason = store.DynamicSecretAccessUnsupported, dynsecret.AccessReason(dynsecret.ErrAccessUnsupported)
		return observed
	}
	callCtx, cancel := context.WithTimeout(ctx, dynamicSecretAccessCallTimeout)
	defer cancel()
	access, err := resolver.ResolveAccess(callCtx, lease.BackendRef)
	observed.TargetKind, observed.TargetRef, observed.Login = access.TargetKind, access.TargetRef, access.Login
	switch {
	case err == nil:
		observed.Status, observed.Grants, observed.Truncated = store.DynamicSecretAccessResolved, access.Grants, access.Truncated
	case errors.Is(err, dynsecret.ErrAccessUnsupported):
		observed.Status, observed.Reason = store.DynamicSecretAccessUnsupported, dynsecret.AccessReason(err)
	default:
		observed.Status, observed.Reason = store.DynamicSecretAccessUnknown, dynsecret.AccessReason(err)
	}
	return observed
}

// sameDynamicSecretLeaseAccess reports whether a read found a lease's access
// exactly as recorded: the same target, login, status and reason, and the
// same grants in the same order.
func sameDynamicSecretLeaseAccess(recorded store.DynamicSecretLeaseAccess, observed projections.DynamicSecretLeaseAccessObserved) bool {
	return recorded.Provider == observed.Provider && recorded.Status == observed.Status &&
		recorded.TargetKind == observed.TargetKind && recorded.TargetRef == observed.TargetRef &&
		recorded.Login == observed.Login && recorded.Reason == observed.Reason &&
		recorded.Truncated == observed.Truncated && slices.Equal(recorded.Grants, observed.Grants)
}
