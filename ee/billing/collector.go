// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

type TenantLister func(context.Context) ([]string, error)

type Collector struct {
	store    Store
	tenants  TenantLister
	count    TenantCounter
	log      *slog.Logger
	now      func() time.Time
	mu       sync.Mutex
	observed map[string]resourceObservation
	maxGap   time.Duration
}

// NewCollector builds a resource sampler. PostgreSQL stores read their actual
// resources in the same transaction as the snapshot; count is the fallback for
// non-durable stores, which cannot authorize signed evidence.
func NewCollector(store Store, tenants TenantLister, count TenantCounter, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{store: store, tenants: tenants, count: count, log: log, now: time.Now,
		observed: map[string]resourceObservation{}, maxGap: 30 * time.Minute}
}

func (c *Collector) WithClock(now func() time.Time) *Collector {
	if now != nil {
		c.now = now
	}
	return c
}

func (c *Collector) Snapshot(ctx context.Context) error {
	if c == nil || c.store == nil || c.tenants == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tenants, err := c.tenants(ctx)
	if err != nil {
		clear(c.observed)
		return err
	}
	period := PeriodStart(c.now())
	seen := map[string]bool{}
	var failures []error
	for _, tenantID := range tenants {
		if seen[tenantID] {
			continue
		}
		seen[tenantID] = true
		if err := ctx.Err(); err != nil {
			clear(c.observed)
			return errors.Join(append(failures, err)...)
		}
		if durable, ok := c.store.(*PGStore); ok {
			tenantCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			observation, err := durable.collectResources(tenantCtx, tenantID, c.observed[tenantID], c.now, c.maxGap)
			stop()
			if err != nil {
				delete(c.observed, tenantID)
				failures = append(failures, fmt.Errorf("metering resources for %s: %w", tenantID, err))
			} else {
				c.observed[tenantID] = observation
			}
			continue
		}
		if c.count == nil {
			continue
		}
		counts, err := c.count(ctx, tenantID)
		if err != nil {
			if c.log != nil {
				c.log.Warn("metering tenant snapshot failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			}
			failures = append(failures, err)
			continue
		}
		for _, meter := range []string{usage.MeterAgents, usage.MeterTenants, usage.MeterCertificatesStored, usage.MeterSecretsStored} {
			value, ok := counts[meter]
			if !ok {
				continue
			}
			if err := c.store.SetGauge(ctx, tenantID, meter, period, value); err != nil {
				return err
			}
		}
	}
	for tenantID := range c.observed {
		if !seen[tenantID] {
			delete(c.observed, tenantID)
		}
	}
	return errors.Join(failures...)
}

func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	c.mu.Lock()
	c.maxGap = 2 * interval
	c.mu.Unlock()
	if err := c.Snapshot(ctx); err != nil && c.log != nil {
		c.log.Warn("metering initial snapshot failed", slog.String("error", err.Error()))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Snapshot(ctx); err != nil && c.log != nil {
				c.log.Warn("metering snapshot failed", slog.String("error", err.Error()))
			}
		}
	}
}
