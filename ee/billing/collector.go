// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

type TenantLister func(context.Context) ([]string, error)

type Collector struct {
	store   Store
	tenants TenantLister
	count   TenantCounter
	log     *slog.Logger
	now     func() time.Time
}

func NewCollector(store Store, tenants TenantLister, count TenantCounter, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{store: store, tenants: tenants, count: count, log: log, now: time.Now}
}

func (c *Collector) WithClock(now func() time.Time) *Collector {
	if now != nil {
		c.now = now
	}
	return c
}

func (c *Collector) Snapshot(ctx context.Context) error {
	if c == nil || c.store == nil || c.tenants == nil || c.count == nil {
		return nil
	}
	tenants, err := c.tenants(ctx)
	if err != nil {
		return err
	}
	period := PeriodStart(c.now())
	for _, tenantID := range tenants {
		counts, err := c.count(ctx, tenantID)
		if err != nil {
			if c.log != nil {
				c.log.Warn("metering tenant snapshot failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			}
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
	return nil
}

func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
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
