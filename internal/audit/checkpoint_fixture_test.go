// SPDX-License-Identifier: BUSL-1.1

package audit_test

import (
	"context"
	"sync"
	"trstctl.com/trstctl/internal/audit"
)

// memCheckpoints supplies existing archive boundaries to core consumer tests.
type memCheckpoints struct {
	mu sync.Mutex
	m  map[string]audit.Checkpoint
}

func (c *memCheckpoints) LatestAuditCheckpoint(_ context.Context, tenantID string) (audit.Checkpoint, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.m[tenantID]
	return cp, ok, nil
}

func (c *memCheckpoints) SaveAuditCheckpoint(_ context.Context, cp audit.Checkpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]audit.Checkpoint{}
	}
	if cur, ok := c.m[cp.TenantID]; !ok || cp.BoundarySeq >= cur.BoundarySeq {
		c.m[cp.TenantID] = cp
	}
	return nil
}
