// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrResourceAdmissionBusy asks a creator to retry. No quota decision or domain
// event has been made while another replica admits the same tenant's resource.
var ErrResourceAdmissionBusy = errors.New("resource creation is in progress; retry the same request")

// WithTenantResourceCreation serializes one resource's first creation across
// replicas. It holds a PostgreSQL SESSION advisory lock, never a SQL transaction,
// across the caller's quota read, event append and projection. The session comes
// from the tenant service fence when one is active; that lets nested projection
// locks reuse the same lock-pool connection. The lock key includes both tenant
// and resource, so unrelated customers and resource types keep moving.
func (s *Store) WithTenantResourceCreation(ctx context.Context, tenantID, resource string, fn func(context.Context) error) (result error) {
	if s == nil || fn == nil {
		return errors.New("store: resource creation fence is incomplete")
	}
	parsed, err := uuid.Parse(tenantID)
	if err != nil || strings.TrimSpace(resource) == "" || len(resource) > 64 {
		return errors.New("store: resource creation fence needs a tenant UUID and resource")
	}
	tenantID = parsed.String()
	if held, _ := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence); held == nil {
		work, release, err := s.BeginTenantService(ctx, tenantID)
		if err != nil {
			return err
		}
		defer release()
		ctx = work
	} else if held.store != s || held.tenantID != tenantID || !held.active.Load() {
		return errors.New("store: resource creation fence has a foreign or expired tenant service session")
	}
	name := "resource-create\x1f" + tenantID + "\x1f" + resource
	conn, done, err := s.borrowTenantServiceSession(ctx)
	if err != nil {
		return err
	}
	var acquired bool
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, name).Scan(&acquired)
	if err != nil {
		// A canceled query may have obtained the session lock without returning
		// the result. Closing the connection is the only unambiguous release.
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = conn.Conn().Close(cleanup)
		cancel()
	}
	done()
	if err != nil {
		return fmt.Errorf("store: acquire resource creation fence: %w", err)
	}
	if !acquired {
		return ErrResourceAdmissionBusy
	}
	defer func() {
		conn, done, err := s.borrowTenantServiceSession(ctx)
		if err != nil {
			if result == nil {
				result = err
			}
			return
		}
		defer done()
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var released bool
		unlockErr := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, name).Scan(&released)
		if unlockErr != nil || !released {
			_ = conn.Conn().Close(cleanup)
			if result == nil {
				result = fmt.Errorf("store: release resource creation fence: %v (released=%v)", unlockErr, released)
			}
		}
	}()
	return fn(ctx)
}
