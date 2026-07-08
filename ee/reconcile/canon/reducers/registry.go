// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reducers

import (
	"context"
	"fmt"
	"sync"
)

type PlaneReducer interface {
	Observe(ctx context.Context, tenantID string) (Observation, error)
}

type Registry struct {
	mu       sync.RWMutex
	reducers map[string]PlaneReducer
}

func NewRegistry() *Registry {
	return &Registry{reducers: map[string]PlaneReducer{}}
}

func (r *Registry) Register(name string, reducer PlaneReducer) error {
	if name == "" {
		return fmt.Errorf("xrec reducers: reducer name required")
	}
	if reducer == nil {
		return ErrMissingSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reducers[name] = reducer
	return nil
}

func (r *Registry) Observe(ctx context.Context, name, tenantID string) (Observation, error) {
	if r == nil {
		return Observation{}, fmt.Errorf("xrec reducers: registry is nil")
	}
	r.mu.RLock()
	reducer := r.reducers[name]
	r.mu.RUnlock()
	if reducer == nil {
		return Observation{}, fmt.Errorf("xrec reducers: reducer %q is not registered", name)
	}
	return reducer.Observe(ctx, tenantID)
}
