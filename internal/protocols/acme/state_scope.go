// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/events"
)

// StateScope identifies one retained tenant registration. Identity remains stable
// across history rebuilds; FirstSequence is its position in the current history.
// The zero value represents an absent tenant, never permission to replay all history.
type StateScope struct {
	Identity      string
	FirstSequence uint64
}

// StateScopeSource resolves the live registration. The served assembly supplies
// this together with an event log that checks the same scope before every append.
type StateScopeSource func(context.Context) (StateScope, error)

type stateScopeContextKey struct{}

// RequestStateScope returns the registration admitted for this operation. Durable
// adapters must reject a missing or superseded scope rather than infer authority
// from a tenant UUID that may have been reused.
func RequestStateScope(ctx context.Context) (StateScope, bool) {
	scope, ok := ctx.Value(stateScopeContextKey{}).(StateScope)
	return scope, ok
}

// WithStateScope must be called before WithStateLog and before accepting traffic.
// Standalone servers without this option retain their existing single-lifetime behavior.
func (s *Server) WithStateScope(source StateScopeSource) *Server {
	s.stateScopeSource = source
	return s
}

func (s *Server) beginStateScope(ctx context.Context) (context.Context, func(), error) {
	if s.stateScopeSource == nil {
		return ctx, func() {}, nil
	}
	for {
		s.stateScopeMu.RLock()
		scope, err := s.stateScopeSource(ctx)
		if err != nil || scope.Identity == "" || scope.FirstSequence == 0 {
			s.stateScopeMu.RUnlock()
			if err == nil {
				err = errors.New("acme: no live tenant registration")
			}
			return ctx, nil, err
		}
		if scope == s.stateScope {
			scoped := context.WithValue(ctx, stateScopeContextKey{}, scope)
			// P15-L1: another replica may have appended state since this view
			// last caught up; serve what the shared log holds.
			s.mu.Lock()
			err := s.catchUpLocked(scoped)
			s.mu.Unlock()
			if err != nil {
				s.stateScopeMu.RUnlock()
				return ctx, nil, err
			}
			return scoped, s.stateScopeMu.RUnlock, nil
		}
		s.stateScopeMu.RUnlock()
		// Only registration changes need an exclusive lock. Ordinary requests
		// remain concurrent; old in-flight handlers finish before their maps reset.
		s.stateScopeMu.Lock()
		scope, err = s.stateScopeSource(ctx)
		if err == nil && scope != s.stateScope {
			s.mu.Lock()
			s.resetStateScopeLocked()
			s.stateScope = scope
			err = s.replayStateScopeLocked(ctx)
			if err != nil {
				s.resetStateScopeLocked()
				s.stateScope = StateScope{}
			}
			s.mu.Unlock()
		}
		s.stateScopeMu.Unlock()
		if err != nil {
			return ctx, nil, err
		}
	}
}

func (s *Server) replayStateScopeLocked(ctx context.Context) error {
	from := uint64(1)
	if s.stateScopeSource != nil {
		if s.stateScope.Identity == "" && s.stateScope.FirstSequence == 0 {
			return nil
		}
		if s.stateScope.Identity == "" || s.stateScope.FirstSequence == 0 {
			return errors.New("acme: incomplete state scope")
		}
		from = s.stateScope.FirstSequence
		ctx = context.WithValue(ctx, stateScopeContextKey{}, s.stateScope)
	}
	if s.stateLog == nil {
		return errors.New("acme: scoped state requires an event log")
	}
	apply := func(ev events.Event) error {
		if ev.Sequence > s.stateThrough {
			s.stateThrough = ev.Sequence
		}
		if ev.TenantID != s.stateTenantID || !strings.HasPrefix(ev.Type, acmeEventPrefix) {
			return nil
		}
		return s.applyStateEventLocked(ev)
	}
	// The direct embedded-log path can use the same source index as the served
	// registration adapter. Other eventLog implementations keep their contract.
	if indexed, ok := s.stateLog.(interface {
		ReplayTenantTypesThrough(context.Context, string, uint64, uint64, []string, func(events.Event) error) error
		LastSequence(context.Context) (uint64, error)
		WithHistoryRead(context.Context, func(context.Context) error) error
	}); ok {
		return indexed.WithHistoryRead(ctx, func(readCtx context.Context) error {
			head, err := indexed.LastSequence(readCtx)
			if err != nil {
				return err
			}
			return indexed.ReplayTenantTypesThrough(readCtx, s.stateTenantID, from, head, StateEventTypes(), apply)
		})
	}
	return s.stateLog.Replay(ctx, from, apply)
}

// catchUpLocked applies the state events appended since this view last
// caught up, by this or another process sharing the log (P15-L1): every
// replica then serves the accounts, orders, authorizations, challenges and
// certificates the others created, and an email reply is matched on whichever
// replica receives it. Events this process appended and applied itself are
// skipped. When the log can say its head cheaply and nothing was appended
// since the last catch-up, nothing is read.
func (s *Server) catchUpLocked(ctx context.Context) error {
	if s.stateLog == nil || s.stateTenantID == "" {
		return nil
	}
	headLog, hasHead := s.stateLog.(interface {
		LastSequence(context.Context) (uint64, error)
	})
	head := uint64(0)
	if hasHead {
		var err error
		if head, err = headLog.LastSequence(ctx); err != nil {
			return fmt.Errorf("acme: state log head: %w", err)
		}
		if head <= s.stateHead {
			return nil
		}
	}
	from := s.stateThrough + 1
	if s.stateScopeSource != nil && from < s.stateScope.FirstSequence {
		from = s.stateScope.FirstSequence
	}
	err := s.stateLog.Replay(ctx, from, func(ev events.Event) error {
		if ev.Sequence > s.stateThrough {
			s.stateThrough = ev.Sequence
		}
		if s.ownApplied[ev.Sequence] {
			delete(s.ownApplied, ev.Sequence)
			return nil
		}
		if ev.TenantID != s.stateTenantID || !strings.HasPrefix(ev.Type, acmeEventPrefix) {
			return nil
		}
		return s.applyStateEventLocked(ev)
	})
	if err != nil {
		return fmt.Errorf("acme: catch up state: %w", err)
	}
	for seq := range s.ownApplied {
		if seq <= s.stateThrough {
			delete(s.ownApplied, seq)
		}
	}
	if head > s.stateHead {
		s.stateHead = head
	}
	return nil
}

func (s *Server) resetStateScopeLocked() {
	s.nonces = map[string]time.Time{}
	s.accounts = map[string]*account{}
	s.byKey = map[string]*account{}
	s.orders = map[string]*order{}
	s.authzs = map[string]*authorization{}
	s.challenges = map[string]*challenge{}
	s.certs = map[string][]byte{}
	s.issued = map[string]*issuedCert{}
	s.certOwner = map[string]string{}
	s.revoked = map[string]revocation{}
	s.ariWindows = map[string]ariWindow{}
	s.earlyRenew = map[string]bool{}
	s.seq = 0
	s.stateThrough, s.stateHead = 0, 0
	s.ownApplied = map[uint64]bool{}
	// Preserve configured EAB controls and abuse budgets. Account URLs include
	// the registration identity, so per-account limits cannot alias old accounts.
}
