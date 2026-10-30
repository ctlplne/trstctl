// No exported method may mint this grant for an arbitrary handler.
// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"sync/atomic"

	"trstctl.com/trstctl/internal/eventprotect"
)

type destructionGrantKey struct{}

// DestructionAuthority exposes only authorization checking. Only this package
// can mint the short-lived exact-command grant after source/outbox validation.
// Nonzero size gives each controller a distinct pointer identity.
type DestructionAuthority struct{ _ byte }

func NewDestructionAuthority() *DestructionAuthority { return &DestructionAuthority{} }

type destructionGrant struct {
	authority *DestructionAuthority
	request   eventprotect.DestructionRequest
	active    atomic.Bool
}

func sameDestructionRequest(a, b eventprotect.DestructionRequest) bool {
	if !a.OffboardedAt.Equal(b.OffboardedAt) || !a.NotBefore.Equal(b.NotBefore) {
		return false
	}
	a.OffboardedAt, a.NotBefore = b.OffboardedAt, b.NotBefore
	return a == b
}

func (authority *DestructionAuthority) AuthorizeDestruction(ctx context.Context, request eventprotect.DestructionRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	grant, _ := ctx.Value(destructionGrantKey{}).(*destructionGrant)
	if authority == nil || grant == nil || grant.authority != authority || !grant.active.Load() || !sameDestructionRequest(grant.request, request) {
		return ErrSource
	}
	return nil
}

// Called by the receiver only after its verified exact command has
// all required fences. No source, SQL or custody reads happen in the authorizer.
func (authority *DestructionAuthority) withVerifiedDestructionGrant(ctx context.Context, request eventprotect.DestructionRequest, visit func(context.Context) error) error {
	if authority == nil || visit == nil || request.Validate() != nil {
		return ErrSource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	grant := &destructionGrant{authority: authority, request: request}
	grant.active.Store(true)
	defer grant.active.Store(false)
	return visit(context.WithValue(ctx, destructionGrantKey{}, grant))
}
