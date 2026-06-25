package api

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

const apiTokenExpirySweepLimit = 100

// apiTokenLeaseEngine adapts event-sourced API-token expiry to the generic
// leaseworker.Engine contract. API tokens have no external revocation outbox: once
// the api_token.revoked event is projected, authentication stops accepting them.
type apiTokenLeaseEngine struct {
	orch  *orchestrator.Orchestrator
	limit int
}

func (e apiTokenLeaseEngine) ExpireDue(ctx context.Context, now time.Time) (int, error) {
	if e.orch == nil {
		return 0, nil
	}
	limit := e.limit
	if limit <= 0 {
		limit = apiTokenExpirySweepLimit
	}
	return e.orch.ExpireAPITokens(ctx, now, limit)
}

func (apiTokenLeaseEngine) RunRevocations(context.Context) (int, error) { return 0, nil }
