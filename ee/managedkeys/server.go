package managedkeys

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
)

// NewFactory adapts the licensed managed-key lifecycle to the core server seam.
func NewFactory(backend crypto.RemoteKeyLifecycle) server.ManagedKeyServiceFactory {
	return func(d server.ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
		if d.Log == nil {
			return nil, errors.New("managedkeys: event log is required")
		}
		cfg := Config{
			Backend: backend,
			Sink:    eventLogSink{log: d.Log},
		}
		if d.Idempotency != nil {
			cfg.Idem = orchestratorIdempotency{idem: d.Idempotency}
		}
		if d.ApprovalChecker != nil {
			cfg.Gate = approvalGate{checker: d.ApprovalChecker}
		}
		return New(cfg)
	}
}

type eventLogSink struct{ log *events.Log }

func (s eventLogSink) Emit(ctx context.Context, e byok.LifecycleEvent) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: e.Type, TenantID: e.TenantID, Data: payload})
	return err
}

type orchestratorIdempotency struct{ idem *orchestrator.Idempotency }

func (o orchestratorIdempotency) Do(ctx context.Context, tenantID, key string, fn func(context.Context) (Result, error)) (Result, error) {
	raw, err := o.idem.Do(ctx, tenantID, key, func(ctx context.Context) ([]byte, error) {
		res, ferr := fn(ctx)
		if ferr != nil {
			return nil, ferr
		}
		return json.Marshal(res)
	})
	if err != nil {
		return Result{}, err
	}
	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return Result{}, err
	}
	return res, nil
}

type approvalGate struct{ checker api.ApprovalChecker }

func (g approvalGate) IsApproved(ctx context.Context, tenantID, keyID, action, requester string) (bool, string) {
	return g.checker.IsApproved(ctx, tenantID, keyID, action, requester)
}
