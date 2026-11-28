// SPDX-License-Identifier: BUSL-1.1

package events

import "context"

// IngressObserveAppendStream reads the current source head inside the active
// producer admission. The result is valid only for that source and callback.
func IngressObserveAppendStream(ctx context.Context, tenantID string) (AppendStreamPosition, error) {
	scope, ok := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if !ok || scope == nil {
		return AppendStreamPosition{}, ErrAppendAdmissionUnavailable
	}
	scope.mu.Lock()
	if !scope.active || scope.history == nil {
		scope.mu.Unlock()
		return AppendStreamPosition{}, ErrAppendAdmissionUnavailable
	}
	scope.historyCalls.Add(1)
	log := scope.history
	scope.mu.Unlock()
	defer scope.historyCalls.Done()
	return log.ObserveAppendStream(ctx, tenantID)
}

// IngressEventByID reads one canonical event from the producer's source while
// the admission callback is active.
func IngressEventByID(ctx context.Context, eventID string) (Event, bool, error) {
	scope, ok := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if !ok || scope == nil || eventID == "" {
		return Event{}, false, ErrAppendAdmissionUnavailable
	}
	scope.mu.Lock()
	if !scope.active || scope.history == nil {
		scope.mu.Unlock()
		return Event{}, false, ErrAppendAdmissionUnavailable
	}
	scope.historyCalls.Add(1)
	log := scope.history
	scope.mu.Unlock()
	defer scope.historyCalls.Done()
	return log.EventByID(ctx, eventID)
}

// IngressAtStreamPosition binds the observed source head to the one-use
// publication callback. A changed head refuses publication.
func IngressAtStreamPosition(ctx context.Context, tenantID string, position AppendStreamPosition,
	publish func(context.Context) (Event, error),
) (Event, error) {
	scope, ok := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if !ok || scope == nil || publish == nil {
		return Event{}, ErrAppendAdmissionUnavailable
	}
	scope.mu.Lock()
	active := scope.active && scope.history != nil && position.log == scope.history &&
		position.stream != "" && position.tenantID == tenantID
	scope.mu.Unlock()
	if !active {
		return Event{}, ErrAppendAdmissionUnavailable
	}
	return publish(context.WithValue(ctx, appendStreamPositionKey{}, position))
}
