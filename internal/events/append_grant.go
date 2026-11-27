// SPDX-License-Identifier: BUSL-1.1
package events

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type appendGrantContextKey struct{}
type ingressProducerContextKey struct{}

type ingressProducerScope struct {
	mu           sync.Mutex
	digest       []byte
	explicitTime bool
	imported     bool
	active       bool
	history      *Log
	historyCalls sync.WaitGroup
}

// IngressIsImport distinguishes retained source history from a live producer
// command while the normalized append admission is active.
func IngressIsImport(ctx context.Context) bool {
	scope, _ := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if scope == nil {
		return false
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	return scope.active && scope.imported
}

// IngressEventAlreadyPublished preserves an exact producer retry when the
// current read model has changed since the original event projected.
func IngressEventAlreadyPublished(ctx context.Context, candidate Event) (bool, error) {
	scope, _ := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if scope == nil || candidate.ID == "" {
		return false, ErrAppendAdmissionUnavailable
	}
	var found bool
	err := WithIngressHistoryRead(ctx, func(readCtx context.Context) error {
		scope.mu.Lock()
		log := scope.history
		explicitTime := scope.explicitTime
		scope.mu.Unlock()
		if log == nil {
			return ErrAppendAdmissionUnavailable
		}
		canonical, exists, err := log.EventByID(readCtx, candidate.ID)
		found = exists && canonical.TenantID == candidate.TenantID && canonical.Type == candidate.Type &&
			canonical.SchemaVersion == candidate.SchemaVersion && bytes.Equal(canonical.Data, candidate.Data) &&
			sameProtectedActorEncoding(canonical.Actor, candidate.Actor) &&
			(!explicitTime || canonical.Time.Equal(candidate.Time))
		return err
	})
	return found, err
}

type ingressHistoryReadContextKey struct{}

type ingressHistoryReadGrant struct {
	log    *Log
	active atomic.Bool
}

// IngressHistoryReadPreheld reports whether the caller entered this exact
// log's history read wall before beginning append admission. Transaction
// owners use it to prove that their already-open B did not precede history A.
func IngressHistoryReadPreheld(ctx context.Context) bool {
	scope, _ := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	grant, _ := ctx.Value(ingressHistoryReadContextKey{}).(*ingressHistoryReadGrant)
	if scope == nil || grant == nil {
		return false
	}
	scope.mu.Lock()
	active := scope.active && grant.log == scope.history
	scope.mu.Unlock()
	return active && grant.active.Load()
}

// WithIngressHistoryRead lets the active append adapter acquire the source
// generation's read wall before it opens its durable commit transaction. The
// callback receives the reentrant read context used by protected publication.
// A retained admission context has no authority after Append or Import returns.
func WithIngressHistoryRead(ctx context.Context, fn func(context.Context) error) error {
	scope, ok := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if !ok || scope == nil || fn == nil {
		return ErrAppendAdmissionUnavailable
	}
	scope.mu.Lock()
	if !scope.active || scope.history == nil {
		scope.mu.Unlock()
		return ErrAppendAdmissionUnavailable
	}
	scope.historyCalls.Add(1)
	log := scope.history
	scope.mu.Unlock()
	defer scope.historyCalls.Done()
	return log.WithHistoryRead(ctx, fn)
}

// IngressProducerMAC computes the target-local journal commitment only for
// the exact normalized producer view inside its active admission callback.
// The returned MAC can be persisted; the readable view cannot.
func IngressProducerMAC(ctx context.Context, key []byte, keyID string, event Event) ([]byte, bool, error) {
	scope, ok := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if !ok || scope == nil {
		return nil, false, ErrAppendAdmissionUnavailable
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if !scope.active {
		return nil, false, ErrAppendAdmissionUnavailable
	}
	digest, err := appendProducerDigest(event, scope.explicitTime)
	if err != nil {
		return nil, false, err
	}
	defer secret.Wipe(digest)
	if !crypto.ConstantTimeEqual(scope.digest, digest) {
		return nil, false, ErrAppendAdmissionUnavailable
	}
	mac, err := appendProducerMAC(key, keyID, event, scope.explicitTime)
	if err != nil {
		return nil, false, err
	}
	return mac, scope.explicitTime, nil
}

// IngressCanonicalProducerMAC authenticates a returned canonical event under
// the same active attempt's key and explicit-time choice. A public duplicate
// may intentionally have a different MAC from the discarded candidate.
func IngressCanonicalProducerMAC(ctx context.Context, key []byte, keyID string,
	canonical Event,
) ([]byte, bool, error) {
	scope, ok := ctx.Value(ingressProducerContextKey{}).(*ingressProducerScope)
	if !ok || scope == nil {
		return nil, false, ErrAppendAdmissionUnavailable
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if !scope.active {
		return nil, false, ErrAppendAdmissionUnavailable
	}
	mac, err := appendProducerMAC(key, keyID, canonical, scope.explicitTime)
	if err != nil {
		return nil, false, err
	}
	return mac, scope.explicitTime, nil
}

// The grant is scoped to one normalized producer call. Protection may replace
// the stored Data/Actor fields, while the in-memory Event still carries their
// producer view through the publication boundary.
type appendGrant struct {
	log          *Log
	digest       []byte
	explicitTime bool
	active       atomic.Bool
}

func appendProducerView(event Event, explicitTime bool) ([]byte, error) {
	return json.Marshal(struct {
		ID, Type, TenantID string
		Time               int64
		SchemaVersion      int
		Data               []byte
		Actor              *Actor
		ExplicitTime       bool
	}{event.ID, event.Type, event.TenantID, event.Time.UnixNano(),
		event.SchemaVersion, event.Data, event.Actor, explicitTime})

}

func appendProducerDigest(event Event, explicitTime bool) ([]byte, error) {
	wire, err := appendProducerView(event, explicitTime)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(wire)
	return crypto.SHA256Sum(wire), nil
}

// appendProducerMAC binds the readable normalized producer view to a distinct
// versioned target-local integrity key. Only this keyed value may be retained
// in the ingress journal; the readable view and its unkeyed digest stay local.
func appendProducerMAC(key []byte, keyID string, event Event, explicitTime bool) ([]byte, error) {
	if len(key) != 32 || keyID == "" {
		return nil, ErrAppendAdmissionUnavailable
	}
	// The append path fills an omitted Time on every attempt. Bind the caller's
	// time only when it was supplied, so an otherwise identical retry has the
	// same journal identity after normalization.
	if !explicitTime {
		event.Time = time.Unix(0, 0)
	}
	wire, err := appendProducerView(event, explicitTime)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(wire)
	const domain = "trstctl.event-ingress.producer.v1\x00"
	material := make([]byte, 0, len(domain)+len(keyID)+1+len(wire))
	material = append(material, domain...)
	material = append(material, keyID...)
	material = append(material, 0)
	material = append(material, wire...)
	defer secret.Wipe(material)
	return crypto.HMACSHA256(key, material), nil
}

func (l *Log) withAppendGrant(ctx context.Context, event Event, explicitTime bool,
	fn func(context.Context) (Event, error),
) (Event, error) {
	digest, err := appendProducerDigest(event, explicitTime)
	if err != nil {
		return Event{}, err
	}
	grant := &appendGrant{log: l, digest: digest, explicitTime: explicitTime}
	grant.active.Store(true)
	defer func() {
		grant.active.Store(false)
		secret.Wipe(grant.digest)
	}()
	return fn(context.WithValue(ctx, appendGrantContextKey{}, grant))
}

func (l *Log) requireAppendGrant(ctx context.Context, event Event) error {
	grant, ok := ctx.Value(appendGrantContextKey{}).(*appendGrant)
	if !ok || grant == nil || grant.log != l || !grant.active.Load() {
		return ErrAppendAdmissionUnavailable
	}
	digest, err := appendProducerDigest(event, grant.explicitTime)
	if err != nil {
		return err
	}
	defer secret.Wipe(digest)
	if !crypto.ConstantTimeEqual(grant.digest, digest) {
		return ErrAppendAdmissionUnavailable
	}
	return nil
}
