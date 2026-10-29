// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

const sourceTenant = "d59b4292-1adc-4d43-a405-781f95b1779c"

// This lock is ONLY a single-process source-parser fixture. PostgreSQL session
// nesting is separately exercised by internal/store's real integration tests.
type sourceFixtureLocker struct{ mu sync.Mutex }
type sourceFixtureGrantKey struct{}

func (locker *sourceFixtureLocker) WithKeyLock(ctx context.Context, _ eventprotect.KeyRef, fn func(context.Context) error) error {
	if held, _ := ctx.Value(sourceFixtureGrantKey{}).(*sourceFixtureLocker); held == locker {
		return fn(ctx)
	}
	locker.mu.Lock()
	defer locker.mu.Unlock()
	return fn(context.WithValue(ctx, sourceFixtureGrantKey{}, locker))
}

func (locker *sourceFixtureLocker) WithTenantEventProtection(ctx context.Context, tenantID string, fn func(context.Context) error) error {
	return locker.WithKeyLock(ctx, eventprotect.KeyRef{TenantID: tenantID}, fn)
}

func appendSource(t *testing.T, log *events.Log, id, kind string, when time.Time, body any) events.Event {
	t.Helper()
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(t.Context(), events.Event{ID: id, Type: kind, TenantID: sourceTenant, Time: when, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func sourceFixture(t *testing.T, mutate func(*eventprivacy.Activated)) (eventprivacy.SourcePolicy, *events.Log, events.Event, eventprivacy.Activated) {
	t.Helper()
	base := t.TempDir()
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registration := appendSource(t, log, "privacy-first-registration", "tenant.registered", time.Now().UTC().Add(-2*time.Second), struct {
		Name string `json:"name"`
	}{"first name"})
	request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requested := appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, registration.Time.Add(time.Second), request)
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "independent-keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: &sourceFixtureLocker{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: request.KeyID}
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := keys.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	activation := eventprivacy.Activated{RegistrationIdentity: request.RegistrationIdentity, OperationID: request.OperationID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
	if mutate != nil {
		mutate(&activation)
	}
	appendSource(t, log, request.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
	return eventprivacy.SourcePolicy{Log: log}, log, registration, activation
}

func TestSourceAuthorityKeepsFirstRegistrationThroughRename(t *testing.T) {
	policy, log, first, activation := sourceFixture(t, nil)
	appendSource(t, log, "privacy-renamed-registration", "tenant.registered", activation.Creation.CreatedAt.Add(time.Nanosecond), struct {
		Name string `json:"name"`
	}{"renamed"})
	state, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	if state.Registration.ID != first.ID || state.Activation == nil || state.Activation.Body.KeyID != activation.KeyID || state.Offboard != nil {
		t.Fatal("rename changed the source-backed key lifetime")
	}
}

func TestSourceAuthorityTenantAliasesCannotBecomeUnprotected(t *testing.T) {
	policy, _, _, activation := sourceFixture(t, nil)
	for _, alias := range []string{strings.ToUpper(sourceTenant), "urn:uuid:" + sourceTenant} {
		state, err := policy.LatestLifetime(t.Context(), alias)
		if err != nil || state.Activation == nil || state.Activation.Body.KeyID != activation.KeyID {
			t.Fatalf("tenant spelling lost active protection authority: alias=%s err=%v", alias, err)
		}
	}
}

func TestSourceAuthorityDistinguishesSameUUIDReregistration(t *testing.T) {
	policy, log, first, activation := sourceFixture(t, nil)
	offboard := appendSource(t, log, "privacy-offboard-source", "tenant.offboarded", activation.Creation.CreatedAt.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	state, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil || state.Registration.ID != first.ID || state.Offboard == nil || state.Offboard.ID != offboard.ID || state.Activation == nil {
		t.Fatalf("offboard lost its exact activation lifetime: %v", err)
	}
	registered := appendSource(t, log, "privacy-new-lifetime", "tenant.registered", offboard.Time.Add(time.Nanosecond), struct {
		Name string `json:"name"`
	}{"same UUID new tenant"})
	state, err = policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil || state.Registration.ID != registered.ID || state.Activation != nil || state.Request != nil || state.Offboard != nil {
		t.Fatalf("new registration inherited erased lifetime authority: %v", err)
	}
	newRequest, err := eventprivacy.NewRequested(sourceTenant, registered.ID, time.Hour)
	if err != nil || newRequest.KeyID == activation.KeyID {
		t.Fatal("new lifetime reused the old key identity")
	}
}

func TestSourceAuthorityRefusesInventedActivationParent(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*eventprivacy.Activated)
	}{
		{"sequence", func(a *eventprivacy.Activated) { a.RequestedSequence++ }},
		{"identity", func(a *eventprivacy.Activated) { a.RequestedEventID = "invented-request-source" }},
		{"time", func(a *eventprivacy.Activated) { a.RequestedAt = a.RequestedAt.Add(-time.Second) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			policy, _, _, _ := sourceFixture(t, mutate.change)
			if _, err := policy.LatestLifetime(t.Context(), sourceTenant); !errors.Is(err, eventprivacy.ErrSource) {
				t.Fatalf("invented activation parent accepted: %v", err)
			}
		})
	}
}

func TestSourceAuthorityRefusesUnsignedCompletion(t *testing.T) {
	policy, log, _, activation := sourceFixture(t, nil)
	offboard := appendSource(t, log, "privacy-offboard-source", "tenant.offboarded", activation.Creation.CreatedAt.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	appendSource(t, log, "privacy-invented-completion", eventprivacy.EventDestroyed, offboard.Time.Add(time.Hour), eventprivacy.Destroyed{JWS: "unsigned-claim"})
	if _, err := policy.LatestLifetime(t.Context(), sourceTenant); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("unsigned completion gained source authority: %v", err)
	}
}
