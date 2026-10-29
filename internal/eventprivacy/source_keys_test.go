// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// This fixture checks the source/custody read adapter only. The production
// destruction authorizer still has to verify the exact PostgreSQL outbox claim.
type sourceReadDestructionAuthority struct {
	want eventprotect.DestructionRequest
}

func (authority *sourceReadDestructionAuthority) AuthorizeDestruction(_ context.Context, request eventprotect.DestructionRequest) error {
	if request != authority.want {
		return eventprivacy.ErrSource
	}
	return nil
}

func TestSourceKeysUseRetainedCreationAndCurrentDestruction(t *testing.T) {
	base := t.TempDir()
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registration := appendSource(t, log, "key-read-registration", "tenant.registered", time.Now().UTC().Add(-2*time.Second), struct {
		Name string `json:"name"`
	}{"fixture"})
	requested, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	requestSource := appendSource(t, log, eventprivacy.RequestedEventID(requested), eventprivacy.EventRequested, registration.Time.Add(time.Second), requested)
	key, err := jose.GenerateRSASigningKey("source-key-readback-fixture")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &sourceReadDestructionAuthority{}
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: &sourceFixtureLocker{}, EvidenceKey: key, DestructionAuthority: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: requested.KeyID}
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := keys.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	activation := eventprivacy.Activated{RegistrationIdentity: requested.RegistrationIdentity, OperationID: requested.OperationID, KeyID: requested.KeyID, RetentionNanos: requested.RetentionNanos, RequestedEventID: requestSource.ID, RequestedSequence: requestSource.Sequence, RequestedAt: requestSource.Time, Creation: creation}
	appendSource(t, log, requested.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
	reader := eventprivacy.SourceKeys{Policy: eventprivacy.SourcePolicy{Log: log, Trust: key.JWKS()}, Custody: keys}
	admission := eventprivacy.SourceAdmission{Policy: reader.Policy, Custody: keys}
	decision, err := admission.EventProtectionFor(t.Context(), events.Event{TenantID: sourceTenant, Type: "fixture.private"})
	if err != nil || decision.Mode != events.EventProtectionSensitive || decision.Ref != ref {
		t.Fatalf("active source did not select its retained key: %+v %v", decision, err)
	}
	plain := []byte("source-bound private field")
	defer secret.Wipe(plain)
	var sealed []byte
	if err := reader.WithKey(t.Context(), ref, func(wrapper seal.KeyWrapper) error {
		var err error
		sealed, err = seal.SealDomain(wrapper, plain, []byte("fixture-context"), []byte("fixture-domain"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := reader.WithKey(t.Context(), ref, func(wrapper seal.KeyWrapper) error {
		opened, err := seal.OpenDomain(wrapper, sealed, []byte("fixture-context"), []byte("fixture-domain"))
		defer secret.Wipe(opened)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("source-backed key could not open its bytes: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	appendSource(t, log, "key-read-offboard", "tenant.offboarded", creation.CreatedAt.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	if _, err := admission.EventProtectionFor(t.Context(), events.Event{TenantID: sourceTenant, Type: "fixture.private"}); err == nil {
		t.Fatal("normal mutation into an offboarded lifetime was admitted")
	}
	if decision, err := admission.EventProtectionFor(t.Context(), events.Event{TenantID: sourceTenant, Type: "tenant.registered"}); err != nil || decision.Mode != events.EventProtectionLegacy {
		t.Fatalf("new registration could not begin a distinct lifetime: %+v %v", decision, err)
	}
	lifetime, err := reader.Policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	authorizer.want, err = eventprivacy.NewDestructionRequest(lifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Destroy(t.Context(), authorizer.want); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := reader.WithKey(t.Context(), ref, func(seal.KeyWrapper) error { called = true; return nil }); !errors.Is(err, eventprotect.ErrDestroyed) || called {
		t.Fatalf("current independent destruction was not applied to source-backed reads: %v called=%v", err, called)
	}
	// Completion is intentionally absent: a restored data cut can predate the
	// worker's source completion while current independent custody is destroyed.
	if lifetime.Completion != nil {
		t.Fatal("fixture unexpectedly published completion")
	}
}
