// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// Real NATS/current file authority and signed destruction, but local fixture
// locks and authorizer. This is not production outbox, PG or process proof.
func currentCustodyFixture(t *testing.T) (eventprivacy.SourceKeys, *events.Log, *eventprotect.FileAuthority, string, eventprotect.KeyRef, *sourceReadDestructionAuthority) {
	t.Helper()
	base := t.TempDir()
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registration := appendSource(t, log, "current-custody-registration", "tenant.registered", time.Now().UTC().Add(-2*time.Second), struct {
		Name string `json:"name"`
	}{"fixture"})
	request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	requested := appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, registration.Time.Add(time.Second), request)
	key, err := jose.GenerateRSASigningKey("current-custody-fixture")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "independent-keys")
	authorizer := &sourceReadDestructionAuthority{}
	custody, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: directory, BackupRoots: []string{filepath.Join(base, "events")}, Locker: &sourceFixtureLocker{}, EvidenceKey: key, DestructionAuthority: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: request.KeyID}
	if err := custody.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := custody.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	activation := eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.KeyID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
	appendSource(t, log, request.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
	return eventprivacy.SourceKeys{Policy: eventprivacy.SourcePolicy{Log: log, Trust: key.JWKS()}, Custody: custody}, log, custody, directory, ref, authorizer
}

func TestCurrentCustodyProbeChecksMaterialAndRecordWithoutRegeneration(t *testing.T) {
	for _, suffix := range []string{".key", ".json"} {
		t.Run(suffix, func(t *testing.T) {
			reader, _, custody, directory, ref, _ := currentCustodyFixture(t)
			original, err := custody.CreationEvidence(t.Context(), ref)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.VerifyCurrentCustody(t.Context()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, ref.TenantID, ref.ID+suffix)
			held := path + ".held-by-custody-test"
			if err := os.Rename(path, held); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := os.Stat(held); err == nil {
					_ = os.Rename(held, path)
				}
			})
			if err := reader.VerifyCurrentCustody(t.Context()); !errors.Is(err, eventprotect.ErrKey) {
				t.Fatalf("missing custody became healthy/erased: %v", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("probe recreated missing custody")
			}
			if err := os.Rename(held, path); err != nil {
				t.Fatal(err)
			}
			if err := reader.VerifyCurrentCustody(t.Context()); err != nil {
				t.Fatal(err)
			}
			got, err := custody.CreationEvidence(t.Context(), ref)
			if err != nil || got.Digest() != original.Digest() {
				t.Fatal("probe regenerated creation identity")
			}
		})
	}
}

func TestCurrentCustodyProbeAcceptsOnlyVerifiedRemovalAndCurrentAbsence(t *testing.T) {
	reader, log, custody, directory, ref, authorizer := currentCustodyFixture(t)
	appendSource(t, log, "current-custody-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := reader.Policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	authorizer.want, err = eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.Destroy(t.Context(), authorizer.want); err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyCurrentCustody(t.Context()); err != nil {
		t.Fatalf("signed independently verified removal was unhealthy: %v", err)
	}
	path := filepath.Join(directory, ref.TenantID, ref.ID+".key")
	// Path reappearance alone invalidates a destruction claim; no saved key bytes
	// or second recoverable key copy are needed for this negative.
	if err := os.WriteFile(path, []byte("not-key-material"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyCurrentCustody(t.Context()); !errors.Is(err, eventprotect.ErrKey) {
		t.Fatalf("reintroduced material retained erased/healthy status: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyCurrentCustody(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentCustodyProbeDoesNotHideLaterInvalidSourceOrMissingAdapter(t *testing.T) {
	reader, log, _, _, _, _ := currentCustodyFixture(t)
	missing := reader
	missing.Custody = nil
	if err := missing.VerifyCurrentCustody(t.Context()); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatal("missing current adapter reported healthy")
	}
	if _, err := log.Append(t.Context(), events.Event{Type: eventprivacy.EventDestroyed, TenantID: sourceTenant, SchemaVersion: 3, Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyCurrentCustody(t.Context()); err == nil {
		t.Fatal("partial prefix success hid invalid later source")
	}
}

func TestCurrentCustodyProbeLegacyNeedsNoKeysAndHonorsCancellation(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "events")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendSource(t, log, "current-custody-legacy", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"fixture"})
	reader := eventprivacy.SourceKeys{Policy: eventprivacy.SourcePolicy{Log: log}}
	if err := reader.VerifyCurrentCustody(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reader.VerifyCurrentCustody(ctx); err == nil {
		t.Fatal("canceled source probe reported verified health")
	}
}
