// SPDX-License-Identifier: BUSL-1.1
package backup_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

// CR-045: event-key lifetime and nested sealed-field validation need a finite
// read-only source from the HMAC-verified artifact before target NATS mutation.
func TestVerifiedHistoryReaderUsesArtifactWithoutTargetLogCR045(t *testing.T) {
	key := []byte("fixture-history-reader-integrity-key")
	artifact := makeBackup(t, key)
	called := false
	var escaped *backup.VerifiedHistoryReader
	err := backup.WithVerifiedHistoryReader(t.Context(), bytes.NewReader(artifact), key,
		func(reader *backup.VerifiedHistoryReader) error {
			called = true
			escaped = reader
			return reader.WithHistoryRead(t.Context(), func(ctx context.Context) error {
				head, err := reader.LastSequence(ctx)
				if err != nil || head != 3 {
					t.Fatalf("verified artifact cut=%d err=%v", head, err)
				}
				var first events.Event
				if err := reader.ReplayTypesThrough(ctx, 1, head, []string{"owner.created"}, func(event events.Event) error {
					first = event
					return nil
				}); err != nil {
					return err
				}
				if first.ID == "" || first.Sequence != 1 || string(first.Data) != `{"name":"payments"}` {
					t.Fatalf("artifact reader first event=%+v", first)
				}
				meta, found, err := reader.TenantMetadataByID(ctx, drTenant, first.ID)
				if err != nil || !found || meta.Sequence != 1 || meta.Type != first.Type {
					t.Fatalf("artifact metadata=%+v found=%t err=%v", meta, found, err)
				}
				event, found, err := reader.EventAtSequence(ctx, 1)
				if err != nil || !found || event.ID != first.ID {
					t.Fatalf("artifact sequence event=%+v found=%t err=%v", event, found, err)
				}
				return reader.ReplayTenantMetadataTypesThrough(ctx, drTenant, 1, head,
					[]string{"owner.created"}, func(meta events.EnvelopeMetadata) error {
						if meta.ID != first.ID || meta.Sequence != first.Sequence {
							t.Fatalf("tenant artifact metadata=%+v", meta)
						}
						return nil
					})
			})
		})
	if err != nil || !called {
		t.Fatalf("verified artifact reader called=%t err=%v", called, err)
	}
	if _, err := escaped.LastSequence(t.Context()); err == nil {
		t.Fatal("verified artifact reader remained usable after private spool cleanup")
	}
	called = false
	if err := backup.WithVerifiedHistoryReader(t.Context(), bytes.NewReader(artifact),
		[]byte("wrong-history-reader-integrity-key"),
		func(*backup.VerifiedHistoryReader) error { called = true; return nil }); err == nil || called {
		t.Fatalf("wrong-key artifact reached reader callback=%t err=%v", called, err)
	}
}

func TestVerifiedArtifactReaderSuppliesEventKeyRegistrationLifetimeCR045(t *testing.T) {
	ctx := t.Context()
	source := openLog(t)
	registration, err := source.Append(ctx, events.Event{ID: "artifact-registration",
		Type: "tenant.registered", TenantID: drTenant, Data: []byte(`{"name":"fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("fixture-registration-history-key")
	var artifact bytes.Buffer
	if _, err := backup.WriteLogWithKey(ctx, source, &artifact, key); err != nil {
		t.Fatal(err)
	}
	if err := backup.WithVerifiedHistoryReader(ctx, bytes.NewReader(artifact.Bytes()), key,
		func(reader *backup.VerifiedHistoryReader) error {
			policy := eventprivacy.SourcePolicy{Reader: reader}
			lifetime, err := policy.LatestLifetime(ctx, drTenant)
			if err != nil {
				return err
			}
			if lifetime.Registration.ID != registration.ID || lifetime.Activation != nil {
				t.Fatalf("artifact lifetime=%+v", lifetime)
			}
			return (eventprivacy.SourceKeys{Policy: policy}).VerifyCurrentCustody(ctx)
		}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedArtifactReaderKeepsScopeUntilConcurrentReplayFinishesCR045(t *testing.T) {
	key := []byte("plain concurrent artifact key")
	artifact := makeBackup(t, key)
	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	scanDone := make(chan error, 1)
	closed := make(chan error, 1)
	go func() {
		closed <- backup.WithVerifiedHistoryReader(context.Background(), bytes.NewReader(artifact), key,
			func(reader *backup.VerifiedHistoryReader) error {
				go func() {
					scanDone <- reader.ReplayThrough(context.Background(), 1, 3, func(events.Event) error {
						select {
						case <-entered:
						default:
							close(entered)
						}
						<-release
						return nil
					})
				}()
				select {
				case <-entered:
					return nil
				case <-time.After(3 * time.Second):
					return context.DeadlineExceeded
				}
			})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent verified replay did not start")
	}
	select {
	case err := <-closed:
		t.Fatalf("artifact scope ended while replay callback was active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	released = true
	if err := <-scanDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
