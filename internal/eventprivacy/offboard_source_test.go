// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

func TestSourceOffboardWithoutOptInDoesNotInventDestruction(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "events")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registered := appendSource(t, log, "legacy-registration", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"legacy fixture name"})
	offboard := appendSource(t, log, "legacy-offboard", "tenant.offboarded", registered.Time.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	policy := eventprivacy.SourcePolicy{Log: log}
	request, protected, err := policy.EventKeyDestructionForOffboard(t.Context(), offboard)
	if err != nil || protected || request.Ref.ID != "" {
		t.Fatalf("default-off tenant acquired invented custody authority: %+v %v", request, err)
	}
	after, found, err := log.EventAtSequence(t.Context(), registered.Sequence)
	if err != nil || !found || after.Protection != nil || !bytes.Equal(after.Data, registered.Data) {
		t.Fatalf("default-off source bytes changed: %v", err)
	}
}

func TestSourceOffboardIntentBindsHistoricalLifetimeWithoutOpeningCustody(t *testing.T) {
	policy, log, registration, activation := sourceFixture(t, nil)
	offboard := appendSource(t, log, "privacy-offboard-source", "tenant.offboarded", activation.Creation.CreatedAt.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	// This policy owns no key provider. Missing/unavailable custody must never
	// force SQL to retain personal rows or manufacture a destruction receipt.
	command, protected, err := policy.EventKeyDestructionForOffboard(t.Context(), offboard)
	if err != nil || !protected || command.Ref.ID != activation.KeyID || command.RegistrationIdentity != registration.ID ||
		command.CreationDigest != activation.Creation.Digest() || command.OffboardEventID != offboard.ID ||
		command.OffboardSequence != offboard.Sequence || !command.NotBefore.Equal(offboard.Time.Add(time.Hour)) {
		t.Fatalf("offboard did not preserve exact public source coordinates: %+v %v", command, err)
	}
	appendSource(t, log, "privacy-new-lifetime", "tenant.registered", offboard.Time.Add(time.Nanosecond), struct {
		Name string `json:"name"`
	}{"new lifetime"})
	retry, protected, err := policy.EventKeyDestructionForOffboard(t.Context(), offboard)
	if err != nil || !protected || retry != command {
		t.Fatalf("historical retry adopted another lifetime: %+v %v", retry, err)
	}
	for name, mutate := range map[string]func(*events.Event){
		"identity": func(e *events.Event) { e.ID = "invented-offboard" },
		"sequence": func(e *events.Event) { e.Sequence++ },
		"time":     func(e *events.Event) { e.Time = e.Time.Add(time.Second) },
		"schema":   func(e *events.Event) { e.SchemaVersion++ },
		"tenant":   func(e *events.Event) { e.TenantID = "22222222-2222-2222-2222-222222222222" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := offboard
			mutate(&changed)
			if _, _, err := policy.EventKeyDestructionForOffboard(t.Context(), changed); !errors.Is(err, eventprivacy.ErrSource) {
				t.Fatalf("changed source gained a destruction intent: %v", err)
			}
		})
	}
}
