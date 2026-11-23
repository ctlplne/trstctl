// SPDX-License-Identifier: BUSL-1.1
package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// CR-045: the target-local producer journal must bind the normalized readable
// view with a secret MAC. A different tenant, actor, payload or explicit-time
// choice must never verify under the same versioned key.
func TestAppendProducerMACBindsNormalizedViewCR045(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 32)
	event := Event{ID: "plain-journal-event", Type: "tenant.registered",
		TenantID:      "49900000-0000-4000-8000-0000000000c1",
		Time:          time.Date(2026, time.November, 21, 3, 30, 0, 0, time.UTC),
		SchemaVersion: 1, Data: []byte(`{"label":"plain-value"}`),
		Actor: &Actor{Subject: "plain-actor"}}
	base, err := appendProducerMAC(key, "plain-journal-v1", event, false)
	if err != nil {
		t.Fatal(err)
	}
	checkDifferent := func(name string, changed Event, explicitTime bool, changedKey []byte, keyID string) {
		t.Helper()
		mac, err := appendProducerMAC(changedKey, keyID, changed, explicitTime)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if crypto.ConstantTimeEqual(base, mac) {
			t.Fatalf("%s reused the original producer MAC", name)
		}
	}
	changed := event
	changed.TenantID = "49900000-0000-4000-8000-0000000000c2"
	checkDifferent("tenant", changed, false, key, "plain-journal-v1")
	changed = event
	changed.Data = []byte(`{"label":"different-value"}`)
	checkDifferent("payload", changed, false, key, "plain-journal-v1")
	changed = event
	changed.Actor = &Actor{Subject: "another-actor"}
	checkDifferent("actor", changed, false, key, "plain-journal-v1")
	checkDifferent("explicit time", event, true, key, "plain-journal-v1")
	checkDifferent("key version", event, false, key, "plain-journal-v2")
	checkDifferent("key material", event, false, bytes.Repeat([]byte{0x32}, 32), "plain-journal-v1")
	omittedTimeRetry := event
	omittedTimeRetry.Time = event.Time.Add(2 * time.Hour)
	omittedMAC, err := appendProducerMAC(key, "plain-journal-v1", omittedTimeRetry, false)
	if err != nil || !crypto.ConstantTimeEqual(base, omittedMAC) {
		t.Fatalf("omitted-time retry changed producer MAC: %v", err)
	}
	checkDifferent("supplied time", omittedTimeRetry, true, key, "plain-journal-v1")
	again, err := appendProducerMAC(key, "plain-journal-v1", event, false)
	if err != nil || !crypto.ConstantTimeEqual(base, again) {
		t.Fatalf("same normalized view did not reproduce producer MAC: %v", err)
	}
	if _, err := appendProducerMAC(nil, "plain-journal-v1", event, false); err == nil {
		t.Fatal("producer MAC accepted missing key")
	}
}

// CR-045: the server may commit only the MAC for the event normalized in the
// active admission callback; it must not have to retain the readable payload.
func TestAppendAdmissionProducerMACContextCR045(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	var admittedMAC []byte
	var escapedContext context.Context
	log, err := Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithAppendAdmission(func(ctx context.Context, event Event,
			publish func(context.Context) (Event, error),
		) (Event, error) {
			escapedContext = ctx
			var err error
			admittedMAC, _, err = IngressProducerMAC(ctx, key, "plain-journal-v1", event)
			if err != nil {
				return Event{}, err
			}
			changed := event
			changed.Data = []byte(`{"label":"different-value"}`)
			if _, _, err := IngressProducerMAC(ctx, key, "plain-journal-v1", changed); err == nil {
				return Event{}, errors.New("admission MAC accepted a different producer view")
			}
			canonicalMAC, _, err := IngressCanonicalProducerMAC(ctx, key, "plain-journal-v1", changed)
			if err != nil || crypto.ConstantTimeEqual(admittedMAC, canonicalMAC) {
				return Event{}, errors.New("canonical MAC did not bind a distinct returned view")
			}
			return publish(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	input := Event{Type: "tenant.registered", TenantID: "49900000-0000-4000-8000-0000000000c1",
		Data: []byte(`{"label":"plain-value"}`)}
	if _, _, err := IngressProducerMAC(t.Context(), key, "plain-journal-v1", input); err == nil {
		t.Fatal("MAC accepted context outside admission")
	}
	published, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := appendProducerMAC(key, "plain-journal-v1", published, false)
	if err != nil || !crypto.ConstantTimeEqual(admittedMAC, expected) {
		t.Fatalf("admission MAC did not bind normalized published event: %v", err)
	}
	if _, _, err := IngressProducerMAC(escapedContext, key, "plain-journal-v1", published); err == nil {
		t.Fatal("admission MAC remained usable after callback")
	}
	if _, _, err := IngressCanonicalProducerMAC(escapedContext, key, "plain-journal-v1", published); err == nil {
		t.Fatal("canonical MAC remained usable after callback")
	}
}

// The ingress owner must acquire the history read wall before opening its
// key-state commit transaction. The read grant belongs to this one admission;
// a context retained by a callback cannot acquire it after Append returns.
func TestAppendAdmissionCanAcquireHistoryBeforePublishCR045(t *testing.T) {
	var escaped context.Context
	var escapedRead context.Context
	var historyHeld bool
	log, err := Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithAppendAdmission(func(ctx context.Context, _ Event,
			publish func(context.Context) (Event, error),
		) (Event, error) {
			escaped = ctx
			if IngressHistoryReadPreheld(ctx) {
				return Event{}, errors.New("admission arrived with an invented history grant")
			}
			var published Event
			err := WithIngressHistoryRead(ctx, func(readCtx context.Context) error {
				escapedRead = readCtx
				if !IngressHistoryReadPreheld(readCtx) {
					return errors.New("history read callback lost its active admission grant")
				}
				historyHeld = true
				var publishErr error
				published, publishErr = publish(readCtx)
				return publishErr
			})
			return published, err
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(t.Context(), Event{Type: "tenant.registered",
		TenantID: "49900000-0000-4000-8000-0000000000f1", Data: []byte(`{"label":"plain-value"}`)}); err != nil {
		t.Fatal(err)
	}
	if !historyHeld {
		t.Fatal("ingress callback did not hold history before publication")
	}
	if err := WithIngressHistoryRead(escaped, func(context.Context) error { return nil }); err == nil {
		t.Fatal("escaped admission reacquired history after append")
	}
	if IngressHistoryReadPreheld(escaped) {
		t.Fatal("escaped admission retained a history grant")
	}
	if IngressHistoryReadPreheld(escapedRead) {
		t.Fatal("expired history read callback retained its grant")
	}
	if err := WithIngressHistoryRead(t.Context(), func(context.Context) error { return nil }); err == nil {
		t.Fatal("unadmitted context acquired ingress history")
	}
}

// CR-045: a broker ACK alone is insufficient to settle ingress. The callback
// must see authenticated canonical bytes and distinguish a duplicate return.
func TestIngressCanonicalProofUsesRawWireAndDuplicateOutcomeCR045(t *testing.T) {
	var outcomes []struct {
		hash      string
		duplicate bool
		data      string
	}
	log, err := Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithAppendAdmission(func(ctx context.Context, _ Event,
			publish func(context.Context) (Event, error),
		) (Event, error) {
			return publish(ctx)
		}),
		WithIngressCanonicalProof(func(_ context.Context, candidate, canonical Event, rawHash string, duplicate bool) error {
			if candidate.ID != canonical.ID || canonical.Sequence == 0 {
				return errors.New("canonical proof did not bind event identity and sequence")
			}
			outcomes = append(outcomes, struct {
				hash      string
				duplicate bool
				data      string
			}{rawHash, duplicate, string(canonical.Data)})
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	base := Event{ID: "plain-canonical-event", Type: "tenant.registered",
		TenantID: "49900000-0000-4000-8000-0000000000c1", Data: []byte(`{"label":"plain-value"}`)}
	first, err := log.Append(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	retry := base
	retry.Data = []byte(`{"label":"changed-public-value"}`)
	duplicate, err := log.Append(t.Context(), retry)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || outcomes[0].duplicate || !outcomes[1].duplicate ||
		outcomes[0].hash == "" || outcomes[0].hash != outcomes[1].hash ||
		outcomes[0].data != string(base.Data) || outcomes[1].data != string(base.Data) ||
		duplicate.Sequence != first.Sequence {
		t.Fatalf("canonical outcomes=%+v first=%d duplicate=%d", outcomes, first.Sequence, duplicate.Sequence)
	}
}

// CR-045: the exact serialized candidate must be journaled before either
// Append or Import may call JetStream. A failed stage leaves the stream empty.
func TestAppendWireStagePrecedesBrokerMutationCR045(t *testing.T) {
	ctx := t.Context()
	refused := errors.New("candidate wire stage refused")
	staged := 0
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithAppendAdmission(func(admitted context.Context, _ Event,
			publish func(context.Context) (Event, error),
		) (Event, error) {
			return publish(admitted)
		}),
		WithIngressWireStage(func(_ context.Context, event Event, wireHash string) error {
			staged++
			if event.ID == "" || event.Time.IsZero() || event.SchemaVersion == 0 {
				t.Fatal("wire stage received an unnormalized event")
			}
			stored, err := storedForEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(stored)
			if err != nil || wireHash != crypto.SHA256Hex(wire) {
				t.Fatalf("wire stage did not receive the exact serialized event hash: err=%v", err)
			}
			return refused
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	for _, write := range []func(context.Context, Event) (Event, error){log.Append, log.Import} {
		_, err := write(ctx, Event{ID: "plain-wire-stage-event", Type: "tenant.registered",
			TenantID: "49900000-0000-4000-8000-0000000000c3", Time: time.Now().UTC(),
			Data: []byte(`{"label":"plain-wire"}`)})
		if !errors.Is(err, refused) {
			t.Fatalf("write crossed refused wire stage: %v", err)
		}
	}
	if staged != 2 {
		t.Fatalf("Append and Import wire stage calls=%d, want 2", staged)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 0 {
		t.Fatalf("refused wire reached JetStream: sequence=%d err=%v", head, err)
	}
}

func TestAppendAndImportShareNormalizedPrepublishAdmission(t *testing.T) {
	ctx := context.Background()
	refused := errors.New("admission refused")
	seen := 0
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")},
		WithAppendAdmission(func(_ context.Context, event Event, _ func(context.Context) (Event, error)) (Event, error) {
			seen++
			if event.ID == "" || event.Time.IsZero() || event.SchemaVersion == 0 || event.TenantID == "" {
				t.Fatal("admission received an event before envelope normalization")
			}
			return Event{}, refused
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	for _, write := range []func(context.Context, Event) (Event, error){log.Append, log.Import} {
		_, err := write(ctx, Event{ID: "admission-event", Time: time.Now().UTC(), Type: "admission.checked",
			TenantID: "11111111-1111-4111-8111-111111111111", Data: []byte(`{"value":1}`)})
		if !errors.Is(err, refused) {
			t.Fatalf("write without admission: %v", err)
		}
	}
	if seen != 2 {
		t.Fatalf("Append and Import admission calls = %d, want 2", seen)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("refused writes reached JetStream: head=%d err=%v", head, err)
	}
}

// CR-045: a production event source must never publish through an omitted or
// accidentally replaced ingress adapter, including the Import path.
func TestRequiredAppendAdmissionRefusesMissingAdapter(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	event := Event{ID: "required-admission", Time: time.Now().UTC(), Type: "admission.checked",
		TenantID: "11111111-1111-4111-8111-111111111111", Data: []byte(`{"value":1}`)}
	for _, write := range []func(context.Context, Event) (Event, error){log.Append, log.Import} {
		if _, err := write(ctx, event); !errors.Is(err, ErrAppendAdmissionUnavailable) {
			t.Fatalf("write without required adapter: %v", err)
		}
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("missing adapter reached JetStream: head=%d err=%v", head, err)
	}
}

func TestBareLogRequiresExplicitAppendAdmission(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{Type: "admission.checked",
		TenantID: "11111111-1111-4111-8111-111111111111", Data: []byte(`{"value":1}`)}); !errors.Is(err, ErrAppendAdmissionUnavailable) {
		t.Fatalf("bare log append=%v, want explicit admission refusal", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("bare log published without admission: head=%d err=%v", head, err)
	}
}

func TestExplicitFixtureCanAppendPublicButCannotSatisfyProductionRequirement(t *testing.T) {
	ctx := context.Background()
	log, err := openFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, Event{Type: "admission.checked",
		TenantID: "11111111-1111-4111-8111-111111111111", Data: []byte(`{"value":1}`)}); err != nil {
		t.Fatalf("explicit fixture public append: %v", err)
	}
	_ = log.Close()
	if required, err := openFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission()); !errors.Is(err, ErrAppendAdmissionUnavailable) {
		if required != nil {
			_ = required.Close()
		}
		t.Fatalf("fixture satisfied required production admission: %v", err)
	}
}

func TestExplicitFixtureRefusesSealedBearingAndUnknownSealedSchemas(t *testing.T) {
	ctx := context.Background()
	log, err := openFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	for _, candidate := range []Event{
		{Type: "secret.sync.queued", Data: []byte(`{"id":"fixture-job"}`)},
		{Type: "fixture.unknown", Data: []byte(`{"nested":{"sealed":"fixture-value"}}`)},
	} {
		candidate.TenantID = "11111111-1111-4111-8111-111111111111"
		if _, err := log.Append(ctx, candidate); !errors.Is(err, ErrFixtureSealedAdmissionRequired) {
			t.Fatalf("fixture accepted %s without sealed admission: %v", candidate.Type, err)
		}
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("refused fixture writes reached JetStream: head=%d err=%v", head, err)
	}
}

func TestUnprotectedSealedDuplicateRequiresExactSealedBytes(t *testing.T) {
	ctx := context.Background()
	const tenant = "11111111-1111-4111-8111-111111111111"
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Cleanup(func() {
		for index := range key {
			key[index] = 0
		}
	})
	aad := []byte(tenant + "|test-secret")
	sealData := func() []byte {
		t.Helper()
		sealed, err := crypto.AESGCMSeal(key, []byte("fixture value"), aad)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(struct {
			Sealed []byte `json:"sealed"`
		}{Sealed: sealed})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission(),
		WithAppendAdmission(func(admitted context.Context, event Event,
			publish func(context.Context) (Event, error),
		) (Event, error) {
			if event.Type == "secret.version.written" {
				var payload struct {
					Sealed []byte `json:"sealed"`
				}
				if err := json.Unmarshal(event.Data, &payload); err != nil {
					return Event{}, err
				}
				opened, err := crypto.AESGCMOpen(key, payload.Sealed, aad)
				if err != nil {
					return Event{}, err
				}
				for index := range opened {
					opened[index] = 0
				}
			}
			return publish(admitted)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	base := Event{ID: "sealed-duplicate", Time: time.Now().UTC(), Type: "secret.version.written",
		TenantID: tenant, Data: sealData()}
	canonical, err := log.Append(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, write := range []func(context.Context, Event) (Event, error){log.Append, log.Import} {
		changed := base
		changed.Data = sealData() // Same plaintext, distinct authenticated wrapper.
		if _, err := write(ctx, changed); !errors.Is(err, ErrConflictingEventIdentity) {
			t.Fatalf("changed sealed duplicate accepted: %v", err)
		}
	}
	if got, err := log.Import(ctx, base); err != nil || got.Sequence != canonical.Sequence {
		t.Fatalf("exact sealed duplicate: event=%+v err=%v", got, err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != canonical.Sequence {
		t.Fatalf("sealed duplicate changed history head: %d, %v", head, err)
	}
	public := Event{ID: "public-duplicate", Time: time.Now().UTC(), Type: "admission.checked",
		TenantID: tenant, Data: []byte(`{"value":1}`)}
	first, err := log.Append(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	public.Data = []byte(`{"value":2}`)
	got, err := log.Import(ctx, public)
	if err != nil || got.Sequence != first.Sequence || string(got.Data) != `{"value":1}` {
		t.Fatalf("public duplicate lost existing canonical contract: event=%+v err=%v", got, err)
	}
}

func TestAppendAdmissionPublicationCallbackIsOneUseAndExpires(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"append", "import"} {
		t.Run(mode, func(t *testing.T) {
			var delayed func(context.Context) (Event, error)
			log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
				WithRequiredAppendAdmission(),
				WithAppendAdmission(func(admitted context.Context, event Event,
					publish func(context.Context) (Event, error),
				) (Event, error) {
					delayed = publish
					if event.ID == "refused-late" {
						return Event{}, errors.New("admission refused before publication")
					}
					first, err := publish(admitted)
					if err != nil {
						return Event{}, err
					}
					if _, err := publish(admitted); !errors.Is(err, ErrAppendAdmissionUnavailable) {
						t.Fatalf("same admission published twice: %v", err)
					}
					return first, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			write := log.Append
			if mode == "import" {
				write = log.Import
			}
			at := time.Now().UTC()
			if _, err := write(ctx, Event{ID: "published-once", Time: at,
				Type: "admission.checked", TenantID: "11111111-1111-4111-8111-111111111111"}); err != nil {
				t.Fatal(err)
			}
			if _, err := write(ctx, Event{ID: "refused-late", Time: at,
				Type: "admission.checked", TenantID: "11111111-1111-4111-8111-111111111111"}); err == nil {
				t.Fatal("refused admission unexpectedly succeeded")
			}
			if _, err := delayed(ctx); !errors.Is(err, ErrAppendAdmissionUnavailable) {
				t.Fatalf("expired admission callback published later: %v", err)
			}
			head, err := log.LastSequence(ctx)
			if err != nil || head != 1 {
				t.Fatalf("expired callback changed broker head: %d, %v", head, err)
			}
		})
	}
}

func TestAppendAdmissionCallbackExpiresAfterRefusal(t *testing.T) {
	ctx := context.Background()
	var delayed func(context.Context) (Event, error)
	refused := errors.New("admission refused before publication")
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission(),
		WithAppendAdmission(func(_ context.Context, _ Event, publish func(context.Context) (Event, error)) (Event, error) {
			delayed = publish
			return Event{}, refused
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{Type: "admission.checked",
		TenantID: "11111111-1111-4111-8111-111111111111"}); !errors.Is(err, refused) {
		t.Fatalf("refused append: %v", err)
	}
	if _, err := delayed(ctx); !errors.Is(err, ErrAppendAdmissionUnavailable) {
		t.Fatalf("expired callback published after refusal: %v", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("expired callback changed broker head: %d, %v", head, err)
	}
}

func TestAppendAdmissionConcurrentLateCallbackRefusesWithoutBrokerWrite(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	late := make(chan error, 1)
	refused := errors.New("admission returned before publication")
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission(),
		WithAppendAdmission(func(admitted context.Context, _ Event, publish func(context.Context) (Event, error)) (Event, error) {
			go func() {
				<-release
				_, err := publish(admitted)
				late <- err
			}()
			return Event{}, refused
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{Type: "admission.checked",
		TenantID: "11111111-1111-4111-8111-111111111111"}); !errors.Is(err, refused) {
		t.Fatalf("refused append: %v", err)
	}
	close(release)
	select {
	case err := <-late:
		if !errors.Is(err, ErrAppendAdmissionUnavailable) {
			t.Fatalf("concurrent late callback published: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late admission callback did not finish")
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("concurrent late callback changed broker head: %d, %v", head, err)
	}
}

func TestBackupHistoryAdmissionCallbackExpiresAfterReturn(t *testing.T) {
	ctx := context.Background()
	for _, authorized := range []bool{false, true} {
		name := "raw"
		if authorized {
			name = "authorized"
		}
		t.Run(name, func(t *testing.T) {
			var delayed func(context.Context) (int, error)
			log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
				WithBackupHistoryAdmission(func(_ context.Context, _ uint64, _ string,
					run func(context.Context) (int, error),
				) (int, error) {
					delayed = run
					return 0, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			read := false
			source := func(func(BackupHistoryRecord) error) error { read = true; return nil }
			var restoreErr error
			if authorized {
				_, restoreErr = log.RestoreAuthorizedBackupHistory(ctx, 0, "fixture-digest", nil, source)
			} else {
				_, restoreErr = log.RestoreBackupHistory(ctx, 0, "fixture-digest", source)
			}
			if restoreErr != nil {
				t.Fatalf("admission did not return its planned result: %v", restoreErr)
			}
			if _, err := delayed(ctx); !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
				t.Fatalf("expired raw restore callback was still callable: %v", err)
			}
			if read {
				t.Fatal("expired raw restore callback reached its source")
			}
		})
	}
}

func TestProductionSourceRefusesLegacyPhysicalHistoryDeletion(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission(),
		WithHistoryRewriteCoordinator(&opaqueHistoryRewriteCoordinator{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if err := log.Delete(ctx, 1); !errors.Is(err, ErrLegacyHistoryMutationUnavailable) {
		t.Fatalf("production physical delete: %v", err)
	}
	called := false
	if err := log.PruneTenantThroughCheckpoint(ctx, "11111111-1111-4111-8111-111111111111", 1,
		func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrLegacyHistoryMutationUnavailable) {
		t.Fatalf("production physical checkpoint prune: %v", err)
	}
	if called {
		t.Fatal("production physical prune called its checkpoint callback")
	}
}

// CR-045: lower-level publication must carry the normalized ingress grant.
func TestPreparedPublicationRefusesMissingIngressGrant(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredAppendAdmission())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	event := Event{ID: "direct-publication", Time: time.Now().UTC(), Type: "admission.checked",
		TenantID: "11111111-1111-4111-8111-111111111111", SchemaVersion: DefaultSchemaVersion,
		Data: []byte(`{"value":1}`)}
	if _, err := log.publishPreparedEvent(ctx, event); !errors.Is(err, ErrAppendAdmissionUnavailable) {
		t.Fatalf("unguarded prepared publish: %v", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("unguarded publish reached JetStream: head=%d err=%v", head, err)
	}
}

// CR-045: the raw history writer crosses the same production source boundary
// as Append/Import, including when an authenticated grant was supplied.
func TestRequiredBackupHistoryAdmissionRefusesMissingAdapter(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredBackupHistoryAdmission())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	called := false
	source := func(func(BackupHistoryRecord) error) error {
		called = true
		return nil
	}
	if _, err := log.RestoreBackupHistory(ctx, 0, "fixture-digest", source); !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
		t.Fatalf("raw restore without adapter: %v", err)
	}
	if _, err := log.RestoreAuthorizedBackupHistory(ctx, 0, "fixture-digest", nil, source); !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
		t.Fatalf("authorized raw restore without adapter: %v", err)
	}
	if called {
		t.Fatal("missing raw restore adapter read source")
	}
}

func TestRequiredRawHistoryLowLevelRefusesUnboundOwnerCR045(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithRequiredBackupHistoryAdmission(),
		WithBackupHistoryAdmission(func(ctx context.Context, _ uint64, _ string,
			run func(context.Context) (int, error),
		) (int, error) {
			return run(ctx)
		}),
		WithBackupHistoryJournal(func(ctx context.Context, _ uint64, _, _ string,
			_ BackupHistoryRecord, run func(context.Context) error,
		) error {
			return run(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	source := func(func(BackupHistoryRecord) error) error { return nil }
	if _, err := log.restoreBackupHistoryAdmitted(ctx, 0, strings.Repeat("a", 64), source, true); !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
		t.Fatalf("direct raw writer bypassed the live owner lease: %v", err)
	}
	name, stream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.clearBackupRestoreIdentity(ctx, name, stream, strings.Repeat("a", 64), 0); !errors.Is(err, ErrBackupHistoryAdmissionUnavailable) {
		t.Fatalf("direct stream-unbinding path bypassed the live owner lease: %v", err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != 0 {
		t.Fatalf("unowned raw writer changed broker head: %d, %v", head, err)
	}
}
