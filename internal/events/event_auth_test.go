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

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/eventauth"
)

func TestC0012ForgedBrokerEnvelopeNeverReachesReplay(t *testing.T) {
	server, err := natsserver.NewServer(&natsserver.Options{
		JetStream: true, StoreDir: t.TempDir(), Port: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	if !server.ReadyForConnections(10 * time.Second) {
		t.Fatal("event broker did not start")
	}
	t.Cleanup(server.Shutdown)
	keyPath := filepath.Join(t.TempDir(), "event-auth.key")
	if err := eventauth.Provision(keyPath); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	cfg := config.NATS{
		Mode: config.NATSExternal, URL: server.ClientURL(), Replicas: 1,
		AllowSingleReplica: true, AllowPlaintextDev: true, EventAuthKeyFile: keyPath,
	}
	log, err := openFixture(ctx, cfg, WithBackgroundEventIDIndexer())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, Event{ID: "legit-event", Type: "owner.created", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	peer, err := OpenExternalSource(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	indexedDeadline := time.Now().Add(10 * time.Second)
	for {
		var peerEvents []Event
		err := peer.Replay(ctx, 1, func(event Event) error {
			peerEvents = append(peerEvents, event)
			return nil
		})
		if err == nil && len(peerEvents) == 1 && peerEvents[0].ID == "legit-event" {
			break
		}
		if time.Now().After(indexedDeadline) {
			t.Fatalf("signed federation source was not indexed within 10s: events=%d err=%v", len(peerEvents), err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	forged, err := json.Marshal(storedEvent{
		ID: "forged-token", Type: "api_token.created", TenantID: "tenant-a",
		Time: time.Now().UTC(), Data: []byte(`{"scopes":["*"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, "events.tenant-a.api_token.created", forged, jetstream.WithMsgID("forged-token")); err != nil {
		t.Fatal(err)
	}
	peerSeen := 0
	if err := peer.Replay(ctx, 1, func(Event) error { peerSeen++; return nil }); !errors.Is(err, ErrEventAuthentication) || peerSeen != 1 {
		t.Fatalf("federation read accepted %d events before error %v; want signed original only", peerSeen, err)
	}
	seen := 0
	err = log.Replay(ctx, 1, func(Event) error { seen++; return nil })
	if !errors.Is(err, ErrEventAuthentication) || seen != 1 {
		t.Fatalf("forged event replay = %d accepted, error %v; want one legitimate event then authentication refusal", seen, err)
	}
	if _, found, err := log.EventAtSequence(ctx, 2); found || !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("forged event sequence lookup found=%t err=%v", found, err)
	}
	legitimateRaw, err := log.stream.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.validateBackupLiveRecord(BackupHistoryRecord{
		Sequence: 1, Subject: legitimateRaw.Subject, MessageID: "legit-event", Stored: legitimateRaw.Data,
	}); err != nil {
		t.Fatalf("authenticated backup record rejected: %v", err)
	}
	forgedRaw, err := log.stream.GetMsg(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.validateBackupLiveRecord(BackupHistoryRecord{
		Sequence: 2, Subject: forgedRaw.Subject, MessageID: "forged-token", Stored: forgedRaw.Data,
	}); !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("unauthenticated backup record accepted: %v", err)
	}
	if err := log.ExportBackupHistoryThrough(ctx, 2, func(BackupHistoryRecord) error { return nil }); !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("backup export of forged event accepted: %v", err)
	}
	var altered storedEvent
	if err := json.Unmarshal(legitimateRaw.Data, &altered); err != nil {
		t.Fatal(err)
	}
	altered.ID, altered.Data = "modified-signed-event", []byte(`{"scopes":["*"]}`)
	tampered, err := json.Marshal(altered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, "events.tenant-a.owner.created", tampered, jetstream.WithMsgID("modified-signed-event")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventAtSequence(ctx, 3); found || !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("tampered signed event sequence lookup found=%t err=%v", found, err)
	}
	if _, err := log.js.Publish(ctx, "events.tenant-a.owner.created", legitimateRaw.Data,
		jetstream.WithMsgID("replayed-signed-event")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventAtSequence(ctx, 4); found || !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("replayed signed event at a new stream position found=%t err=%v", found, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if restarted, err := openFixture(ctx, cfg); err == nil {
		_ = restarted.Close()
		t.Fatal("cold event-log restart accepted unauthenticated retained history")
	}
}

func TestC0012AuthenticatedBackupRestoresAndRejectsTampering(t *testing.T) {
	ctx := t.Context()
	keyPath := filepath.Join(t.TempDir(), "event-auth.key")
	if err := eventauth.Provision(keyPath); err != nil {
		t.Fatal(err)
	}
	open := func() *Log {
		t.Helper()
		log, err := openFixture(ctx, config.NATS{
			Mode: config.NATSEmbedded, StoreDir: t.TempDir(), EventAuthKeyFile: keyPath,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = log.Close() })
		return log
	}
	source := open()
	if _, err := source.Append(ctx, Event{ID: "signed-backup", Type: "owner.created", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	var records []BackupHistoryRecord
	if err := source.ExportBackupHistoryThrough(ctx, 1, func(record BackupHistoryRecord) error {
		records = append(records, record)
		return nil
	}); err != nil || len(records) != 1 {
		t.Fatalf("signed backup export records=%d err=%v", len(records), err)
	}
	target := open()
	if _, err := target.RestoreBackupHistory(ctx, 1, strings.Repeat("a", 64), func(yield func(BackupHistoryRecord) error) error {
		return yield(records[0])
	}); err != nil {
		t.Fatalf("authenticated backup restore: %v", err)
	}
	if event, found, err := target.EventAtSequence(ctx, 1); err != nil || !found || event.ID != "signed-backup" {
		t.Fatalf("restored event found=%t id=%q err=%v", found, event.ID, err)
	}
	forged := records[0]
	forged.Stored = append([]byte(nil), forged.Stored...)
	forged.Stored = bytes.Replace(forged.Stored, []byte("signed-backup"), []byte("forged-backup"), 1)
	forged.MessageID = "forged-backup"
	failedTarget := open()
	if _, err := failedTarget.RestoreBackupHistory(ctx, 1, strings.Repeat("b", 64), func(yield func(BackupHistoryRecord) error) error {
		return yield(forged)
	}); !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("tampered backup restore = %v, want authentication refusal", err)
	}
}

func TestC0012ValidEnvelopeCannotBeReplayedAtNewSequence(t *testing.T) {
	ctx := t.Context()
	keyPath := filepath.Join(t.TempDir(), "event-auth.key")
	if err := eventauth.Provision(keyPath); err != nil {
		t.Fatal(err)
	}
	log, err := openFixture(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), EventAuthKeyFile: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, Event{ID: "original", Type: "owner.created", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	raw, err := log.stream.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, raw.Subject, raw.Data, jetstream.WithMsgID("replayed-copy")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventAtSequence(ctx, 2); found || !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("replayed event sequence lookup found=%t err=%v", found, err)
	}
	seen := 0
	if err := log.Replay(ctx, 1, func(Event) error { seen++; return nil }); !errors.Is(err, ErrEventAuthentication) || seen != 1 {
		t.Fatalf("replayed event callback count=%d err=%v", seen, err)
	}
	tailCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err = log.TailFrom(tailCtx, func(context.Context) (uint64, error) { return 1, nil },
		func(Event) error { t.Fatal("tail delivered a replayed signed envelope"); return nil })
	if !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("projector tail accepted replayed signed envelope: %v", err)
	}
	state, err := log.schedulerSafetySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	epoch := log.eventIDIndexEpoch(state)
	forgedIndex, err := json.Marshal(eventIDIndexEntry{Sequence: 2, Digest: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, eventIDKeySubject(epoch, "original"), forgedIndex); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventAtSequence(ctx, 2); found || !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("forged first-ID index mapping found=%t err=%v", found, err)
	}
	forgedCursor, err := json.Marshal(eventIDIndexCursor{Through: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(ctx, eventIDCursorSubject(epoch), forgedCursor); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventAtSequence(ctx, 2); found || !errors.Is(err, ErrEventAuthentication) {
		t.Fatalf("forged first-ID cursor found=%t err=%v", found, err)
	}
}

func TestC0012UnsignedHistoryFailsClosedWhenAuthenticationIsEnabled(t *testing.T) {
	ctx := t.Context()
	storeDir := t.TempDir()
	legacy, err := openFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Append(ctx, Event{ID: "legacy", Type: "owner.created", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "event-auth.key")
	if err := eventauth.Provision(keyPath); err != nil {
		t.Fatal(err)
	}
	if upgraded, err := openFixture(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: storeDir, EventAuthKeyFile: keyPath,
	}); err == nil || !errors.Is(err, ErrEventAuthentication) {
		if upgraded != nil {
			_ = upgraded.Close()
		}
		t.Fatalf("unsigned retained history was accepted after event authentication was enabled: %v", err)
	}
	reopened, err := openFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir})
	if err != nil {
		t.Fatalf("authentication refusal changed the original event stream: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if event, found, err := reopened.EventAtSequence(ctx, 1); err != nil || !found || event.ID != "legacy" {
		t.Fatalf("legacy source was not preserved: found=%t event=%+v err=%v", found, event, err)
	}
}
