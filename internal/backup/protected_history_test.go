// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

const protectedBackupFixtureType = "backup.protected_source_fixture"

type protectedBackupPayload struct {
	Email string `json:"email"`
}

func init() {
	if err := events.RegisterPrivacyEventPolicy(protectedBackupFixtureType, 1, events.PrivacyEventPolicy{
		Rules:        []events.PrivacyFieldRule{{Path: "/email", Mode: events.PrivacyFieldIdentityExact}},
		PayloadShape: events.PrivacyPayloadShapeOf[protectedBackupPayload](),
	}); err != nil {
		panic(err)
	}
}

type protectedBackupKeys struct {
	key    seal.KeyWrapper
	ref    eventprotect.KeyRef
	calls  int
	closed bool
}

func (f *protectedBackupKeys) WithTenantEventProtection(ctx context.Context, _ string, visit func(context.Context) error) error {
	return visit(ctx)
}
func (f *protectedBackupKeys) EventProtectionFor(_ context.Context, event events.Event) (events.EventProtectionDecision, error) {
	if event.Type == protectedBackupFixtureType {
		return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: f.ref}, nil
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
}
func (f *protectedBackupKeys) WithKey(_ context.Context, ref eventprotect.KeyRef, visit func(seal.KeyWrapper) error) error {
	f.calls++
	if f.closed || ref != f.ref {
		return eventprotect.ErrKey
	}
	return visit(f.key)
}

// Real NATS and AEAD; admission and memory-only custody are explicit codec
// fixtures. This does not qualify production offboarding or persistent removal.
func protectedHistoryFixture(t testing.TB) (*events.Log, *protectedBackupKeys, []events.BackupHistoryRecord) {
	t.Helper()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	key, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	f := &protectedBackupKeys{key: key, ref: eventprotect.KeyRef{TenantID: "60aad68e-4613-4658-a75a-10ee97084edf", ID: "06bc0318-6b02-471c-b3c4-54257995848a"}}
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithEventProtection(events.EventProtection{Admission: f, Keys: f}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(t.Context(), events.Event{Type: protectedBackupFixtureType, TenantID: f.ref.TenantID, Data: []byte(`{"email":"protected-backup@example.invalid"}`), Actor: &events.Actor{Subject: "private-backup-actor@example.invalid"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: "neighbor.created", TenantID: "c35cd6e9-8580-42bc-8123-ff65267f526f", Data: []byte(`{"name":"neighbor"}`)}); err != nil {
		t.Fatal(err)
	}
	var history []events.BackupHistoryRecord
	if err := log.ExportBackupHistoryThrough(t.Context(), 2, func(record events.BackupHistoryRecord) error { history = append(history, record); return nil }); err != nil {
		t.Fatal(err)
	}
	if history[0].Event.Protection == nil || history[0].Event.SchemaVersion != 1 || f.calls != 1 {
		t.Fatal("fixture did not store one actual protected source event")
	}
	key.Destroy()
	f.closed = true
	return log, f, history
}

func TestProtectedEventBackupRetainsExactSourceWithoutKeyAccess(t *testing.T) {
	log, keys, source := protectedHistoryFixture(t)
	integrity := []byte("owned backup integrity fixture")
	var artifact bytes.Buffer
	count, err := WriteLogWithKey(t.Context(), log, &artifact, integrity)
	if err != nil || count != 2 {
		t.Fatalf("protected source export: count=%d err=%v", count, err)
	}
	if keys.calls != 1 || bytes.Contains(artifact.Bytes(), []byte("@example.invalid")) {
		t.Fatal("export opened private source details")
	}
	var h header
	if err := json.Unmarshal(bytes.Split(artifact.Bytes(), []byte{'\n'})[0], &h); err != nil || h.Version != 3 {
		t.Fatalf("protected source did not declare a reader-safe version: %+v %v", h, err)
	}
	summary, err := VerifyEventLogBackupWithKey(bytes.NewReader(artifact.Bytes()), integrity)
	if err != nil || summary.Records != 2 || summary.EventCutSequence != 2 || !summary.ExactSequenceLayout || summary.HasGaps {
		t.Fatalf("protected artifact verification: %+v %v", summary, err)
	}
	authorizer, err := crypto.NewBackupRestoreAuthorizer(integrity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	target, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithBackupRestoreAuthorizer(authorizer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	if count, err := RestoreLogWithKey(t.Context(), target, bytes.NewReader(artifact.Bytes()), integrity); err != nil || count != 2 {
		t.Fatalf("protected source restore: %d %v", count, err)
	}
	i := 0
	if err := target.ExportBackupHistoryThrough(t.Context(), 2, func(got events.BackupHistoryRecord) error {
		if i >= len(source) || !reflect.DeepEqual(got, source[i]) {
			return errors.New("restored source bytes, schema, protection or transport identity changed")
		}
		i++
		return nil
	}); err != nil || i != 2 {
		t.Fatalf("exact restored ciphertext: %d %v", i, err)
	}
	if keys.calls != 1 {
		t.Fatal("verification or restore reached original custody")
	}
}

func TestProtectedEventBackupRejectsAuthenticatedMirrorMismatch(t *testing.T) {
	log, keys, _ := protectedHistoryFixture(t)
	integrity := []byte("owned backup integrity fixture")
	var original bytes.Buffer
	if _, err := WriteLogWithKey(t.Context(), log, &original, integrity); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"data", "actor", "schema", "missing-protection", "key", "stored", "old-version"} {
		t.Run(name, func(t *testing.T) {
			lines := bytes.Split(bytes.TrimSpace(original.Bytes()), []byte{'\n'})
			var output bytes.Buffer
			digest := newDigest(integrity)
			for index, line := range lines[:len(lines)-1] {
				var value map[string]json.RawMessage
				if err := json.Unmarshal(line, &value); err != nil {
					t.Fatal(err)
				}
				if index == 0 && name == "old-version" {
					value["version"] = json.RawMessage(`2`)
				}
				if index == 1 {
					switch name {
					case "data":
						value["data"] = json.RawMessage(`{"injected":true}`)
					case "actor":
						value["actor"] = json.RawMessage(`{"subject":"injected"}`)
					case "schema":
						value["v"] = json.RawMessage(`2`)
					case "missing-protection":
						delete(value, "protection")
					case "key":
						var envelope map[string]json.RawMessage
						if err := json.Unmarshal(value["protection"], &envelope); err != nil {
							t.Fatal(err)
						}
						envelope["key_id"] = json.RawMessage(`"38b727d5-dc46-4ac1-9070-b5f7b494d98e"`)
						value["protection"], _ = json.Marshal(envelope)
					case "stored":
						var stored []byte
						if err := json.Unmarshal(value["stored"], &stored); err != nil {
							t.Fatal(err)
						}
						value["stored"], _ = json.Marshal(append([]byte(" "), stored...))
					}
				}
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				feed(digest, encoded)
				output.Write(encoded)
				output.WriteByte('\n')
			}
			var tr trailer
			if err := json.Unmarshal(lines[len(lines)-1], &tr); err != nil {
				t.Fatal(err)
			}
			tr.SHA256, tr.HMACSHA256 = digest.sumHex(), digest.macHex()
			if err := json.NewEncoder(&output).Encode(tr); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyEventLogBackupWithKey(bytes.NewReader(output.Bytes()), integrity); err == nil {
				t.Fatal("authenticated protected mirror mismatch verified")
			}
			if keys.calls != 1 {
				t.Fatal("invalid artifact reached key custody")
			}
		})
	}
}
