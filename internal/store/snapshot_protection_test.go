// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
)

const snapshotProtectionFixtureTenant = "d59b4292-1adc-4d43-a405-781f95b1779c"

type snapshotProtectionFixture struct {
	key                  seal.KeyWrapper
	opens, seals, plains int
	erased               bool
}

func (p *snapshotProtectionFixture) ProtectSnapshotChunk(_ context.Context, binding eventprotect.Context, raw []byte) (eventprotect.Envelope, bool, error) {
	p.seals++
	envelope, err := eventprotect.Protect(p.key, binding, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", snapshotProtectionPolicyDigest(), eventprotect.Payload{Data: raw})
	return envelope, true, err
}
func (p *snapshotProtectionFixture) OpenSnapshotChunk(_ context.Context, binding eventprotect.Context, envelope eventprotect.Envelope) ([]byte, bool, error) {
	p.opens++
	if p.erased {
		return nil, true, nil
	}
	payload, err := eventprotect.Open(p.key, binding, snapshotProtectionPolicyDigest(), envelope)
	return payload.Data, false, err
}
func (p *snapshotProtectionFixture) RestorePlainSnapshot(context.Context, eventprotect.Context, []byte) (bool, error) {
	p.plains++
	return false, nil
}

// Component AEAD/framing only. This fixture does not prove source selection,
// persistent key destruction, PostgreSQL restoration or an operator workflow.
func newSnapshotProtectionFixture(t testing.TB, name string) (snapshotSetMetadata, []byte, *snapshotProtectionFixture) {
	t.Helper()
	material, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	key, err := seal.NewLocalKEK(material)
	secret.Wipe(material)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	metadata := snapshotSetMetadata{ID: "9c9ad802-f619-4aba-a84e-9044825dd337", CoveredSequence: 17, TenantCount: 2, TenantSetSHA256: crypto.SHA256Hex([]byte("snapshot-fixture-set")), CapturedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)}
	data := map[string]any{snapshotSetPayloadKey: metadata}
	for _, table := range snapshotTables {
		data[table] = []any{}
	}
	data["tenants"] = []any{map[string]any{"tenant_id": snapshotProtectionFixtureTenant, "name": "Private tenant"}}
	data["owners"] = []any{map[string]any{"tenant_id": snapshotProtectionFixtureTenant, "name": name, "email": "private-snapshot-owner@example.invalid"}}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return metadata, raw, &snapshotProtectionFixture{key: key}
}

func TestProtectedSnapshotPayloadExceedsSingleEventFrameWithoutChangingItsLimit(t *testing.T) {
	metadata, raw, provider := newSnapshotProtectionFixture(t, strings.Repeat("a", (32<<20)+17))
	defer secret.Wipe(raw)
	encoded, err := protectSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, raw, provider)
	if err != nil {
		t.Fatal(err)
	}
	if provider.seals < 2 || bytes.Contains(encoded, []byte("private-snapshot-owner@example.invalid")) {
		t.Fatal("large snapshot was not bounded ciphertext chunks")
	}
	opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, encoded, provider)
	if err != nil || !bytes.Equal(opened, raw) || provider.opens != provider.seals {
		t.Fatalf("large snapshot changed or bypassed opening: %v", err)
	}
	secret.Wipe(opened)
}

func TestProtectedSnapshotPayloadRejectsAmbiguityAndTransplants(t *testing.T) {
	metadata, raw, provider := newSnapshotProtectionFixture(t, "Private owner")
	defer secret.Wipe(raw)
	encoded, err := protectSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, raw, provider)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"readable-mirror": func(body map[string]any) { body["owners"] = []any{map[string]any{"email": "injected@example.invalid"}} },
		"missing-chunks":  func(body map[string]any) { body["_trstctl_snapshot_protection"].(map[string]any)["chunks"] = []any{} },
		"negative-length": func(body map[string]any) { body["_trstctl_snapshot_protection"].(map[string]any)["payload_bytes"] = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal(encoded, &body); err != nil {
				t.Fatal(err)
			}
			mutate(body)
			changed, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			before := provider.opens
			if opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, changed, provider); err == nil || len(opened) != 0 || provider.opens != before {
				t.Fatal("malformed public framing reached custody or returned plaintext")
			}
		})
	}
	for name, change := range map[string]func(*snapshotSetMetadata){
		"capture": func(meta *snapshotSetMetadata) { meta.ID = "ac017cc7-4b28-426e-8052-5485c9270921" },
		"cut":     func(meta *snapshotSetMetadata) { meta.CoveredSequence++ },
		"time":    func(meta *snapshotSetMetadata) { meta.CapturedAt = meta.CapturedAt.Add(time.Nanosecond) },
		"set":     func(meta *snapshotSetMetadata) { meta.TenantSetSHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := metadata
			change(&changed)
			if opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, changed, encoded, provider); err == nil || len(opened) != 0 {
				t.Fatal("snapshot accepted a foreign generation binding")
			}
		})
	}
	if opened, err := openSnapshotPayload(t.Context(), "fe04b949-2c14-4c68-9f14-91a365cb44e6", metadata, encoded, provider); err == nil || len(opened) != 0 {
		t.Fatal("snapshot accepted a foreign tenant")
	}
	if opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, encoded, nil); err == nil || len(opened) != 0 {
		t.Fatal("missing custody became plaintext")
	}
	provider.erased = true
	if opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, encoded, provider); !errors.Is(err, ErrSnapshotErased) || len(opened) != 0 {
		t.Fatal("verified erasure failed to require source reconstruction")
	}
}

func TestProtectedSnapshotCaptureRejectsRegistrationNewerThanCoveredCut(t *testing.T) {
	metadata, raw, provider := newSnapshotProtectionFixture(t, "Private owner")
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	body["tenants"].([]any)[0].(map[string]any)["event_seq"] = metadata.CoveredSequence + 1
	changed, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	before := provider.seals
	if encoded, err := protectSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, changed, provider); err == nil || len(encoded) != 0 || provider.seals != before {
		t.Fatal("a future SQL registration reached source-key selection")
	}
}

func TestProtectedSnapshotChunksBindOrderCountLengthAndRewrittenHeaders(t *testing.T) {
	metadata, raw, provider := newSnapshotProtectionFixture(t, strings.Repeat("x", snapshotProtectionChunkBytes+64))
	defer secret.Wipe(raw)
	encoded, err := protectSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, raw, provider)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*protectedSnapshotPayload){
		"reorder": func(frame *protectedSnapshotPayload) {
			frame.Protection.Chunks[0], frame.Protection.Chunks[1] = frame.Protection.Chunks[1], frame.Protection.Chunks[0]
		},
		"duplicate": func(frame *protectedSnapshotPayload) { frame.Protection.Chunks[1] = frame.Protection.Chunks[0] },
		"truncate":  func(frame *protectedSnapshotPayload) { frame.Protection.Chunks = frame.Protection.Chunks[:1] },
		"extra": func(frame *protectedSnapshotPayload) {
			frame.Protection.Chunks = append(frame.Protection.Chunks, frame.Protection.Chunks[0])
		},
		"length":  func(frame *protectedSnapshotPayload) { frame.Protection.PayloadBytes++ },
		"version": func(frame *protectedSnapshotPayload) { frame.Protection.Version++ },
	} {
		t.Run(name, func(t *testing.T) {
			var frame protectedSnapshotPayload
			if err := json.Unmarshal(encoded, &frame); err != nil {
				t.Fatal(err)
			}
			mutate(&frame)
			changed, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, changed, provider); err == nil || len(opened) != 0 {
				t.Fatal("altered chunk layout returned private snapshot bytes")
			}
		})
	}
	for name, mutate := range map[string]func(*snapshotSetMetadata){
		"capture": func(meta *snapshotSetMetadata) { meta.ID = "ac017cc7-4b28-426e-8052-5485c9270921" },
		"cut":     func(meta *snapshotSetMetadata) { meta.CoveredSequence++ },
		"time":    func(meta *snapshotSetMetadata) { meta.CapturedAt = meta.CapturedAt.Add(time.Microsecond) },
		"set":     func(meta *snapshotSetMetadata) { meta.TenantSetSHA256 = strings.Repeat("c", 64) },
	} {
		t.Run("rewritten-"+name, func(t *testing.T) {
			var frame protectedSnapshotPayload
			if err := json.Unmarshal(encoded, &frame); err != nil {
				t.Fatal(err)
			}
			mutate(&frame.Metadata)
			changed, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			before := provider.opens
			if opened, err := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, frame.Metadata, changed, provider); err == nil || len(opened) != 0 || provider.opens == before {
				t.Fatal("rewritten public header bypassed authenticated chunk binding")
			}
		})
	}
}
