// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
)

// Chunks bound each custody hold without imposing a new total snapshot limit.
const snapshotProtectionChunkBytes = 8 << 20
const SnapshotProtectionPolicyDomain = "trstctl.read-model-snapshot-sensitive.v1"
const snapshotProtectionPayloadKey = "_trstctl_snapshot_protection"

var ErrSnapshotErased = errors.New("store: snapshot lifetime is erased; reconstruct from current source")

// SnapshotProtection belongs to one operation and its configured source. It
// grants no key creation/removal. Providers preserve exact chunk bytes and must
// independently verify current destruction before reporting erased.
type SnapshotProtection interface {
	ProtectSnapshotChunk(context.Context, eventprotect.Context, []byte) (eventprotect.Envelope, bool, error)
	OpenSnapshotChunk(context.Context, eventprotect.Context, eventprotect.Envelope) ([]byte, bool, error)
	RestorePlainSnapshot(context.Context, eventprotect.Context, []byte) (bool, error)
}

func snapshotProtectionArgument(providers []SnapshotProtection) (SnapshotProtection, error) {
	if len(providers) > 1 {
		return nil, errors.New("store: snapshot operation has multiple custody providers")
	}
	if len(providers) == 1 {
		return providers[0], nil
	}
	return nil, nil
}

type protectedSnapshotPayload struct {
	Metadata   snapshotSetMetadata    `json:"_trstctl_snapshot_set"`
	Tenants    []snapshotPublicTenant `json:"tenants"`
	Protection snapshotChunkSet       `json:"_trstctl_snapshot_protection"`
}
type snapshotPublicTenant struct {
	TenantID string `json:"tenant_id"`
}
type snapshotChunkSet struct {
	Version      int                     `json:"version"`
	PayloadBytes int                     `json:"payload_bytes"`
	Chunks       []eventprotect.Envelope `json:"chunks"`
}

func snapshotProtectionPolicyDigest() string {
	return crypto.SHA256Hex([]byte(SnapshotProtectionPolicyDomain))
}

func snapshotChunkCount(length int) int {
	if length <= 0 {
		return 0
	}
	return (length-1)/snapshotProtectionChunkBytes + 1
}

func snapshotChunkContext(tenant string, metadata snapshotSetMetadata, length, ordinal int) eventprotect.Context {
	basis, _ := json.Marshal(struct {
		Metadata   snapshotSetMetadata `json:"metadata"`
		Length     int                 `json:"payload_bytes"`
		Count      int                 `json:"chunk_count"`
		ChunkBytes int                 `json:"chunk_bytes"`
	}{metadata, length, snapshotChunkCount(length), snapshotProtectionChunkBytes})
	return eventprotect.Context{Scope: eventprotect.ScopeSnapshot,
		ID:   metadata.ID + ":" + strconv.FormatUint(metadata.CoveredSequence, 10) + ":" + strconv.Itoa(ordinal) + ":" + crypto.SHA256Hex(basis),
		Type: "read_model_snapshot", TenantID: tenant, SchemaVersion: SnapshotFormatVersion, Time: metadata.CapturedAt}
}

func protectSnapshotPayload(ctx context.Context, tenant string, metadata snapshotSetMetadata, raw []byte, provider SnapshotProtection) ([]byte, error) {
	if provider == nil {
		return raw, nil
	}
	if err := validateOpenedSnapshotPayload(tenant, metadata, raw); err != nil {
		return nil, err
	}
	frame := protectedSnapshotPayload{Metadata: metadata, Tenants: []snapshotPublicTenant{{TenantID: tenant}}, Protection: snapshotChunkSet{Version: 1, PayloadBytes: len(raw)}}
	for start, ordinal := 0, 1; start < len(raw); ordinal++ {
		end := min(len(raw), start+snapshotProtectionChunkBytes)
		binding := snapshotChunkContext(tenant, metadata, len(raw), ordinal)
		envelope, protected, err := provider.ProtectSnapshotChunk(ctx, binding, raw[start:end])
		if err != nil {
			return nil, err
		}
		if !protected {
			if start != 0 {
				return nil, errors.New("store: snapshot protection changed during capture")
			}
			return raw, nil
		}
		if err := eventprotect.ValidateEnvelope(binding, snapshotProtectionPolicyDigest(), envelope); err != nil {
			return nil, err
		}
		frame.Protection.Chunks = append(frame.Protection.Chunks, envelope)
		start = end
	}
	return json.Marshal(frame)
}

func openSnapshotPayload(ctx context.Context, tenant string, metadata snapshotSetMetadata, raw []byte, provider SnapshotProtection) ([]byte, error) {
	metadata.CapturedAt = metadata.CapturedAt.UTC()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return nil, errors.New("store: snapshot payload is not an object")
	}
	defer wipeSnapshotFields(root)
	if _, protected := root[snapshotProtectionPayloadKey]; !protected {
		if provider == nil {
			return bytes.Clone(raw), nil
		}
		if err := validateOpenedSnapshotPayload(tenant, metadata, raw); err != nil {
			return nil, err
		}
		erased, err := provider.RestorePlainSnapshot(ctx, snapshotChunkContext(tenant, metadata, len(raw), 1), raw)
		if err != nil {
			return nil, err
		}
		if erased {
			return nil, ErrSnapshotErased
		}
		return bytes.Clone(raw), nil
	}
	var frame protectedSnapshotPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return nil, fmt.Errorf("store: invalid protected snapshot frame: %w", err)
	}
	frame.Metadata.CapturedAt = frame.Metadata.CapturedAt.UTC()
	if decoder.Decode(new(any)) != io.EOF || frame.Metadata != metadata ||
		len(frame.Tenants) != 1 || frame.Tenants[0].TenantID != tenant ||
		frame.Protection.Version != 1 || frame.Protection.PayloadBytes <= 0 ||
		len(frame.Protection.Chunks) != snapshotChunkCount(frame.Protection.PayloadBytes) {
		return nil, errors.New("store: protected snapshot identity or chunk layout mismatch")
	}
	for index, envelope := range frame.Protection.Chunks {
		binding := snapshotChunkContext(tenant, metadata, frame.Protection.PayloadBytes, index+1)
		if err := eventprotect.ValidateEnvelope(binding, snapshotProtectionPolicyDigest(), envelope); err != nil {
			return nil, err
		}
	}
	if provider == nil {
		return nil, errors.New("store: protected snapshot requires current source custody")
	}
	// Never allocate from an unauthenticated claimed total. Retain bounded opened
	// chunks, validate their actual lengths, then allocate exactly their sum.
	var chunks [][]byte
	defer func() {
		for _, chunk := range chunks {
			secret.Wipe(chunk)
		}
	}()
	total := 0
	for index, envelope := range frame.Protection.Chunks {
		binding := snapshotChunkContext(tenant, metadata, frame.Protection.PayloadBytes, index+1)
		chunk, erased, err := provider.OpenSnapshotChunk(ctx, binding, envelope)
		if err != nil || erased {
			secret.Wipe(chunk)
			if err != nil {
				return nil, err
			}
			return nil, ErrSnapshotErased
		}
		want := min(snapshotProtectionChunkBytes, frame.Protection.PayloadBytes-total)
		if len(chunk) != want {
			secret.Wipe(chunk)
			return nil, errors.New("store: opened snapshot chunk length mismatch")
		}
		chunks = append(chunks, chunk)
		total += len(chunk)
	}
	opened := make([]byte, total)
	position := 0
	for _, chunk := range chunks {
		position += copy(opened[position:], chunk)
	}
	if err := validateOpenedSnapshotPayload(tenant, metadata, opened); err != nil {
		secret.Wipe(opened)
		return nil, err
	}
	return opened, nil
}

func wipeSnapshotFields(fields map[string]json.RawMessage) {
	for _, raw := range fields {
		secret.Wipe(raw)
	}
}

func validateOpenedSnapshotPayload(tenant string, metadata snapshotSetMetadata, raw []byte) error {
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return errors.New("store: opened snapshot is not an object")
	}
	defer wipeSnapshotFields(root)
	var saved snapshotSetMetadata
	if json.Unmarshal(root[snapshotSetPayloadKey], &saved) != nil {
		return errors.New("store: opened snapshot has invalid generation metadata")
	}
	saved.CapturedAt, metadata.CapturedAt = saved.CapturedAt.UTC(), metadata.CapturedAt.UTC()
	if saved != metadata || len(root) != len(snapshotTables)+1 {
		return errors.New("store: opened snapshot generation mismatch")
	}
	for _, table := range snapshotTables {
		var rows []snapshotPublicTenant
		if json.Unmarshal(root[table], &rows) != nil || rows == nil {
			return fmt.Errorf("store: opened snapshot table %s has no row array", table)
		}
		if table == "tenants" && len(rows) != 1 {
			return errors.New("store: opened snapshot has no unique registration")
		}
		if table == "tenants" {
			var registrations []struct {
				EventSeq uint64 `json:"event_seq"`
			}
			if json.Unmarshal(root[table], &registrations) != nil || registrations[0].EventSeq > metadata.CoveredSequence {
				return errors.New("store: snapshot registration exceeds its captured source cut")
			}
		}
		for _, row := range rows {
			if row.TenantID != tenant {
				return errors.New("store: opened snapshot contains a foreign tenant")
			}
		}
	}
	return nil
}
