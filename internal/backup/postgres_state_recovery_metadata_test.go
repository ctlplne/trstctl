// These tests qualify artifact framing, not current-custody or source authority.
// SPDX-License-Identifier: BUSL-1.1
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprotect"
)

type postgresRecoveryOpener struct {
	key    seal.KeyWrapper
	erased bool
	calls  int
	last   []byte
}

func (*postgresRecoveryOpener) ProtectPostgresRow(context.Context, eventprotect.Context, json.RawMessage) (eventprotect.Envelope, bool, error) {
	panic("read-only framing fixture")
}
func (o *postgresRecoveryOpener) OpenPostgresRow(_ context.Context, c eventprotect.Context, e eventprotect.Envelope) (json.RawMessage, bool, error) {
	o.calls++
	if o.erased {
		return nil, true, nil
	}
	p, err := eventprotect.Open(o.key, c, postgresRowPolicyDigest(), e)
	o.last = p.Data
	return p.Data, false, err
}

func TestProtectedPostgresSignerClaimRetainsOnlyClosedDenialTombstone(t *testing.T) {
	f := newProtectedPostgresStreamFixture(t)
	frame := protectedPostgresRecord{Table: "ca_signer_handle_claims", Ordinal: 1, TenantID: f.row.TenantID, StorageTenantID: "00000000-0000-0000-0000-000000000003"}
	raw := json.RawMessage(`{"tenant_id":"00000000-0000-0000-0000-000000000003","handle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","owner_tenant_id":"d59b4292-1adc-4d43-a405-781f95b1779c","owner_ceremony_id":"3d5183a5-7708-4ba4-8e9b-039c542110a9","state":"claimed","created_at":"2026-10-31T00:00:00Z","preparation_event_actor":{"subject":"private-claim@example.invalid"},"preparation_event_payload":{"name":"private issuer"}}`)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	var err error
	frame.ErasureRow, err = postgresSignerDenialRow(fields)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := postgresRowContext(f.artifact, frame)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := eventprotect.Protect(f.opener.key, binding, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", postgresRowPolicyDigest(), eventprotect.Payload{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	frame.Protection = &envelope
	opener := &postgresRecoveryOpener{key: f.opener.key}
	opened, erased, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, frame, opener)
	if err != nil || erased || !bytes.Equal(opened, raw) {
		t.Fatalf("active claim changed: erased=%v err=%v", erased, err)
	}
	opener.erased = true
	tombstone, erased, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, frame, opener)
	if err != nil || !erased || !bytes.Equal(tombstone, frame.ErasureRow) {
		t.Fatalf("verified erased claim lost its denial: erased=%v err=%v", erased, err)
	}
	if bytes.Contains(tombstone, []byte("private")) || bytes.Contains(tombstone, []byte(frame.TenantID)) {
		t.Fatal("erasure tombstone retained owner details")
	}
	var got struct {
		State string  `json:"state"`
		Hash  string  `json:"handle_sha256"`
		Owner *string `json:"owner_tenant_id"`
	}
	if err := json.Unmarshal(tombstone, &got); err != nil || got.State != "retired" || got.Hash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || got.Owner != nil {
		t.Fatal("erasure tombstone cannot preserve the retired handle denial")
	}
	// A valid-looking replacement from another handle still changes the AEAD.
	changed := frame
	changed.ErasureRow = bytes.Replace(frame.ErasureRow, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 1)
	opener.erased = false
	if _, _, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, changed, opener); err == nil {
		t.Fatal("different handle tombstone opened original private claim")
	}
	// Unknown public fields must fail before any key callback, even if signed by
	// a stream-level fixture: a closed denial row cannot carry readable details.
	changed = frame
	var public map[string]any
	if err := json.Unmarshal(frame.ErasureRow, &public); err != nil {
		t.Fatal(err)
	}
	public["subject"] = "injected@example.invalid"
	changed.ErasureRow, err = json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	before := opener.calls
	if _, _, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, changed, opener); err == nil || opener.calls != before {
		t.Fatal("public denial metadata admitted private fields")
	}
}

func TestProtectedPostgresOpenedOwnerMismatchIsRejectedAndWiped(t *testing.T) {
	f := newProtectedPostgresStreamFixture(t)
	frame := f.row
	binding, err := postgresRowContext(f.artifact, frame)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"tenant_id":"fe04b949-2c14-4c68-9f14-91a365cb44e6","subject":"foreign-owner@example.invalid"}`)
	envelope, err := eventprotect.Protect(f.opener.key, binding, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", postgresRowPolicyDigest(), eventprotect.Payload{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	frame.Protection = &envelope
	opener := &postgresRecoveryOpener{key: f.opener.key}
	if _, _, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, frame, opener); err == nil {
		t.Fatal("authenticated ciphertext with a foreign SQL owner was accepted")
	}
	if opener.calls != 1 || len(opener.last) == 0 {
		t.Fatal("fixture did not exercise decrypted owner validation")
	}
	for _, b := range opener.last {
		if b != 0 {
			t.Fatal("rejected decrypted row bytes were not wiped")
		}
	}
}

func TestProtectedPostgresCheckpointMetadataPreservesPublicSourceBoundary(t *testing.T) {
	f := newProtectedPostgresStreamFixture(t)
	frame := protectedPostgresRecord{Table: "audit_checkpoints", Ordinal: 1, TenantID: f.row.TenantID, Checkpoint: &AuditCheckpointBoundary{TenantID: f.row.TenantID, BoundarySeq: 5, RecordCount: 3}}
	row, err := json.Marshal(map[string]any{"tenant_id": f.row.TenantID, "scope_id": f.row.TenantID, "boundary_seq": 5, "record_count": 3, "boundary_hash": "hash", "archive_uri": "private/archive/reference", "created_at": time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := postgresRowContext(f.artifact, frame)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := eventprotect.Protect(f.opener.key, binding, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", postgresRowPolicyDigest(), eventprotect.Payload{Data: row})
	if err != nil {
		t.Fatal(err)
	}
	frame.Protection = &envelope
	opener := &postgresRecoveryOpener{key: f.opener.key}
	opened, erased, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, frame, opener)
	if err != nil || erased || !bytes.Equal(opened, row) {
		t.Fatalf("exact checkpoint refused: %v", err)
	}
	altered := frame
	boundary := *frame.Checkpoint
	boundary.RecordCount++
	altered.Checkpoint = &boundary
	if _, _, err := openAuthenticatedPostgresRecord(t.Context(), f.artifact, altered, opener); err == nil {
		t.Fatal("changed public checkpoint opened original private archive row")
	}
	opener.erased = true
	opened, erased, err = openAuthenticatedPostgresRecord(t.Context(), f.artifact, frame, opener)
	if err != nil || !erased || len(opened) != 0 {
		t.Fatal("erased checkpoint exposed archive data")
	}
	// The immutable public boundary remains usable for the artifact-pair proof.
	if frame.Checkpoint.RecordCount != 3 || frame.Checkpoint.BoundarySeq != 5 {
		t.Fatal("erasure changed source-continuity evidence")
	}
}

func TestProtectedPostgresPreservesFixedProviderRecoveryAuthority(t *testing.T) {
	fixture := newProtectedPostgresStreamFixture(t)
	header := postgresStateHeader{ArtifactID: fixture.artifact.ID, Version: protectedPostgresStateVersion, CreatedAt: fixture.artifact.CreatedAt, EventCutSequence: fixture.artifact.EventCutSequence}
	for _, table := range []string{"provider_authority_projection_state", "provider_authority_projection_receipts", "provider_tenant_templates"} {
		t.Run(table, func(t *testing.T) {
			// These are fixed Provider-owned authority rows, not a customer's
			// read model. The read-only provider panics if used to seal one.
			var output bytes.Buffer
			fields := map[string]any{"tenant_id": "00000000-0000-0000-0000-000000000000"}
			switch table {
			case "provider_authority_projection_state":
				fields["needs_rebuild"] = true
			case "provider_authority_projection_receipts":
				fields["event_sequence"], fields["event_id"], fields["event_digest"] = 1, "authority-event", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "provider_tenant_templates":
				fields["template_id"], fields["version"], fields["name"] = "baseline", 1, "Provider baseline"
				fields["baseline"], fields["digest"], fields["recorded_by"], fields["recorded_at"] = map[string]any{}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "provider-operator", fixture.artifact.CreatedAt
			}
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(raw) // the internal encoder consumes and wipes raw
			if err := encodePostgresStateRow(t.Context(), json.NewEncoder(&output), header, table, 1, raw, fixture.opener); err != nil {
				t.Fatal(err)
			}
			var frame protectedPostgresRecord
			if err := json.Unmarshal(output.Bytes(), &frame); err != nil || frame.Protection != nil || frame.TenantID != "" || !bytes.Equal(frame.Row, want) {
				t.Fatal("fixed recovery authority was assigned to a customer key or changed")
			}
			for _, b := range raw {
				if b != 0 {
					t.Fatal("consumed SQL row buffer was not wiped")
				}
			}
		})
	}
	var output bytes.Buffer
	if err := encodePostgresStateRow(t.Context(), json.NewEncoder(&output), header, "api_tokens", 1, json.RawMessage(`{"tenant_id":"00000000-0000-0000-0000-000000000000","subject":"unclassified"}`), fixture.opener); err == nil {
		t.Fatal("unclassified zero-tenant data gained a global plaintext exception")
	}
}
