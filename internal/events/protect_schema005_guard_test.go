// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// TestEnvelopeDecodeErrorCarriesStreamSequence pins the pre-callback failure
// contract used by the projection tail. A malformed stored envelope never becomes
// an Event, so the stream sequence must ride on the typed error or the tail cannot
// persist which global cursor position poisoned readiness.
func TestEnvelopeDecodeErrorCarriesStreamSequence(t *testing.T) {
	_, err := decodeStored([]byte(`{"unterminated"`), 37)
	if err == nil {
		t.Fatal("decodeStored malformed envelope returned nil")
	}
	var decodeErr *EnvelopeDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("decodeStored error type = %T, want *EnvelopeDecodeError: %v", err, err)
	}
	if decodeErr.Sequence != 37 {
		t.Fatalf("EnvelopeDecodeError.Sequence = %d, want 37", decodeErr.Sequence)
	}
	if decodeErr.Unwrap() == nil {
		t.Fatal("EnvelopeDecodeError lost the underlying JSON decoder error")
	}
}

func TestReplayPreservesEnvelopeDecodeErrorSequence(t *testing.T) {
	ctx := context.Background()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	ack, err := log.js.Publish(ctx, "events.owner.created", []byte(`{"unterminated"`))
	if err != nil {
		t.Fatal(err)
	}
	err = log.Replay(ctx, 0, func(Event) error {
		t.Fatal("malformed retained envelope reached replay callback")
		return nil
	})
	var decodeErr *EnvelopeDecodeError
	if !errors.As(err, &decodeErr) || decodeErr.Sequence != ack.Sequence {
		t.Fatalf("Replay error = %v, want EnvelopeDecodeError seq %d", err, ack.Sequence)
	}
}

// SCHEMA-005 (16-SCHEMA) PROTECT regression guard.
//
// Confirmed strength: event envelopes carry a payload SCHEMA VERSION, and a
// version-aware projector REJECTS a known event type that arrives at a schema version
// it does not understand (rather than silently decoding the wrong shape on replay).
// Anchors: internal/events/events.go (DefaultSchemaVersion, storedEvent.v stamp on
// Append, recovery on Replay/decode) and internal/projections/projections.go
// (ValidateSchemaVersion / ErrUnknownSchemaVersion reject path).
//
// The envelope half is a BEHAVIORAL test against the real (in-package) storedEvent
// JSON contract — no NATS, no Postgres, no network. The projector-reject half is an
// ANCHOR-LOCK over projections.go (events cannot import projections without a cycle,
// and exercising the reject path against a real projector would need Postgres), so it
// reads the source and asserts the reject machinery is intact.

func TestProtectSCHEMA005_DefaultSchemaVersionIsPositive(t *testing.T) {
	if DefaultSchemaVersion <= 0 {
		t.Fatalf("SCHEMA-005: DefaultSchemaVersion = %d, want > 0; every appended event must carry a positive baseline payload-shape version", DefaultSchemaVersion)
	}
	if DefaultSchemaVersion != 1 {
		t.Fatalf("SCHEMA-005: DefaultSchemaVersion = %d, want the documented baseline v1; a change here shifts how legacy/zero-version events are interpreted on replay", DefaultSchemaVersion)
	}
}

// TestProtectSCHEMA005_EnvelopeRoundTripsSchemaVersion locks the on-disk envelope
// contract: an explicit non-baseline version is stamped into the "v" field and reads
// back unchanged, while a baseline/legacy envelope that omits "v" reads back as
// DefaultSchemaVersion (never 0). This is the exact behavior the version-aware
// projector relies on to dispatch on (Type, SchemaVersion).
func TestProtectSCHEMA005_EnvelopeRoundTripsSchemaVersion(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)

	// (1) An evolved type at v2: the version must survive the JSON round-trip.
	v2 := storedEvent{ID: "e2", Type: "ca.crl.published", TenantID: "t1", Time: now, SchemaVersion: 2}
	raw, err := json.Marshal(v2)
	if err != nil {
		t.Fatalf("SCHEMA-005: marshal v2 envelope: %v", err)
	}
	if !strings.Contains(string(raw), `"v":2`) {
		t.Errorf("SCHEMA-005: a v2 envelope did not stamp its schema version into the wire form; got %s", raw)
	}
	got, err := decodeStored(raw, 7)
	if err != nil {
		t.Fatalf("SCHEMA-005: decode v2 envelope: %v", err)
	}
	if got.SchemaVersion != 2 {
		t.Errorf("SCHEMA-005: v2 envelope round-tripped to SchemaVersion=%d, want 2", got.SchemaVersion)
	}
	if got.Sequence != 7 {
		t.Errorf("SCHEMA-005: decodeStored did not carry the stream sequence (got %d, want 7)", got.Sequence)
	}

	// (2) A legacy/baseline envelope that OMITS "v" must read back as the baseline,
	// not as version 0 (the silent-misprojection failure mode this field prevents).
	legacy := storedEvent{ID: "e1", Type: "owner.created", TenantID: "t1", Time: now} // SchemaVersion left 0 -> omitempty drops "v"
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("SCHEMA-005: marshal legacy envelope: %v", err)
	}
	if strings.Contains(string(legacyRaw), `"v"`) {
		t.Errorf("SCHEMA-005: a baseline (v1) envelope must omit the \"v\" field for backward compatibility, got %s", legacyRaw)
	}
	legacyGot, err := decodeStored(legacyRaw, 1)
	if err != nil {
		t.Fatalf("SCHEMA-005: decode legacy envelope: %v", err)
	}
	if legacyGot.SchemaVersion != DefaultSchemaVersion {
		t.Errorf("SCHEMA-005: a legacy envelope without \"v\" read back as SchemaVersion=%d, want DefaultSchemaVersion=%d (legacy events must normalize to the baseline, never 0)", legacyGot.SchemaVersion, DefaultSchemaVersion)
	}
}

// TestProtectSCHEMA005_ProjectorRejectsUnknownVersionAnchor locks the projector's
// reject path by reading its source: a *known* event type carrying an unrecognized
// schema version must fail closed via ErrUnknownSchemaVersion inside
// ValidateSchemaVersion, which ApplyTx calls before decoding. If a future edit removes
// the version gate or stops failing closed, this guard goes RED.
func TestProtectSCHEMA005_ProjectorRejectsUnknownVersionAnchor(t *testing.T) {
	path := filepath.Join("..", "projections", "projections.go")
	src, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("SCHEMA-005 anchor: cannot read %s (the projector reject path must exist): %v", path, err)
	}
	body := string(src)
	for _, needle := range []string{
		"var knownSchemaVersions",                  // the per-type set of accepted versions
		"ErrUnknownSchemaVersion",                  // the fail-closed sentinel
		"func ValidateSchemaVersion(",              // the gate
		"if v := schemaVersionOf(e); !versions[v]", // rejects a known type at an unknown version
		"return fmt.Errorf(\"%w: type %q v%d",      // the reject wraps ErrUnknownSchemaVersion
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("SCHEMA-005: projector reject path missing %q in %s; unknown-version events may no longer fail closed", needle, path)
		}
	}
	// ApplyTx moved into certificate_recording.go. It must admit the schema
	// before entering metadata classification, which can decode ownership data.
	path = filepath.Join("..", "projections", "certificate_recording.go")
	src, err = os.ReadFile(path) // #nosec G304 -- fixed repository source anchor, not caller input (CWE-22)
	if err != nil {
		t.Fatalf("SCHEMA-005 anchor: cannot read %s: %v", path, err)
	}
	applyIdx := strings.Index(string(src), "func (p *Projector) ApplyTx(")
	if applyIdx < 0 {
		t.Fatalf("SCHEMA-005: ApplyTx no longer exists in %s; re-point this guard", path)
	}
	rest := string(src)[applyIdx:]
	gateIdx := strings.Index(rest, "ValidateSchemaVersion(e)")
	switchIdx := strings.Index(rest, "p.store.WithCertificateProjectionOrderTx(")
	if gateIdx < 0 || switchIdx < 0 {
		t.Fatalf("SCHEMA-005: ApplyTx must validate schema before entering metadata classification; re-validate the reject path")
	}
	if gateIdx >= switchIdx {
		t.Errorf("SCHEMA-005: ApplyTx enters metadata classification (@%d) before validating the schema version (@%d); a known type at an unknown version could be decoded against the wrong struct", switchIdx, gateIdx)
	}
}
