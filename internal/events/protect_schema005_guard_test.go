package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	src, err := os.ReadFile(path)
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
	// The gate must be invoked before any payload decode in ApplyTx.
	applyIdx := strings.Index(body, "func (p *Projector) ApplyTx(")
	if applyIdx < 0 {
		t.Fatalf("SCHEMA-005: ApplyTx no longer exists in %s; re-point this guard", path)
	}
	rest := body[applyIdx:]
	gateIdx := strings.Index(rest, "ValidateSchemaVersion(e)")
	switchIdx := strings.Index(rest, "switch e.Type")
	if gateIdx < 0 || switchIdx < 0 {
		t.Fatalf("SCHEMA-005: ApplyTx no longer gates on ValidateSchemaVersion before dispatching on e.Type; re-validate the reject path")
	}
	if !(gateIdx < switchIdx) {
		t.Errorf("SCHEMA-005: ApplyTx dispatches on e.Type (@%d) before validating the schema version (@%d); a known type at an unknown version could be decoded against the wrong struct", switchIdx, gateIdx)
	}
}
