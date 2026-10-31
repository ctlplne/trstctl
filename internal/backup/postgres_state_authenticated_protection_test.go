// SPDX-License-Identifier: BUSL-1.1
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
)

type authenticatedPostgresOpener struct {
	key   seal.KeyWrapper
	calls int
}

func TestProtectedPostgresCustodyFactoryRunsOnlyAfterAuthentication(t *testing.T) {
	f := newProtectedPostgresStreamFixture(t)
	artifact := f.stream(t, nil, true, true)
	opened, closed := 0, 0
	id := PostgresStateIdentity{TrustAnchors: [][]byte{f.signer.Public().DER}}
	id.ProtectionFactory = func(_ context.Context, summary PostgresStateSummary) (PostgresStateProtection, func(), error) {
		opened++
		if summary.Records != 1 || summary.EventCutSequence != 17 {
			t.Fatal("factory received an unverified cut/count")
		}
		summary.Tables["api_tokens"] = 99 // the callback cannot alter original evidence
		return f.opener, func() { closed++ }, nil
	}
	if _, err := VerifyPostgresStateWithKey(bytes.NewReader(artifact), f.integrity, id); err != nil || opened != 0 {
		t.Fatal("verify-only reached custody construction")
	}
	rows, summary, err := readPostgresStateForRestore(t.Context(), bytes.NewReader(artifact), f.integrity, id)
	if err != nil || opened != 1 || closed != 1 || summary.Tables["api_tokens"] != 1 || summary.AppliedRecords != 1 || !bytes.Equal(rows["api_tokens"][0], f.plain) {
		t.Fatalf("authenticated factory scope/cleanup/counts failed: %+v %v", summary, err)
	}
	for _, bad := range [][]byte{artifact[:len(artifact)/2], f.stream(t, func(_ map[string]any, row *protectedPostgresRecord) { row.Ordinal = 2 }, true, true)} {
		opened, closed = 0, 0
		if _, _, err := readPostgresStateForRestore(t.Context(), bytes.NewReader(bad), f.integrity, id); err == nil || opened != 0 || closed != 0 {
			t.Fatal("invalid artifact reached custody factory")
		}
	}
	opened, closed = 0, 0
	id.ProtectionFactory = func(context.Context, PostgresStateSummary) (PostgresStateProtection, func(), error) {
		opened++
		return nil, func() { closed++ }, errors.New("fixture initialization failed")
	}
	if _, _, err := readPostgresStateForRestore(t.Context(), bytes.NewReader(artifact), f.integrity, id); err == nil || opened != 1 || closed != 1 {
		t.Fatal("partial initialization leaked the factory resource")
	}
}

func (*authenticatedPostgresOpener) ProtectPostgresRow(context.Context, eventprotect.Context, json.RawMessage) (eventprotect.Envelope, bool, error) {
	panic("read-only fixture")
}
func (p *authenticatedPostgresOpener) OpenPostgresRow(_ context.Context, binding eventprotect.Context, envelope eventprotect.Envelope) (json.RawMessage, bool, error) {
	p.calls++
	opened, err := eventprotect.Open(p.key, binding, postgresRowPolicyDigest(), envelope)
	return opened.Data, false, err
}

type protectedPostgresStreamFixture struct {
	artifact  protectedPostgresArtifact
	row       protectedPostgresRecord
	plain     []byte
	integrity []byte
	signer    crypto.Signer
	opener    *authenticatedPostgresOpener
}

func newProtectedPostgresStreamFixture(t *testing.T) protectedPostgresStreamFixture {
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
	f := protectedPostgresStreamFixture{artifact: protectedPostgresArtifact{ID: "5440db9a-dc88-48d9-9b1d-25a3240305c6", CreatedAt: time.Now().UTC(), EventCutSequence: 17}, row: protectedPostgresRecord{Table: "api_tokens", Ordinal: 1, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c"}, plain: []byte(`{"tenant_id":"d59b4292-1adc-4d43-a405-781f95b1779c","subject":"authenticated-artifact@example.invalid"}`), integrity: []byte("local artifact integrity fixture"), signer: signedManifestKey(t), opener: &authenticatedPostgresOpener{key: key}}
	binding, err := postgresRowContext(f.artifact, f.row)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := eventprotect.Protect(key, binding, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", postgresRowPolicyDigest(), eventprotect.Payload{Data: f.plain})
	if err != nil {
		t.Fatal(err)
	}
	f.row.Protection = &envelope
	return f
}
func (f protectedPostgresStreamFixture) stream(t *testing.T, mutate func(map[string]any, *protectedPostgresRecord), keyed, signed bool) []byte {
	t.Helper()
	header := map[string]any{"format": postgresStateFormatTag, "version": 2, "artifact_id": f.artifact.ID, "created_at": f.artifact.CreatedAt, "event_cut_sequence": f.artifact.EventCutSequence, "tables": postgresStateTables()}
	row := f.row
	if mutate != nil {
		mutate(header, &row)
	}
	var integrity []byte
	if keyed {
		integrity = f.integrity
	}
	digest := newDigest(integrity)
	var output bytes.Buffer
	for _, value := range []any{header, row} {
		line, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		feed(digest, line)
		output.Write(line)
		output.WriteByte('\n')
	}
	tr := postgresStateTrailer{Format: postgresStateTrailerTag, SHA256: digest.sumHex(), Records: 1, Tables: map[string]int{row.Table: 1}, EventCutSequence: f.artifact.EventCutSequence}
	if keyed {
		tr.HMACSHA256 = digest.macHex()
	}
	if signed {
		tr = signTrailer(t, f.signer, tr)
	}
	if err := json.NewEncoder(&output).Encode(tr); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
func (f protectedPostgresStreamFixture) identity() PostgresStateIdentity {
	return PostgresStateIdentity{TrustAnchors: [][]byte{f.signer.Public().DER}, Protection: f.opener}
}

func TestProtectedPostgresVerificationNeverOpensRows(t *testing.T) {
	f := newProtectedPostgresStreamFixture(t)
	artifact := f.stream(t, nil, true, true)
	summary, err := VerifyPostgresStateWithKey(bytes.NewReader(artifact), f.integrity, f.identity())
	if err != nil || summary.Records != 1 || summary.Tables["api_tokens"] != 1 || summary.EventCutSequence != 17 {
		t.Fatalf("exact authenticated v2 stream refused: %+v %v", summary, err)
	}
	if f.opener.calls != 0 {
		t.Fatal("verify-only preflight reached tenant key custody")
	}
	rows, restored, err := readPostgresStateForRestore(t.Context(), bytes.NewReader(artifact), f.integrity, f.identity())
	if err != nil || len(rows["api_tokens"]) != 1 || !bytes.Equal(rows["api_tokens"][0], f.plain) || restored.Records != 1 {
		t.Fatalf("authenticated row round trip failed: %+v %v", restored, err)
	}
	if f.opener.calls != 1 {
		t.Fatal("restore did not open the exact authenticated frame once")
	}
}

func TestProtectedPostgresRejectsInvalidWholeArtifactBeforeCustody(t *testing.T) {
	f := newProtectedPostgresStreamFixture(t)
	exact := f.stream(t, nil, true, true)
	cases := map[string][]byte{
		"header-changed":        bytes.Replace(exact, []byte(f.artifact.ID), []byte("f31a8a45-8905-4296-bf66-427ffb790226"), 1),
		"ciphertext-changed":    bytes.Replace(exact, []byte(`"ciphertext":"`), []byte(`"ciphertext":"AA`), 1),
		"truncated":             exact[:len(exact)/2],
		"trailing-data":         append(bytes.Clone(exact), []byte("{}\n")...),
		"signed-bad-ordinal":    f.stream(t, func(_ map[string]any, r *protectedPostgresRecord) { r.Ordinal = 2 }, true, true),
		"signed-unknown-table":  f.stream(t, func(_ map[string]any, r *protectedPostgresRecord) { r.Table = "unclassified_table" }, true, true),
		"signed-bad-cut":        f.stream(t, func(h map[string]any, _ *protectedPostgresRecord) { h["event_cut_sequence"] = 18 }, true, true),
		"signed-ambiguous-row":  f.stream(t, func(_ map[string]any, r *protectedPostgresRecord) { r.Row = f.plain }, true, true),
		"signed-invalid-tenant": f.stream(t, func(_ map[string]any, r *protectedPostgresRecord) { r.TenantID = "invalid" }, true, true),
	}
	for name, artifact := range cases {
		t.Run(name, func(t *testing.T) {
			f.opener.calls = 0
			if _, _, err := readPostgresStateForRestore(t.Context(), bytes.NewReader(artifact), f.integrity, f.identity()); err == nil {
				t.Fatal("invalid artifact accepted")
			}
			if f.opener.calls != 0 {
				t.Fatal("invalid artifact reached custody before complete authentication and structural validation")
			}
			// The real restore must reject before dereferencing even a store handle.
			// Passing nil here makes an unintended SQL path a hard regression failure.
			if _, err := RestorePostgresStateWithKey(t.Context(), nil, bytes.NewReader(artifact), f.integrity, f.identity()); err == nil {
				t.Fatal("real restore accepted invalid artifact")
			}
			if f.opener.calls != 0 {
				t.Fatal("real restore reached custody for invalid artifact")
			}
		})
	}
	// A self-consistent plain SHA is not an origin proof. Do not let a configured
	// opener turn checksum-only content into permission to call key custody.
	f.opener.calls = 0
	id := PostgresStateIdentity{Protection: f.opener}
	if _, _, err := readPostgresStateForRestore(t.Context(), bytes.NewReader(f.stream(t, nil, false, false)), nil, id); err == nil {
		t.Fatal("checksum-only protected artifact reached restore")
	}
	if f.opener.calls != 0 {
		t.Fatal("checksum-only artifact reached custody")
	}
}
