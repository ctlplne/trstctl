// Install before helper to observe missing-API red after the active checkpoint.
// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
)

type fixturePostgresRowOpener struct {
	key   seal.KeyWrapper
	calls int
}

func (opener *fixturePostgresRowOpener) ProtectPostgresRow(context.Context, eventprotect.Context, json.RawMessage) (eventprotect.Envelope, bool, error) {
	panic("read-only fixture")
}
func (opener *fixturePostgresRowOpener) OpenPostgresRow(_ context.Context, context eventprotect.Context, envelope eventprotect.Envelope) (json.RawMessage, bool, error) {
	opener.calls++
	payload, err := eventprotect.Open(opener.key, context, postgresRowPolicyDigest(), envelope)
	return payload.Data, false, err
}

func TestProtectedPostgresFramingBindsArtifactRowTableTenantAndTime(t *testing.T) {
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	key, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	artifact := protectedPostgresArtifact{ID: "bfeae8d0-f7a2-4b94-9d8c-f68621b3820d", CreatedAt: time.Now().UTC()}
	row := protectedPostgresRecord{Table: "api_tokens", Ordinal: 1, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c"}
	binding, err := postgresRowContext(artifact, row)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"tenant_id":"d59b4292-1adc-4d43-a405-781f95b1779c","subject":"person@example.invalid"}`)
	envelope, err := eventprotect.Protect(key, binding, "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", postgresRowPolicyDigest(), eventprotect.Payload{Data: want})
	if err != nil {
		t.Fatal(err)
	}
	row.Protection = &envelope
	opener := &fixturePostgresRowOpener{key: key}
	got, erased, err := openAuthenticatedPostgresRecord(t.Context(), artifact, row, opener)
	if err != nil || erased || !bytes.Equal(got, want) {
		t.Fatalf("exact protected row refused: %v", err)
	}
	defer secret.Wipe(got)
	for _, tc := range []struct {
		name   string
		change func(*protectedPostgresArtifact, *protectedPostgresRecord)
	}{
		{"artifact", func(a *protectedPostgresArtifact, _ *protectedPostgresRecord) {
			a.ID = "531c8134-bdf7-445f-bdad-d7f19b26bc0b"
		}},
		{"paired-cut", func(a *protectedPostgresArtifact, _ *protectedPostgresRecord) { a.EventCutSequence++ }},
		{"ordinal", func(_ *protectedPostgresArtifact, r *protectedPostgresRecord) { r.Ordinal++ }},
		{"table", func(_ *protectedPostgresArtifact, r *protectedPostgresRecord) { r.Table = "tenant_members" }},
		{"tenant", func(_ *protectedPostgresArtifact, r *protectedPostgresRecord) {
			r.TenantID = "2c14fe81-1956-4e9d-a174-e27a38e8e979"
		}},
		{"time", func(a *protectedPostgresArtifact, _ *protectedPostgresRecord) {
			a.CreatedAt = a.CreatedAt.Add(time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r := artifact, row
			tc.change(&a, &r)
			if _, _, err := openAuthenticatedPostgresRecord(t.Context(), a, r, opener); err == nil {
				t.Fatal("transplanted protected row opened")
			}
		})
	}
	if _, _, err := openAuthenticatedPostgresRecord(t.Context(), artifact, row, nil); err == nil {
		t.Fatal("missing custodian accepted protected data")
	}
	row.Row = want
	calls := opener.calls
	if _, _, err := openAuthenticatedPostgresRecord(t.Context(), artifact, row, opener); err == nil || opener.calls != calls {
		t.Fatal("ambiguous clear+protected row reached custody")
	}
}
