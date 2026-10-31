// SPDX-License-Identifier: BUSL-1.1
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventprotect"
)

// Auto-discovered by the native ClusterFuzzLite build. Ciphertext here is a
// structural opaque seed; actual AEAD and full restore have separate tests.
func FuzzProtectedPostgresState(f *testing.F) {
	integrity := []byte("owned postgres integrity fixture")
	var seed bytes.Buffer
	digest := newDigest(integrity)
	encoder := json.NewEncoder(io.MultiWriter(&seed, digest))
	h := postgresStateHeader{Format: postgresStateFormatTag, Version: protectedPostgresStateVersion, ArtifactID: "0497990b-f74f-4644-803e-52e4d0052bf6", CreatedAt: time.Now().UTC(), EventCutSequence: 17, Tables: postgresStateTables()}
	row := protectedPostgresRecord{Table: "api_tokens", Ordinal: 1, TenantID: "60aad68e-4613-4658-a75a-10ee97084edf", Protection: &eventprotect.Envelope{Version: 1, KeyID: "06bc0318-6b02-471c-b3c4-54257995848a", PolicyDigest: postgresRowPolicyDigest(), Ciphertext: []byte("opaque framing seed")}}
	if err := encoder.Encode(h); err != nil {
		f.Fatal(err)
	}
	if err := encoder.Encode(row); err != nil {
		f.Fatal(err)
	}
	tr := postgresStateTrailer{Format: postgresStateTrailerTag, SHA256: digest.sumHex(), HMACSHA256: digest.macHex(), Records: 1, Tables: map[string]int{"api_tokens": 1}, EventCutSequence: 17}
	if err := json.NewEncoder(&seed).Encode(tr); err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.Clone(seed.Bytes()))
	f.Add([]byte(`{}`))
	f.Add(bytes.Clone(seed.Bytes()[:seed.Len()/2]))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		} // generated-example bound, not a product size limit
		calls := 0
		id := PostgresStateIdentity{ProtectionFactory: func(context.Context, PostgresStateSummary) (PostgresStateProtection, func(), error) {
			calls++
			return nil, nil, nil
		}}
		_, _ = VerifyPostgresStateWithKey(bytes.NewReader(raw), integrity, id)
		if calls != 0 {
			t.Fatal("offline SQL artifact verification reached custody factory")
		}
	})
}
