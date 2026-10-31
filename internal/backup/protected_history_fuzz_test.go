// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"testing"
)

// The native target is auto-discovered by .clusterfuzzlite/build.sh. Only seed
// construction uses a live fixture; each fuzz iteration is an offline artifact
// preflight and has no custodian or restore target.
func FuzzProtectedEventBackup(f *testing.F) {
	log, _, _ := protectedHistoryFixture(f)
	integrity := []byte("owned backup integrity fixture")
	var seed bytes.Buffer
	if _, err := WriteLogWithKey(f.Context(), log, &seed, integrity); err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.Clone(seed.Bytes()))
	f.Add([]byte(`{"format":"trstctl-event-log-backup","version":3}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		// Bound generated examples; this is not a production artifact limit.
		if len(raw) > 1<<20 {
			return
		}
		original := bytes.Clone(raw)
		_, _ = VerifyEventLogBackupWithKey(bytes.NewReader(raw), integrity)
		if !bytes.Equal(raw, original) {
			t.Fatal("offline verification changed the input artifact")
		}
	})
}
