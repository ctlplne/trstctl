// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"testing"
)

func FuzzGuardedPostgresBindFraming(f *testing.F) {
	for _, seed := range [][]byte{{}, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 1, 255, 255, 255, 255, 0, 0}, {0, 0, 0, 0, 0, 1, 255, 255, 255, 254, 0, 0}, []byte("unterminated-name")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		original := bytes.Clone(raw)
		portal, statement, ok := pgCommandBind(raw)
		if !bytes.Equal(raw, original) {
			t.Fatal("Bind framing parser modified client traffic")
		}
		if ok && (len(portal) > 256 || len(statement) > 256 || bytes.IndexByte(portal, 0) >= 0 || bytes.IndexByte(statement, 0) >= 0) {
			t.Fatal("Bind parser returned unbounded or unterminated names")
		}
	})
}
