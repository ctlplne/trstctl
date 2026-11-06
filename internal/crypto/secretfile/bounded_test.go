// SPDX-License-Identifier: BUSL-1.1
package secretfile

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestLoadBoundedRejectsOversizedPrivateMaterialA264(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-session.json")
	data := bytes.Repeat([]byte("x"), 4097)
	if err := Create(path, data); err != nil {
		t.Fatal(err)
	}
	if raw, err := LoadBounded(path, 4096); err == nil || len(raw) != 0 {
		t.Fatalf("oversized material returned: bytes=%d err=%v", len(raw), err)
	}
	raw, err := LoadBounded(path, len(data))
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatalf("exact bounded read refused: bytes=%d err=%v", len(raw), err)
	}
}
