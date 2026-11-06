// SPDX-License-Identifier: BUSL-1.1
//go:build !windows

package awsiam

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func TestAWSIAMSharedPOSIXSessionFileRefusedA264(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := secretfile.Create(path, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- deliberate shared-file negative fixture; SessionFile must reject it (CWE-276)
		t.Fatal(err)
	}
	if err := SessionFile(path, time.Now)(context.Background(), func(awssignin.Credentials) error { t.Fatal("shared session file reached signing callback"); return nil }); err == nil {
		t.Fatal("shared session file accepted")
	}
}
