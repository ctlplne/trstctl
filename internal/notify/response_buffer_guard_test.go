// SPDX-License-Identifier: BUSL-1.1

package notify_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every notification receiver is untrusted and may echo a submitted alert,
// bearer token, or secret webhook URL. Generic io.ReadAll/io.Copy helpers can
// leave response bytes in superseded or pooled buffers. Keep every production
// notifier on the owned, explicitly wiped internal/crypto/secret readers.
func TestNotificationResponseReadersStayWipeable(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate notification response-buffer guard")
	}
	root := filepath.Dir(thisFile)
	forbidden := [][]byte{
		[]byte("io.ReadAll("),
		[]byte("io.Copy("),
		[]byte("io.CopyBuffer("),
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
		if err != nil {
			return err
		}
		for _, call := range forbidden {
			if bytes.Contains(source, call) {
				t.Errorf("%s uses %s for notifier I/O; use secret.ReadBounded or secret.DrainBounded so every observed response byte is wipeable", path, call)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
