// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMissingPgCtlForcesArchiveAcquisition(t *testing.T) {
	path := t.TempDir()
	if err := os.Mkdir(filepath.Join(path, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	fetchErr := errors.New("archive acquisition requested")
	db := &EmbeddedPostgres{
		config:              Config{binariesPath: path},
		remoteFetchStrategy: func() error { return fetchErr },
	}
	if err := db.downloadAndExtractBinary(false, filepath.Join(path, "archive.txz")); !errors.Is(err, fetchErr) {
		t.Fatalf("empty bin directory must not bypass acquisition: %v", err)
	}
}

func TestLegacyExtractionCreatesNestedRuntimeParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "runtime", "binaries")
	if err := decompressTarXz(defaultTarReader, "testdata/verified-postgres-fixture.txz", path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "bin", "pg_ctl")); err != nil {
		t.Fatalf("nested extraction did not publish pg_ctl: %v", err)
	}
}

func TestLifecycleErrorsKeepUpstreamSentinels(t *testing.T) {
	if err := (&EmbeddedPostgres{}).Stop(); !errors.Is(err, ErrServerNotStarted) {
		t.Fatalf("stopping an idle database returned %v", err)
	}
	if err := (&EmbeddedPostgres{started: true}).Start(); !errors.Is(err, ErrServerAlreadyStarted) {
		t.Fatalf("starting an active database returned %v", err)
	}
}
