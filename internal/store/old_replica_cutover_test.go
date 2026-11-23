// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/store"
)

// A rewrap admission can recognize upgraded database sessions only if every
// Store connection identifies this exact build, including the request pool.
func TestStoreLabelsRequestConnectionsWithBuildVersion(t *testing.T) {
	s, err := store.Open(context.Background(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var label string
	if err := s.SystemPool().QueryRow(t.Context(),
		`SELECT current_setting('application_name')`).Scan(&label); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(label, "trstctl/") ||
		!strings.Contains(label, buildinfo.Commit()) ||
		!strings.Contains(label, buildinfo.Version()) {
		t.Fatalf("request-pool application_name=%q lacks build version %q and commit %q",
			label, buildinfo.Version(), buildinfo.Commit())
	}
}
