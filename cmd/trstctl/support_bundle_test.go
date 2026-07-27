// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupportBundleCommandDoesNotRequireHealthyConfigOrHTTP(t *testing.T) {
	output := filepath.Join(t.TempDir(), "support.tar.gz")
	getenv := func(key string) string {
		if key == "TRSTCTL_POSTGRES_MODE" {
			return "external"
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"support-bundle", "--output", output}, getenv, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("support archive missing: %v", err)
	}
	if !strings.Contains(stdout.String(), "wrote redacted support bundle") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
