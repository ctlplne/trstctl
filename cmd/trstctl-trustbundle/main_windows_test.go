// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package main

import (
	"strings"
	"testing"
)

// Owner decision 2026-11-02 (item 2g i), proven on windows-latest: the tool
// builds and checks Linux images, so on Windows every command refuses before
// reading anything.
func TestTrustBundleRefusesOnWindows(t *testing.T) {
	for _, args := range [][]string{{"list"}, {"filter", "-in", `C:\bundle.pem`, "-out", `C:\out.pem`}, {"audit"}} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "running it on Windows is what comes next") {
			t.Fatalf("run(%v) on Windows = %v, want a clean refusal", args, err)
		}
	}
}
