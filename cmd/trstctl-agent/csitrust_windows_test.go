// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package main

import (
	"strings"
	"testing"
)

// Owner decision 2026-11-02 (item 2g h), proven on windows-latest: on Windows
// the CSI trust driver refuses before reaching the cluster or opening a
// socket, and says Windows nodes are what comes next.
func TestCSITrustDriverRefusesOnWindows(t *testing.T) {
	err := runCSITrust(t.Context(), `C:\var\lib\kubelet\plugins\trust.csi.trstctl.com\csi.sock`)
	if err == nil || !strings.Contains(err.Error(), "Windows nodes are what comes next") {
		t.Fatalf("runCSITrust on Windows = %v, want a clean refusal", err)
	}
}
