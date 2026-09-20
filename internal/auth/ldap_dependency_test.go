// SPDX-License-Identifier: BUSL-1.1

package auth_test

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestLDAPNTLMSSPDependencyIsFixed(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-json", "github.com/Azure/go-ntlmssp").Output()
	if err != nil {
		t.Fatalf("go list github.com/Azure/go-ntlmssp: %v", err)
	}
	var mod struct {
		Version string
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("parse go list output: %v", err)
	}
	if versionLessThan(mod.Version, "v0.1.1") {
		t.Fatalf("github.com/Azure/go-ntlmssp = %s, want >= v0.1.1 for GHSA-pjcq-xvwq-hhpj", mod.Version)
	}
}

func versionLessThan(got, floor string) bool {
	gotParts, gotOK := majorMinorPatch(got)
	floorParts, floorOK := majorMinorPatch(floor)
	if !gotOK || !floorOK {
		return got != floor
	}
	for i := range gotParts {
		if gotParts[i] != floorParts[i] {
			return gotParts[i] < floorParts[i]
		}
	}
	return false
}

func majorMinorPatch(version string) ([3]int, bool) {
	var parts [3]int
	fields := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(fields) < len(parts) {
		return parts, false
	}
	for i := range parts {
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}
