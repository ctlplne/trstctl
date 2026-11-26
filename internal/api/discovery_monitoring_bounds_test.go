// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoverySourceConfigLimitBeforeManualValidation(t *testing.T) {
	request := discoverySourceRequest{
		Kind: "manual", Name: "large-manual",
		Config: json.RawMessage(`{"findings":[{"note":"` + strings.Repeat("x", 64*1024) + `"}]}`),
	}
	if _, err := validateDiscoverySourceRequest(request); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("oversized source config: %v", err)
	}
}
