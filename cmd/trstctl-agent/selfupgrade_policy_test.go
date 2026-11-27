// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"strings"
	"testing"
)

func TestSelfUpgradeCannotStartWithoutPublisherTrustAnchor(t *testing.T) {
	err := runAgent(context.Background(), agentOptions{selfUpgrade: true})
	if err == nil || !strings.Contains(err.Error(), "--upgrade-publisher-key") {
		t.Fatalf("agent started self-upgrade without publisher trust anchor: %v", err)
	}
}
