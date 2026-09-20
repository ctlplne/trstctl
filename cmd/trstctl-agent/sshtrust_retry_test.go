// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestAgentSSHTrustRetryDoesNotSkipRuntimeChecks(t *testing.T) {
	for _, stage := range []string{"validate", "reload", "health"} {
		t.Run(stage, func(t *testing.T) {
			o := baseOpts(t)
			config := "Port 2222\nTrustedUserCAKeys " + o.trustedKeys + "\n"
			if err := os.WriteFile(o.trustedKeys, []byte(testCALine), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(o.sshdConfig, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "validate":
				o.validateCmd = "false"
			case "reload":
				o.reloadCmd = "false"
			case "health":
				o.healthCmd = "false"
			}
			handled, err := runSSHTrustAddCA(context.Background(), o)
			if !handled || err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("existing files bypassed failed %s command: handled=%v err=%v", stage, handled, err)
			}
			trust, readErr := os.ReadFile(o.trustedKeys)
			if readErr != nil || string(trust) != testCALine {
				t.Fatalf("retry changed trusted CA keys: %v", readErr)
			}
			gotConfig, readErr := os.ReadFile(o.sshdConfig)
			if readErr != nil || string(gotConfig) != config {
				t.Fatalf("retry changed sshd configuration: %v", readErr)
			}
		})
	}
}
