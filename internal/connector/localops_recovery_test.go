// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"os"
	"strings"
	"testing"
)

// A containment's recovery action must be another action the profile pins.
func TestLocalOpsContainmentRecoveryActionMustBeAnotherAction(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := LocalOpsConfig{
		AllowedRoots: []string{t.TempDir()},
		Actions: []LocalAction{
			{LogicalName: "stop-target", LogicalArgs: []string{}, Command: executable},
			{LogicalName: "nginx", Command: executable, PassArgs: true},
		},
		Containments: []LocalContainment{{
			TargetID: "11111111-1111-4111-8111-111111111111",
			Address:  "127.0.0.1:18443", Action: "stop-target", RecoveryAction: "nginx",
		}},
	}
	if _, err := NewLocalOps(config); err != nil {
		t.Fatalf("a recovery action that is another pinned action was refused: %v", err)
	}
	for _, recovery := range []string{"stop-target", "not-an-action"} {
		config.Containments[0].RecoveryAction = recovery
		if _, err := NewLocalOps(config); err == nil || !strings.Contains(err.Error(), "recovery action") {
			t.Fatalf("recovery action %q accepted: %v", recovery, err)
		}
	}
}
