// SPDX-License-Identifier: BUSL-1.1
package splunk

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestSplunkAppAssetsAndCorrelationContracts(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "-m", "unittest", "discover", "-s", "tests", "-v")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("owned Splunk app contract checks: %v\n%s", err, output)
	}
	t.Log(string(output))
}
