// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLICommandExecutionRejectsCallerTokenInArguments(t *testing.T) {
	for _, command := range [][]string{{"access", "run"}, {"access", "agent"}, {"run"}} {
		args := append([]string{"--token", "caller-token-fixture"}, command...)
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), args, Env{}, nil, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "TRSTCTL_TOKEN") {
			t.Fatalf("%v: exit=%d stderr=%q", command, code, stderr.String())
		}
	}
}
