// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"context"
	"os/exec"
)

func ProbeWithOpenSSL(ctx context.Context, address string) {
	// The runtime boundary supplies the validation. This fixture verifies that
	// its exact file/function can launch while shell launches remain forbidden.
	_ = exec.CommandContext(ctx, "/usr/bin/openssl", "s_client", "-connect", address)
	_ = exec.CommandContext(ctx, "/bin/sh", "-c", address) // want "direct shell interpreter execution is not allowed"
}

func unreviewedNeighbor(ctx context.Context, executable string) {
	_ = exec.CommandContext(ctx, executable) // want "exec.Command is not allowed in new process surfaces"
}
