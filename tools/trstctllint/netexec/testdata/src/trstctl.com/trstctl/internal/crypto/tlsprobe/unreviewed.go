// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"context"
	"os/exec"
)

type differentFile struct{}

// Reusing the reviewed function name in another file must not inherit it.
func (differentFile) ProbeWithOpenSSL(ctx context.Context, executable string) {
	_ = exec.CommandContext(ctx, executable) // want "exec.Command is not allowed in new process surfaces"
}
