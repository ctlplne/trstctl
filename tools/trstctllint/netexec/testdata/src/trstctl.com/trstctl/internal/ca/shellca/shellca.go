// SPDX-License-Identifier: MPL-2.0

package shellca

import (
	"context"
	"os/exec"
)

type backend struct {
	command string
	args    []string
}

func (b *backend) run(ctx context.Context) error {
	return exec.CommandContext(ctx, b.command, b.args...).Run()
}
