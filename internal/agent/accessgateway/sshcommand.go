// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto/sshgateway"
)

// sshRequest sees only session requests after upstream authentication. Certificate
// creation and target sign-in never pass through this callback.
func (c *commandConnection) sshRequest(ctx context.Context, kind string, payload []byte) bool {
	switch kind {
	case "pty-req", "window-change", "signal", "break", "keepalive@openssh.com":
		return true
	}
	phase := "control"
	var operations []string
	message := payload
	if kind == "exec" {
		phase = "exec"
		command, valid := sshgateway.ExecCommand(payload)
		if valid {
			message = command
			var err error
			operations, err = accessrules.SSHOperations(command)
			if err != nil {
				phase = "uninspectable"
			}
		} else {
			phase = "uninspectable"
		}
	}
	result, err := c.evaluate(ctx, phase, operations, message, "")
	if err != nil {
		return false
	}
	return result.decision.ID == "" || result.durable && result.decision.Status == accessrules.StatusAuthorized
}
