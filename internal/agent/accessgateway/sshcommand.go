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
			operations, err = accessrules.SSHRuleOperations(command)
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
	return result.decision.ID == "" || result.durable && accessrules.Permits(result.decision.Status)
}

// netDeviceRequest is sshRequest for a network device (A270): an exec
// request's command lines are read for device operations. A shell is
// accepted, because its typed lines are judged one by one (netDeviceLine,
// A270-L1); any other session request answers to every rule.
func (c *commandConnection) netDeviceRequest(ctx context.Context, kind string, payload []byte) bool {
	switch kind {
	case "pty-req", "window-change", "signal", "break", "keepalive@openssh.com", "shell":
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
			operations, err = accessrules.NetDeviceOperations(command)
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
	return result.decision.ID == "" || result.durable && accessrules.Permits(result.decision.Status)
}

// netDeviceLine judges one line typed in an interactive device shell
// (A270-L1) as the device would run it: like an exec request's command, its
// first word names the device operations a rule can match. A line the gateway
// could not follow (history recall, completion, cursor movement) is
// uninspectable and answers to every rule.
func (c *commandConnection) netDeviceLine(ctx context.Context, line []byte, readable bool) bool {
	phase := "exec"
	var operations []string
	if !readable {
		phase = "uninspectable"
	} else {
		var err error
		operations, err = accessrules.NetDeviceOperations(line)
		if err != nil {
			phase = "uninspectable"
		}
	}
	result, err := c.evaluate(ctx, phase, operations, line, "")
	if err != nil {
		return false
	}
	return result.decision.ID == "" || result.durable && accessrules.Permits(result.decision.Status)
}
