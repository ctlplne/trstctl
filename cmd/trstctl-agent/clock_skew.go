// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/agent"
)

// clockSkewRepeat is how often a clock warning that persists is logged again.
const clockSkewRepeat = time.Hour

// clockSkewNotice turns the control plane's clock answers into this host's log
// (A194): a warning when the control plane says this host's clock is past its
// threshold, repeated hourly while it lasts, and one line when it clears.
// Renewal timing still uses this host's clock; the warning is what tells the
// operator it may be wrong.
type clockSkewNotice struct {
	warned     bool
	lastWarned time.Time
}

// observe returns the line to log for one heartbeat response, or "".
func (n *clockSkewNotice) observe(resp *agent.HeartbeatResponse, now time.Time) string {
	if resp == nil || resp.ServerTimeUnixMilli <= 0 {
		return ""
	}
	if !resp.ClockSkewWarning {
		if n.warned {
			n.warned = false
			return "trstctl-agent: clock skew cleared: this host's clock now agrees with the control plane's"
		}
		return ""
	}
	if n.warned && now.Sub(n.lastWarned) < clockSkewRepeat {
		return ""
	}
	n.warned, n.lastWarned = true, now
	skew := now.Sub(time.UnixMilli(resp.ServerTimeUnixMilli))
	direction := "ahead of"
	if skew < 0 {
		direction, skew = "behind", -skew
	}
	return fmt.Sprintf("trstctl-agent: clock skew warning: this host's clock is about %s %s the control plane's; "+
		"this agent times its certificate renewal by this clock, so correct the host's time source (NTP)",
		skew.Round(time.Second), direction)
}
