// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"fmt"
	"time"

	cfg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A194: an agent's clock against the control plane's, measured on each
// heartbeat that carries the agent's clock reading.

// agentClockSkewResponse is the clock finding for one agent. SkewSeconds is
// positive when the agent's clock runs ahead of the control plane's.
type agentClockSkewResponse struct {
	State            string  `json:"state"`
	SkewSeconds      float64 `json:"skew_seconds"`
	ThresholdSeconds float64 `json:"threshold_seconds"`
	ObservedAt       string  `json:"observed_at"`
	Detail           string  `json:"detail"`
}

const (
	agentClockOK         = "ok"
	agentClockWarning    = "warning"
	agentClockUnreported = "unreported"
)

// agentClockSkewFor reports an agent's clock against the control plane's, or
// nil when the agent has never sent a clock reading.
func agentClockSkewFor(a store.Agent, threshold time.Duration) *agentClockSkewResponse {
	if a.ClockSkewMillis == nil || a.ClockSkewObservedAt == nil {
		return nil
	}
	if threshold <= 0 {
		threshold = cfg.DefaultAgentClockSkewWarning
	}
	skew := time.Duration(*a.ClockSkewMillis) * time.Millisecond
	out := &agentClockSkewResponse{
		SkewSeconds: skew.Seconds(), ThresholdSeconds: threshold.Seconds(),
		ObservedAt: a.ClockSkewObservedAt.UTC().Format(time.RFC3339Nano),
	}
	direction, magnitude := "ahead of", skew
	if skew < 0 {
		direction, magnitude = "behind", -skew
	}
	switch {
	case a.LastSeenAt == nil || !a.LastSeenAt.Equal(*a.ClockSkewObservedAt):
		out.State = agentClockUnreported
		out.Detail = "The agent's newest heartbeat carried no clock reading, so its clock cannot be compared now; the last reading is from " +
			out.ObservedAt + "."
	case magnitude > threshold:
		out.State = agentClockWarning
		out.Detail = fmt.Sprintf("This agent's clock is %s %s the control plane's, past the %s warning threshold. The agent times its own certificate renewal by its own clock, so it may renew early or late; correct the host's time source.",
			formatSkew(magnitude), direction, formatSkew(threshold))
	default:
		out.State = agentClockOK
		out.Detail = fmt.Sprintf("This agent's clock is within %s of the control plane's (%s %s at its newest heartbeat).",
			formatSkew(threshold), formatSkew(magnitude), direction)
	}
	return out
}

// formatSkew renders a drift in whole seconds past a minute, tenths below it.
func formatSkew(d time.Duration) string {
	if d >= time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(100 * time.Millisecond).String()
}
