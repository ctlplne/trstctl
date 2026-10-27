// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
)

// A194: the agent logs a named clock-skew warning when the control plane says
// its clock is past the threshold, says how far and in which direction,
// repeats it hourly rather than on every heartbeat, and says when it clears.
func TestAgentLogsANamedClockSkewWarningAndWhenItClears(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	server := now.Add(-7 * time.Minute).UnixMilli()
	var n clockSkewNotice
	if got := n.observe(&agent.HeartbeatResponse{ServerTimeUnixMilli: now.UnixMilli()}, now); got != "" {
		t.Fatalf("an agreeing clock logged %q", got)
	}
	got := n.observe(&agent.HeartbeatResponse{ServerTimeUnixMilli: server, ClockSkewWarning: true}, now)
	if !strings.Contains(got, "clock skew warning") || !strings.Contains(got, "7m0s ahead of") {
		t.Fatalf("warning = %q", got)
	}
	if again := n.observe(&agent.HeartbeatResponse{ServerTimeUnixMilli: server, ClockSkewWarning: true}, now.Add(30*time.Second)); again != "" {
		t.Fatalf("the warning repeated on the next heartbeat: %q", again)
	}
	if hourly := n.observe(&agent.HeartbeatResponse{ServerTimeUnixMilli: server, ClockSkewWarning: true}, now.Add(time.Hour)); !strings.Contains(hourly, "clock skew warning") {
		t.Fatalf("the warning did not repeat after an hour: %q", hourly)
	}
	behind := clockSkewNotice{}
	if got := behind.observe(&agent.HeartbeatResponse{ServerTimeUnixMilli: now.Add(5 * time.Minute).UnixMilli(), ClockSkewWarning: true}, now); !strings.Contains(got, "5m0s behind") {
		t.Fatalf("a clock behind = %q", got)
	}
	if cleared := n.observe(&agent.HeartbeatResponse{ServerTimeUnixMilli: now.UnixMilli()}, now.Add(2*time.Hour)); !strings.Contains(cleared, "clock skew cleared") {
		t.Fatalf("clearing = %q", cleared)
	}
	if got := n.observe(&agent.HeartbeatResponse{}, now); got != "" {
		t.Fatalf("a control plane that sent no time logged %q", got)
	}
}
