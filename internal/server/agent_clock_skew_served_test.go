// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A194: the heartbeat carries both clocks. An agent whose clock is seven
// minutes ahead is told so in the heartbeat's answer, is named on the agents
// list as a clock-skew warning with the measured drift, and is counted by the
// gauge the TrstctlAgentClockSkew alert watches; when its clock agrees again
// the warning clears, and a heartbeat with no clock reading is reported as
// unreported rather than as current.
func TestServedHeartbeatClockSkewRaisesANamedWarningAndFinding(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "a194-edge", []string{mtls.AgentRoleHost}, nil, nil)
	reader := seedScopedToken(t, h.store, h.tenant, "agents:read")
	beat := func(agentTime time.Time) *transport.HeartbeatResponse {
		t.Helper()
		req := &transport.HeartbeatRequest{Version: "a194", Status: "active"}
		if !agentTime.IsZero() {
			req.AgentTimeUnixMilli = agentTime.UnixMilli()
		}
		resp, err := h.client.Heartbeat(ctx, req)
		if err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		return resp
	}
	clock := func() (state string, skew float64, detail string) {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", reader, nil)
		var list struct {
			Agents []struct {
				Name      string `json:"name"`
				ClockSkew *struct {
					State       string  `json:"state"`
					SkewSeconds float64 `json:"skew_seconds"`
					Detail      string  `json:"detail"`
				} `json:"clock_skew"`
			} `json:"agents"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("agent list = %d %s", code, body)
		}
		for _, agent := range list.Agents {
			if agent.Name == h.agent && agent.ClockSkew != nil {
				return agent.ClockSkew.State, agent.ClockSkew.SkewSeconds, agent.ClockSkew.Detail
			}
		}
		return "", 0, ""
	}
	gauge := func() string {
		t.Helper()
		if err := h.srv.sampleAgentFleetHealth(ctx); err != nil {
			t.Fatal(err)
		}
		var prom strings.Builder
		if err := h.srv.registry.WriteProm(&prom); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(prom.String(), "\n") {
			if strings.HasPrefix(line, "trstctl_agents_clock_skewed_total ") {
				return strings.TrimPrefix(line, "trstctl_agents_clock_skewed_total ")
			}
		}
		return "absent"
	}

	if state, _, _ := clock(); state != "" {
		t.Fatalf("an agent that never sent its clock has a clock finding: %q", state)
	}
	ahead := beat(time.Now().Add(7 * time.Minute))
	if !ahead.ClockSkewWarning || math.Abs(float64(time.Now().UnixMilli()-ahead.ServerTimeUnixMilli)) > 10_000 {
		t.Fatalf("heartbeat answer = %+v; want the control plane's time and a clock-skew warning", ahead)
	}
	state, skew, detail := clock()
	if state != "warning" || skew < 410 || skew > 430 || !strings.Contains(detail, "ahead of the control plane") {
		t.Fatalf("clock finding = %q %.1fs %q; want a warning about seven minutes ahead", state, skew, detail)
	}
	if got := gauge(); got != "1" {
		t.Fatalf("trstctl_agents_clock_skewed_total = %s, want 1", got)
	}
	var recorded projections.AgentHeartbeat
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == projections.EventAgentHeartbeat && e.TenantID == h.tenant && e.SchemaVersion == projections.AgentHeartbeatClockSchemaVersion {
			return json.Unmarshal(e.Data, &recorded)
		}
		return nil
	}); err != nil || recorded.AgentTimeUnixMilli == 0 {
		t.Fatalf("no schema-6 heartbeat carried the agent's clock: %+v, %v", recorded, err)
	}

	if agrees := beat(time.Now()); agrees.ClockSkewWarning {
		t.Fatal("an agreeing clock was warned")
	}
	if state, skew, _ := clock(); state != "ok" || math.Abs(skew) > 10 {
		t.Fatalf("clock finding after the fix = %q %.1fs", state, skew)
	}
	if got := gauge(); got != "0" {
		t.Fatalf("trstctl_agents_clock_skewed_total after the fix = %s, want 0", got)
	}
	if old := beat(time.Time{}); old.ClockSkewWarning || old.ServerTimeUnixMilli == 0 {
		t.Fatalf("a heartbeat without a clock reading = %+v", old)
	}
	if state, _, _ := clock(); state != "unreported" {
		t.Fatalf("clock finding after a heartbeat without a reading = %q, want unreported", state)
	}
}
