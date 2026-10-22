// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/connector"
)

// KindAgentSelfCheck is the post-upgrade functional check (A71). The campaign
// queues one for each agent that came back on the target build, pinned to
// that agent; the new binary claims it, exercises the parts of itself an
// upgrade can break without stopping the process, and reports a signed
// receipt. A ring verifies only once every agent in it passed, so "running the
// target build and answering" is no longer the whole of verification.
const KindAgentSelfCheck = "agent.self_check"

// SelfCheckIntent is the campaign's question: which build should this agent
// be running. It carries nothing to redeem.
type SelfCheckIntent struct {
	CampaignID    string `json:"campaign_id"`
	Ring          string `json:"ring,omitempty"`
	Round         int    `json:"round,omitempty"`
	TargetVersion string `json:"target_version"`
}

// SelfCheckReport is the agent's answer, carried in the signed receipt's
// detail. Each check names what it exercised and whether it passed; the
// outcome is executed only when every check passed.
type SelfCheckReport struct {
	Version string            `json:"version,omitempty"`
	Checks  []SelfCheckResult `json:"checks"`
}

// SelfCheckResult is one exercised part of the agent.
type SelfCheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Passed reports whether every check passed.
func (r SelfCheckReport) Passed() bool {
	for _, check := range r.Checks {
		if !check.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// runSelfCheck exercises what an upgrade can break without stopping the
// process: that the binary is the one the campaign targets, that a host
// executor's exec profile still names roots and commands that exist on this
// machine, and that the relay's plugin runtime loaded. The claim and the signed
// receipt themselves prove the channel. It redeems nothing.
func runSelfCheck(ctx context.Context, ch Channel, hostProfile connector.LocalOpsConfig, plugins *PluginRuntime, selfUp *SelfUpgrade, job Job) bool {
	var intent SelfCheckIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || strings.TrimSpace(intent.TargetVersion) == "" {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a self-check intent")
		return false
	}
	out := SelfCheckReport{}
	if selfUp != nil {
		out.Version = selfUp.CurrentVersion
	}
	out.Checks = append(out.Checks, selfCheckVersion(out.Version, intent.TargetVersion))
	if len(hostProfile.AllowedRoots) > 0 || len(hostProfile.Actions) > 0 {
		out.Checks = append(out.Checks, selfCheckHostProfile(hostProfile))
	}
	if plugins != nil {
		out.Checks = append(out.Checks, SelfCheckResult{Name: "plugins", OK: true,
			Detail: fmt.Sprintf("%d plugin(s) loaded", len(plugins.Names()))})
	}
	out.Checks = append(out.Checks, SelfCheckResult{Name: "job_channel", OK: true,
		Detail: "claimed over the enrolled channel; this receipt is signed with its key"})
	encoded, err := json.Marshal(out)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "self-check report could not be encoded")
		return false
	}
	if !out.Passed() {
		report(ctx, ch, job, OutcomeFailed, string(encoded))
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(encoded))
	return true
}

func selfCheckVersion(running, target string) SelfCheckResult {
	switch running {
	case "":
		// An agent without the self-upgrade executor does not know its own
		// version here; the control plane scores the version it reported on
		// its heartbeat instead.
		return SelfCheckResult{Name: "version", OK: true, Detail: "version reported on the heartbeat"}
	case target:
		return SelfCheckResult{Name: "version", OK: true, Detail: "running " + running}
	default:
		return SelfCheckResult{Name: "version", OK: false, Detail: "running " + running + "; the campaign targets " + target}
	}
}

// selfCheckHostProfile re-reads the operator's exec allowlist against the
// machine: every allowed root must still be a directory and every absolute
// command must still exist. A build whose profile no longer resolves would
// fail its first deploy, and this says so before one is queued.
func selfCheckHostProfile(profile connector.LocalOpsConfig) SelfCheckResult {
	var problems []string
	for _, root := range profile.AllowedRoots {
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			problems = append(problems, "allowed root "+root+" is not a directory")
		}
	}
	for _, action := range profile.Actions {
		if !filepath.IsAbs(action.Command) {
			continue
		}
		if _, err := os.Stat(action.Command); err != nil {
			problems = append(problems, "command "+action.Command+" for "+action.LogicalName+" is missing")
		}
	}
	if len(problems) > 0 {
		return SelfCheckResult{Name: "host_exec_profile", OK: false, Detail: strings.Join(problems, "; ")}
	}
	return SelfCheckResult{Name: "host_exec_profile", OK: true,
		Detail: fmt.Sprintf("%d allowed root(s) and %d action(s) resolve on this host", len(profile.AllowedRoots), len(profile.Actions))}
}
