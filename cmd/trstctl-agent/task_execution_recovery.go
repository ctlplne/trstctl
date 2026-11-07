// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

type taskRecoveryCommand struct {
	Action                   string
	JobID                    int64
	StepID, Instance, Reason string
}
type taskRecoveryResult struct {
	ActiveFences []reportstate.TaskExecutionFence   `json:"active_fences"`
	Recovery     *reportstate.TaskExecutionRecovery `json:"recovery,omitempty"`
	Notice       string                             `json:"notice"`
}

func runTaskExecutionCommand(o agentOptions, command taskRecoveryCommand) ([]byte, error) {
	var observer reportstate.TerminalTaskObserver
	if command.Action == "reconcile" {
		if runtime.GOOS != "windows" {
			return nil, errors.New("native task terminal recovery requires the enrolled Windows host")
		}
		tasks, err := windependents.NewTasks(windependents.TaskExecutionPolicy{})
		if err != nil {
			return nil, err
		}
		observer = tasks
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return taskExecutionCommandFor(ctx, o, command, observer, func() (string, error) {
		current, err := user.Current()
		if err != nil {
			return "", err
		}
		if current.Uid == "" {
			return "", errors.New("local operator identity is unavailable")
		}
		return current.Uid, nil
	})
}

// This path loads only the existing on-disk registration. It never enrolls,
// connects to the control plane, opens a vault credential or executes a task.
func taskExecutionCommandFor(ctx context.Context, o agentOptions, command taskRecoveryCommand, observer reportstate.TerminalTaskObserver, actor func() (string, error)) ([]byte, error) {
	if command.Action != "inspect" && command.Action != "reconcile" {
		return nil, errors.New("task-execution must be inspect or reconcile")
	}
	if command.Action == "inspect" && (command.JobID != 0 || command.StepID != "" || command.Instance != "" || command.Reason != "") {
		return nil, errors.New("task execution inspection takes no reconciliation arguments")
	}
	if o.caBundle == "" || o.commonName == "" || o.keyPath == "" || o.certPath == "" {
		return nil, errors.New("existing --ca-bundle, --name, --key and --cert are required")
	}
	path, err := pendingReportsDir(o)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(o.caBundle)
	if err != nil {
		return nil, fmt.Errorf("read existing CA bundle: %w", err)
	}
	id, err := mtls.LoadAgentIdentity(o.commonName, o.keyPath, o.certPath)
	if err != nil {
		return nil, fmt.Errorf("load existing enrolled identity: %w", err)
	}
	defer id.Destroy()
	serverName := o.serverName
	if serverName == "" {
		serverName = o.commonName
	}
	binding, err := reportIdentityBinding(id, caPEM, serverName)
	id.Destroy() // Only its public registration binding is needed during native observation.
	if err != nil {
		return nil, err
	}
	state, err := reportstate.OpenExisting(path, binding)
	if err != nil {
		return nil, err
	}
	defer func() { _ = state.Close() }()
	result := taskRecoveryResult{Notice: "Original native task outcomes remain unchanged. Preserve the sealed history and inspect active fences before resuming the agent."}
	if command.Action == "reconcile" {
		canonical, ok := windependents.CanonicalTaskInstance(command.Instance)
		if !ok {
			return nil, errors.New("exact existing task instance GUID required")
		}
		if actor == nil {
			return nil, errors.New("local recovery actor is unavailable")
		}
		subject, err := actor()
		if err != nil {
			return nil, err
		}
		recovered, err := state.ReconcileTaskExecution(ctx, command.JobID, command.StepID, canonical, subject, strings.TrimSpace(command.Reason), observer)
		if err != nil {
			return nil, err
		}
		result.Recovery = &recovered
	}
	result.ActiveFences, err = state.TaskExecutionFences(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// A lost start reply pauses dependent mutation claims while keeping explicitly
// selected unrelated job kinds available. Never send an empty filtered slice:
// an empty wire filter means unrestricted claims on the server.
func (r relayChannel) dependentTaskClaimKinds(ctx context.Context, kinds []string) ([]string, bool, error) {
	if r.pending == nil {
		return kinds, false, nil
	}
	fences, err := r.pending.TaskExecutionFences(ctx)
	if err != nil {
		return nil, false, err
	}
	paused := false
	for _, fence := range fences {
		if fence.Instance == "" && fence.Recovery == nil {
			paused = true
			break
		}
	}
	if !paused {
		return kinds, false, nil
	}
	filtered := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		if kind != servicedependents.RotationDestination {
			filtered = append(filtered, kind)
		}
	}
	return filtered, true, nil
}
