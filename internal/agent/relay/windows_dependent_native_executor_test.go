// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

// The parent owns native SAM/SCM/task/IIS fixtures. This exact test executable
// invokes the shipped receiver without an import cycle through its crypto SDK.
// Credentials travel only through the inherited anonymous pipe, then locked RAM.
type nativeExecutorInput struct {
	SID       string
	Services  []windependents.Service
	Tasks     []windependents.Task
	Pools     []windependents.Pool
	Probes    map[string]string
	StateDir  string
	Failure   string
	Old, Next secret.JSONBytes
}
type nativeExecutorMessage struct {
	Request   string `json:"request"`
	Family    string `json:"family,omitempty"`
	Action    string `json:"action,omitempty"`
	Direction string `json:"direction,omitempty"`
	Status    string `json:"status,omitempty"`
	Failure   string `json:"failure,omitempty"`
}
type nativeExecutorChannel struct {
	Channel
	state    *reportstate.Store
	password *secret.Buffer
}

func (c *nativeExecutorChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	return map[string][]byte{servicedependents.RotationCredentialName: append([]byte(nil), c.password.Bytes()...)}, nil
}
func (c *nativeExecutorChannel) DependentTaskJournalReady(ctx context.Context, task windependents.Task) bool {
	return c.state.TaskExecutionReady(ctx, task) == nil
}
func (c *nativeExecutorChannel) ExecuteDependentTaskOnce(ctx context.Context, jobID int64, stepID string, task windependents.Task, e DependentTaskExecutor) (windependents.TaskRunProof, error) {
	proof, err := c.state.ExecuteTaskOnce(ctx, jobID, stepID, task, e)
	if errors.Is(err, reportstate.ErrTaskExecutionUncertain) {
		err = errors.Join(ErrDependentTaskUncertain, err)
	}
	return proof, err
}
func TestNativeWindowsDependentExecutorChildA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_NATIVE_CHILD") != "1" {
		t.Skip("owned native receiver child only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 2<<20))
	var input nativeExecutorInput
	if decoder.Decode(&input) != nil {
		t.Fatal("native receiver input unavailable")
	}
	old, e := secret.NewFrom(input.Old)
	secret.Wipe(input.Old)
	if e != nil {
		t.Fatal(e)
	}
	defer old.Destroy()
	next, e := secret.NewFrom(input.Next)
	secret.Wipe(input.Next)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Destroy()
	if len(input.Services) != 1 || len(input.Tasks) != 1 || len(input.Pools) != 1 || !windependents.ValidAccountSID(input.SID) {
		t.Fatal("exact owned native fixture required")
	}
	state, e := reportstate.Open(input.StateDir, "a267-native-executor")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := state.Close(); e != nil {
			t.Error("close native fixture report state", e)
		}
	}()
	channel := &nativeExecutorChannel{state: state, password: next}
	taskAdapter, e := windependents.NewTasks(windependents.TaskExecutionPolicy{VerificationPaths: []string{input.Tasks[0].Path}})
	if e != nil {
		t.Fatal(e)
	}
	native := dependentNativeAdapters{services: windependents.NewServices(), tasks: taskAdapter, pools: windependents.NewPools()}
	account := servicedependents.AccountBinding{AccountID: uuid.NewString(), ProviderID: "owned-sam-fixture", Name: "owned", DN: "CN=owned,DC=fixture,DC=test", SID: input.SID, GUID: strings.Repeat("a", 32)}
	binding := servicedependents.HostBinding{Account: account, AgentID: uuid.NewString(), Revision: 1, Enabled: true}
	scan, e := servicedependents.NewInventoryIntent(uuid.NewString(), binding)
	if e != nil {
		t.Fatal(e)
	}
	report := servicedependents.InventoryReport{RunID: scan.RunID, BindingDigest: scan.BindingDigest, ObservedAt: time.Now().UTC(), Services: input.Services, Tasks: input.Tasks, Pools: input.Pools, Coverage: []servicedependents.FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}}}
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	inputs := []servicedependents.RotationHostInput{{Binding: binding, Inventory: report, InventoryDigest: crypto.SHA256Hex(raw)}}
	refs := []servicedependents.DependentRef{{AgentID: binding.AgentID, Family: "services", Name: input.Services[0].Name}, {AgentID: binding.AgentID, Family: "tasks", Name: input.Tasks[0].Path}, {AgentID: binding.AgentID, Family: "iis", Name: input.Pools[0].Name}}
	plan, e := servicedependents.NewRotationPlan(uuid.NewString(), account, "owned/fixture", inputs, refs, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	intent := servicedependents.RotationIntent{Plan: plan, ExpectedVersion: 1, ProviderBinding: strings.Repeat("b", 64)}
	profile := connector.LocalOpsConfig{}
	for _, ref := range refs {
		intent.Probes = append(intent.Probes, servicedependents.ProbeBinding{Ref: ref, ProbeID: ref.Family})
		profile.WindowsDependentWrites = append(profile.WindowsDependentWrites, connector.WindowsDependentWriteGrant{AccountSID: input.SID, Family: ref.Family, Name: ref.Name, ProbeID: ref.Family})
		profile.WindowsDependentProbes = append(profile.WindowsDependentProbes, connector.WindowsDependentProbe{ID: ref.Family, URL: input.Probes[ref.Family]})
	}
	if e = intent.Validate(inputs); e != nil {
		t.Fatal(e)
	}
	send := func(message nativeExecutorMessage) {
		t.Helper()
		raw, e := json.Marshal(message)
		if e != nil {
			t.Fatal(e)
		}
		fmt.Printf("A267_MESSAGE %s\n", raw)
	}
	reset := func(generation string) {
		t.Helper()
		send(nativeExecutorMessage{Request: generation})
		var ack struct{ OK bool }
		if decoder.Decode(&ack) != nil || !ack.OK {
			t.Fatal("owned native reset was not acknowledged")
		}
	}
	var jobID int64
	previous := map[string][]uint32{}
	stopped := map[string][]uint32{}
	failed := false
	execute := func(direction string, preflight bool) {
		t.Helper()
		steps, e := intent.Steps(inputs, direction)
		if e != nil {
			t.Fatal(e)
		}
		for _, step := range steps {
			if (step.Action == servicedependents.Preflight) != preflight {
				continue
			}
			jobID++
			step.Challenge = uuid.NewString()
			step.NotBefore = time.Now().UTC()
			step.Deadline = step.NotBefore.Add(2 * time.Minute)
			if step.Service != nil && (step.Action == servicedependents.Start || step.Action == servicedependents.Probe) {
				step.PreviousPIDs = previous[step.Ref.Family]
			}
			if step.Pool != nil && (step.Action == servicedependents.Start || step.Action == servicedependents.Probe) {
				step.PreviousPIDs = stopped[step.Ref.Family]
			}
			local := profile
			if direction == servicedependents.Forward && step.Ref.Family == "tasks" {
				if input.Failure == "update" && step.Action == servicedependents.Update {
					local.WindowsDependentWrites = nil
				}
				if input.Failure == "functional" && step.Action == servicedependents.Probe {
					local.WindowsDependentProbes = append([]connector.WindowsDependentProbe(nil), profile.WindowsDependentProbes...)
					for i := range local.WindowsDependentProbes {
						if local.WindowsDependentProbes[i].ID == "tasks" {
							local.WindowsDependentProbes[i].URL = input.Probes["failtask"]
						}
					}
				}
			}
			observation := executeDependentStep(ctx, channel, local, Job{JobID: jobID, Attempt: 1}, step, native)
			if e = observation.Validate(step); e != nil {
				t.Fatal("native executor returned invalid evidence", e)
			}
			encoded, e := json.Marshal(observation)
			if e != nil {
				t.Fatal(e)
			}
			outcome := "executed"
			if observation.Status != "succeeded" {
				outcome = "failed"
			}
			terminal := reportstate.Observation{JobID: jobID, Attempt: 1, Outcome: outcome, Detail: encoded, EvidenceDigest: crypto.SHA256Hex(encoded)}
			// Read-only replay of a password-task probe must retain the native instance
			// and leave the independently observed work receipt unchanged.
			if step.Task != nil && step.Action == servicedependents.Probe && observation.Status == "succeeded" {
				repeated := executeDependentStep(ctx, channel, local, Job{JobID: jobID, Attempt: 1}, step, native)
				if repeated.Status != observation.Status || repeated.TaskProof == nil || repeated.TaskProof.InstanceID != observation.TaskProof.InstanceID {
					t.Fatal("native task replay repeated or lost its instance")
				}
			}
			if e = state.Put(terminal); e != nil {
				t.Fatal(e)
			}
			if e = state.Acknowledge(terminal); e != nil {
				t.Fatal(e)
			}
			send(nativeExecutorMessage{Request: "step", Family: step.Ref.Family, Action: step.Action, Direction: direction, Status: observation.Status, Failure: observation.Failure})
			if observation.Status != "succeeded" {
				if direction == servicedependents.Inverse || preflight || input.Failure == "" {
					t.Fatal("unexpected native step failure")
				}
				failed = true
				return
			}
			if step.Service != nil && observation.Runtime != nil && observation.Runtime.ProcessID != 0 && (step.Action == servicedependents.Preflight || step.Action == servicedependents.Probe) {
				previous[step.Ref.Family] = append(previous[step.Ref.Family], observation.Runtime.ProcessID)
			}
			if step.Pool != nil && step.Action == servicedependents.Stop {
				stopped[step.Ref.Family] = observation.PoolProof.PreviousPIDs
			}

		}
	}
	execute(servicedependents.Forward, true)
	reset("reset_new")
	execute(servicedependents.Forward, false)
	if input.Failure != "" {
		if !failed {
			t.Fatal("native injected failure was not reached")
		}
		reset("reset_old")
		channel.password = old
		execute(servicedependents.Inverse, false)
	}
	send(nativeExecutorMessage{Request: "done"})
}
