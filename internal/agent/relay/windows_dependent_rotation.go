// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"time"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/servicedependents"
)

var ErrDependentTaskUncertain = errors.New("relay: dependent native task start needs observation, never a blind repeat")

type DependentTaskExecutor interface {
	RunAndVerifyRetained(context.Context, windependents.Task, func(string) error) (windependents.TaskRunProof, error)
	ObserveInstance(context.Context, windependents.Task, string) (windependents.TaskRunProof, bool, error)
}
type DependentTaskJournalChannel interface {
	DependentTaskJournalReady(context.Context, windependents.Task) bool
	ExecuteDependentTaskOnce(context.Context, int64, string, windependents.Task, DependentTaskExecutor) (windependents.TaskRunProof, error)
}
type dependentNativeAdapters struct {
	services interface {
		ObserveForRotation(context.Context, windependents.Service) (windependents.Runtime, error)
		StopForRotation(context.Context, windependents.Service) (windependents.Runtime, error)
		StartAfterRotation(context.Context, windependents.Service) (windependents.Runtime, error)
		UpdatePassword(context.Context, windependents.Service, []byte) error
	}
	tasks interface {
		DependentTaskExecutor
		CheckRotationSnapshot(context.Context, windependents.Task) error
		UpdatePassword(context.Context, windependents.Task, []byte) error
	}
	pools interface {
		CheckRotationSnapshot(context.Context, windependents.Pool) error
		StopForRotation(context.Context, windependents.Pool) (windependents.PoolRestartProof, error)
		StartAfterRotation(context.Context, windependents.Pool, windependents.PoolRestartProof) (windependents.PoolRestartProof, error)
		UpdatePassword(context.Context, windependents.Pool, []byte) error
		VerifyWorkers(context.Context, windependents.Pool, windependents.PoolRestartProof) ([]windependents.PoolWorker, error)
	}
	unsupported bool
}

var dependentRotationSlots = make(chan struct{}, 1)

type primedDependentTask struct {
	DependentTaskExecutor
	probe connector.WindowsDependentProbe
	step  servicedependents.RotationStep
}

func (p primedDependentTask) RunAndVerifyRetained(ctx context.Context, task windependents.Task, retain func(string) error) (windependents.TaskRunProof, error) {
	if _, e := dependentProbeRequest(ctx, p.probe, p.step, "", true); e != nil {
		return windependents.TaskRunProof{}, e
	}
	return p.DependentTaskExecutor.RunAndVerifyRetained(ctx, task, retain)
}
func executeDependentStep(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job, step servicedependents.RotationStep, native dependentNativeAdapters) servicedependents.StepReport {
	report := servicedependents.StepReport{RotationID: step.RotationID, PlanDigest: step.PlanDigest, StepID: step.ID, Direction: step.Direction, Status: "succeeded"}
	fail := func(reason string, uncertain bool) servicedependents.StepReport {
		report.Status = "failed"
		if uncertain {
			report.Status = "uncertain"
		}
		report.Runtime = nil
		report.TaskProof = nil
		report.PoolProof = nil
		report.Functional = nil
		report.Failure = reason
		report.ObservedAt = time.Now().UTC()
		return report
	}
	if e := step.Validate(); e != nil || step.Challenge == "" {
		return fail("native_authority_changed", false)
	}
	probe, e := dependentLocalProbe(profile, step)
	if e != nil {
		return fail("local_grant_absent", false)
	}
	if native.unsupported {
		return fail("native_operation_failed", false)
	}
	bounded, cancel := context.WithDeadline(ctx, step.Deadline)
	defer cancel()
	if e := bounded.Err(); e != nil {
		return fail("deadline_exceeded", false)
	}
	if step.Service != nil && native.services == nil || step.Task != nil && native.tasks == nil || step.Pool != nil && native.pools == nil {
		return fail("native_operation_failed", false)
	}
	if step.Task != nil && step.Task.Enabled && step.Task.LogonType == 1 {
		journal, ok := ch.(DependentTaskJournalChannel)
		if !ok {
			return fail("local_grant_absent", false)
		}
		if step.Action == servicedependents.Preflight && !journal.DependentTaskJournalReady(bounded, *step.Task) {
			return fail("task_start_uncertain", true)
		}
	}
	switch step.Action {
	case servicedependents.Preflight:
		if step.Service != nil {
			value, err := native.services.ObserveForRotation(bounded, *step.Service)
			e = err
			report.Runtime = &value
		}
		if step.Task != nil {
			e = native.tasks.CheckRotationSnapshot(bounded, *step.Task)
		}
		if step.Pool != nil {
			e = native.pools.CheckRotationSnapshot(bounded, *step.Pool)
			report.Runtime = &windependents.Runtime{Running: step.Pool.WasStarted, AccountSID: step.AccountSID}
		}
	case servicedependents.Stop:
		if step.Service != nil {
			value, err := native.services.StopForRotation(bounded, *step.Service)
			e = err
			report.Runtime = &value
		}
		if step.Pool != nil {
			value, err := native.pools.StopForRotation(bounded, *step.Pool)
			e = err
			report.PoolProof = &value
		}
	case servicedependents.Update:
		// A service/pool write uses a stopped snapshot. Native implementations
		// recheck stopped state on their mutation handle, closing the read/write gap.
		if step.Service != nil {
			copy := *step.Service
			copy.WasRunning = false
			_, e = native.services.ObserveForRotation(bounded, copy)
		}
		if step.Pool != nil {
			copy := *step.Pool
			copy.WasStarted = false
			e = native.pools.CheckRotationSnapshot(bounded, copy)
		}
		if step.Task != nil {
			e = native.tasks.CheckRotationSnapshot(bounded, *step.Task)
		}
		if e != nil {
			return fail("native_authority_changed", false)
		}
		material, err := ch.RedeemJobCredential(bounded, job.JobID, job.Attempt)
		if err != nil {
			return fail("native_operation_failed", false)
		}
		defer func() {
			for _, value := range material {
				secret.Wipe(value)
			}
		}()
		value := material[servicedependents.RotationCredentialName]
		if len(material) != 1 || len(value) == 0 {
			return fail("native_operation_failed", false)
		}
		held, err := secret.NewFrom(value)
		secret.Wipe(value)
		if err != nil {
			return fail("native_operation_failed", false)
		}
		defer held.Destroy()
		if step.Service != nil {
			copy := *step.Service
			copy.WasRunning = false
			e = native.services.UpdatePassword(bounded, copy, held.Bytes())
		}
		if step.Pool != nil {
			copy := *step.Pool
			copy.WasStarted = false
			e = native.pools.UpdatePassword(bounded, copy, held.Bytes())
		}
		if step.Task != nil {
			e = native.tasks.UpdatePassword(bounded, *step.Task, held.Bytes())
		}
	case servicedependents.Start:
		if step.Service != nil {
			value, err := native.services.StartAfterRotation(bounded, *step.Service)
			e = err
			report.Runtime = &value
		}
		if step.Pool != nil {
			proof := windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: step.Pool.WasStarted, StoppedObserved: true, PreviousPIDs: step.PreviousPIDs}
			value, err := native.pools.StartAfterRotation(bounded, *step.Pool, proof)
			e = err
			report.PoolProof = &value
		}
	case servicedependents.Probe:
		if !step.Active() {
			if step.Service != nil {
				_, e = native.services.ObserveForRotation(bounded, *step.Service)
			}
			if step.Task != nil {
				e = native.tasks.CheckRotationSnapshot(bounded, *step.Task)
			}
			if step.Pool != nil {
				e = native.pools.CheckRotationSnapshot(bounded, *step.Pool)
			}
			report.Runtime = &windependents.Runtime{}
			break
		}
		var functional servicedependents.FunctionalProof
		if step.Task != nil {
			if step.Task.LogonType == 1 {
				journal := ch.(DependentTaskJournalChannel)
				proof, err := journal.ExecuteDependentTaskOnce(bounded, job.JobID, step.ID, *step.Task, primedDependentTask{DependentTaskExecutor: native.tasks, probe: probe, step: step})
				if err != nil {
					var attempted *windependents.TaskExecutionError
					return fail("task_start_uncertain", errors.Is(err, ErrDependentTaskUncertain) || errors.As(err, &attempted))
				}
				report.TaskProof = &proof
				functional, e = runDependentFunctionalProbe(bounded, probe, step, proof.InstanceID)
			} else {
				// Non-password tasks are observed only; they are never re-registered or
				// explicitly started under a password-task capability.
				functional, e = runDependentFunctionalProbe(bounded, probe, step, "")
				if e == nil {
					proof, ready, err := native.tasks.ObserveInstance(bounded, *step.Task, functional.TaskInstanceID)
					if err != nil || !ready {
						return fail("functional_probe_failed", false)
					}
					report.TaskProof = &proof
				}
			}
		} else {
			functional, e = runDependentFunctionalProbe(bounded, probe, step, "")
			if e == nil && step.Service != nil {
				value, err := native.services.ObserveForRotation(bounded, *step.Service)
				e = err
				report.Runtime = &value
			}
			if e == nil && step.Pool != nil {
				proof := windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: true, StoppedObserved: true, StartedObserved: true, PreviousPIDs: step.PreviousPIDs}
				workers, err := native.pools.VerifyWorkers(bounded, *step.Pool, proof)
				e = err
				if e == nil {
					for _, worker := range workers {
						if worker.ProcessID == functional.ProcessID {
							report.Runtime = &windependents.Runtime{Running: true, ProcessID: worker.ProcessID, AccountSID: worker.AccountSID}
							break
						}
					}
					if report.Runtime == nil {
						e = errors.New("relay: functional work has no matching native pool worker")
					}
				}
				report.PoolProof = &proof
			}
		}
		if e != nil {
			return fail("functional_probe_failed", false)
		}
		report.Functional = &functional
	}
	if e != nil {
		return fail("native_operation_failed", false)
	}
	report.ObservedAt = time.Now().UTC()
	if e := report.Validate(step); e != nil {
		return fail("native_operation_failed", false)
	}
	return report
}
func runWindowsDependentRotation(ctx context.Context, ch Channel, profile connector.LocalOpsConfig, job Job) bool {
	step, e := servicedependents.DecodeRotationStep(job.Payload)
	if e != nil {
		report(ctx, ch, job, OutcomeFailed, "native dependent rotation intent is invalid")
		return false
	}
	select {
	case dependentRotationSlots <- struct{}{}:
		defer func() { <-dependentRotationSlots }()
	default:
		report(ctx, ch, job, OutcomeFailed, "native dependent rotation worker is busy")
		return false
	}
	native := dependentNativeAdapters{unsupported: runtime.GOOS != "windows"}
	if !native.unsupported {
		tasks, e := windependents.NewTasks(windependents.TaskExecutionPolicy{VerificationPaths: []string{}})
		if step.Task != nil && step.Task.LogonType == 1 {
			tasks, e = windependents.NewTasks(windependents.TaskExecutionPolicy{VerificationPaths: []string{step.Task.Path}})
		}
		if e != nil {
			report(ctx, ch, job, OutcomeFailed, "native dependent task authority is unavailable")
			return false
		}
		native.services = windependents.NewServices()
		native.tasks = tasks
		native.pools = windependents.NewPools()
	}
	value := executeDependentStep(ctx, ch, profile, job, step, native)
	raw, e := json.Marshal(value)
	if e != nil {
		report(ctx, ch, job, OutcomeFailed, "native dependent result could not be encoded")
		return false
	}
	outcome := OutcomeExecuted
	if value.Status != "succeeded" {
		outcome = OutcomeFailed
	}
	reportWithEvidence(ctx, ch, job, outcome, string(raw), crypto.SHA256Hex(raw))
	return value.Status == "succeeded"
}
