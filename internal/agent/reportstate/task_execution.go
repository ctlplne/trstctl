// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

const taskExecutionFile = "task-executions.events"
const maxTaskExecutionBytes = 4 << 20
const maxTaskExecutionFrame = 32 << 10

var ErrTaskExecutionUncertain = errors.New("reportstate: task start was fenced without a retained instance; reconcile without repeating it")

// TaskExecutor separates a native start from read-only instance observation.
type TaskExecutor interface {
	RunAndVerifyRetained(context.Context, windependents.Task, func(string) error) (windependents.TaskRunProof, error)
	ObserveInstance(context.Context, windependents.Task, string) (windependents.TaskRunProof, bool, error)
}
type taskExecutionEvent struct {
	Version  int                         `json:"version"`
	JobID    int64                       `json:"job_id"`
	StepID   string                      `json:"step_id"`
	Phase    string                      `json:"phase"`
	Task     *windependents.Task         `json:"task,omitempty"`
	Instance string                      `json:"instance,omitempty"`
	Proof    *windependents.TaskRunProof `json:"proof,omitempty"`
}
type taskExecutionState struct {
	Task     windependents.Task
	Instance string
	Proof    *windependents.TaskRunProof
}
type taskExecutionProjection struct {
	JobID    int64
	Sequence int
	Bytes    int
	Steps    map[string]*taskExecutionState
}

func taskStepValid(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
func (p *taskExecutionProjection) apply(event taskExecutionEvent) error {
	if event.Version != 1 || event.JobID <= 0 || !taskStepValid(event.StepID) || p.Sequence >= 1536 {
		return ErrInvalidPending
	}
	if p.JobID != 0 && p.JobID != event.JobID {
		return ErrInvalidPending
	}
	state := p.Steps[event.StepID]
	switch event.Phase {
	case "fenced":
		if state != nil || event.Task == nil || event.Instance != "" || event.Proof != nil || len(p.Steps) >= 512 || windependents.ValidateTaskSnapshot(*event.Task) != nil {
			return ErrInvalidPending
		}
		p.Steps[event.StepID] = &taskExecutionState{Task: *event.Task}
	case "started":
		canonical, ok := windependents.CanonicalTaskInstance(event.Instance)
		if state == nil || state.Instance != "" || state.Proof != nil || event.Task != nil || event.Proof != nil || !ok || canonical != event.Instance {
			return ErrInvalidPending
		}
		state.Instance = canonical
	case "completed":
		if state == nil || state.Instance == "" || state.Proof != nil || event.Task != nil || event.Instance != "" || event.Proof == nil || event.Proof.InstanceID != state.Instance || windependents.ValidateTaskRunProof(state.Task, *event.Proof) != nil {
			return ErrInvalidPending
		}
		state.Proof = event.Proof
	default:
		return ErrInvalidPending
	}
	p.JobID = event.JobID
	p.Sequence++
	return nil
}
func (s *Store) taskExecutionAAD(sequence int) []byte {
	return []byte("trstctl.agent.task-execution.v1\x00" + s.binding + "\x00" + strconv.Itoa(sequence))
}
func (s *Store) readTaskExecutions() (*taskExecutionProjection, error) {
	return s.readTaskExecutionsFile(taskExecutionFile)
}
func (s *Store) readTaskExecutionsFile(name string) (*taskExecutionProjection, error) {
	projection := &taskExecutionProjection{Steps: map[string]*taskExecutionState{}}
	info, err := s.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return projection, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxTaskExecutionBytes {
		return nil, ErrInvalidPending
	}
	raw, err := secretfile.Load(filepath.Join(s.path, name))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	projection.Bytes = len(raw)
	for len(raw) > 0 {
		if len(raw) < 4 {
			return nil, ErrInvalidPending
		}
		n := int(binary.LittleEndian.Uint32(raw))
		raw = raw[4:]
		if n < 28 || n > maxTaskExecutionFrame || n > len(raw) {
			return nil, ErrInvalidPending
		}
		var plain []byte
		if err := s.withKey(func(key []byte) error {
			var err error
			plain, err = crypto.AESGCMOpen(key, raw[:n], s.taskExecutionAAD(projection.Sequence))
			return err
		}); err != nil {
			return nil, fmt.Errorf("%w: task execution event cannot be opened", ErrUnopenable)
		}
		var event taskExecutionEvent
		decodeErr := json.Unmarshal(plain, &event)
		secret.Wipe(plain)
		if decodeErr != nil {
			return nil, ErrInvalidPending
		}
		if err := projection.apply(event); err != nil {
			return nil, err
		}
		raw = raw[n:]
	}
	return projection, nil
}
func (s *Store) appendTaskExecution(projection *taskExecutionProjection, event taskExecutionEvent) (err error) {
	if s.closed {
		return fs.ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	sequence := projection.Sequence
	// Validate the transition before appending its source event.
	if err := projection.apply(event); err != nil {
		return err
	}
	plain, err := json.Marshal(event)
	if err != nil {
		return err
	}
	defer secret.Wipe(plain)
	var ciphertext []byte
	if err = s.withKey(func(key []byte) error {
		var err error
		ciphertext, err = crypto.AESGCMSeal(key, plain, s.taskExecutionAAD(sequence))
		return err
	}); err != nil {
		return err
	}
	defer secret.Wipe(ciphertext)
	if len(ciphertext) > maxTaskExecutionFrame || projection.Bytes+4+len(ciphertext) > maxTaskExecutionBytes {
		return errors.New("reportstate: task execution event journal is full")
	}
	defer func() {
		if err != nil {
			s.fault = fmt.Errorf("reportstate: task execution persistence failed; further work refused: %w", err)
		}
	}()
	if info, statErr := s.root.Lstat(taskExecutionFile); statErr == nil && !info.Mode().IsRegular() {
		return ErrInvalidPending
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	file, err := s.root.OpenFile(taskExecutionFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err = secretfile.SecurePrivateFile(filepath.Join(s.path, taskExecutionFile)); err != nil {
		return err
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(ciphertext)&0xffffffff))
	if n, writeErr := file.Write(header[:]); writeErr != nil {
		return writeErr
	} else if n != len(header) {
		return io.ErrShortWrite
	}
	if n, writeErr := file.Write(ciphertext); writeErr != nil {
		return writeErr
	} else if n != len(ciphertext) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return syncDirectory(s.root)
}
func (s *Store) taskExecution(jobID int64, stepID string, task windependents.Task) (*taskExecutionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fs.ErrClosed
	}
	if s.fault != nil {
		return nil, s.fault
	}
	if jobID <= 0 || !taskStepValid(stepID) || windependents.ValidateTaskSnapshot(task) != nil {
		return nil, errors.New("reportstate: exact task execution authority required")
	}
	if archived, found, e := s.readTaskExecutionArchive(jobID); e != nil {
		return nil, e
	} else if found {
		state := archived.Steps[stepID]
		if state == nil || state.Task != task {
			return nil, errors.New("reportstate: archived task job has another frozen step authority")
		}
		return state, nil
	}
	p, err := s.readTaskExecutions()
	if err != nil {
		return nil, err
	}
	if p.JobID != 0 && p.JobID != jobID {
		if !completedTaskExecution(p) {
			return nil, ErrTaskExecutionUncertain
		}
		return nil, errors.New("reportstate: another job owns the task execution journal")
	}
	if state := p.Steps[stepID]; state != nil {
		if state.Task != task {
			return nil, errors.New("reportstate: frozen task authority changed")
		}
		return state, nil
	}
	pending, err := s.read()
	if err != nil {
		return nil, err
	}
	if pending != nil {
		pending.Destroy()
		return nil, errors.New("reportstate: terminal observation must be acknowledged before new task work")
	}
	if err := s.appendTaskExecution(p, taskExecutionEvent{Version: 1, JobID: jobID, StepID: stepID, Phase: "fenced", Task: &task}); err != nil {
		return nil, err
	}
	return nil, nil
}
func (s *Store) recordTaskExecution(event taskExecutionEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fs.ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	p, err := s.readTaskExecutions()
	if err != nil {
		return err
	}
	return s.appendTaskExecution(p, event)
}

// ExecuteTaskOnce fsyncs a start fence before calling Windows. A retained native
// instance is observed after retry; a lost instance reply remains uncertain.
// Only acknowledgement of this job's successful terminal server report retires
// a fully completed journal. Failed reports preserve the original fences.
func (s *Store) ExecuteTaskOnce(ctx context.Context, jobID int64, stepID string, task windependents.Task, executor TaskExecutor) (windependents.TaskRunProof, error) {
	if executor == nil || s == nil {
		return windependents.TaskRunProof{}, errors.New("reportstate: task executor and durable store required")
	}
	if err := ctx.Err(); err != nil {
		return windependents.TaskRunProof{}, err
	}
	if !s.taskMu.TryLock() {
		return windependents.TaskRunProof{}, errors.New("reportstate: task execution worker is busy")
	}
	defer s.taskMu.Unlock()
	state, err := s.taskExecution(jobID, stepID, task)
	if err != nil {
		return windependents.TaskRunProof{}, err
	}
	var proof windependents.TaskRunProof
	if state != nil {
		if state.Proof != nil {
			return *state.Proof, nil
		}
		if state.Instance == "" {
			return proof, ErrTaskExecutionUncertain
		}
		observed, ready, err := executor.ObserveInstance(ctx, task, state.Instance)
		if err != nil {
			return proof, err
		}
		if !ready {
			return proof, errors.New("reportstate: retained task instance has not completed")
		}
		proof = observed
	} else {
		proof, err = executor.RunAndVerifyRetained(ctx, task, func(instance string) error {
			canonical, ok := windependents.CanonicalTaskInstance(instance)
			if !ok {
				return errors.New("reportstate: native task returned invalid instance")
			}
			return s.recordTaskExecution(taskExecutionEvent{Version: 1, JobID: jobID, StepID: stepID, Phase: "started", Instance: canonical})
		})
		if err != nil {
			return windependents.TaskRunProof{}, err
		}
	}
	if err := windependents.ValidateTaskRunProof(task, proof); err != nil {
		return windependents.TaskRunProof{}, err
	}
	if err := s.recordTaskExecution(taskExecutionEvent{Version: 1, JobID: jobID, StepID: stepID, Phase: "completed", Proof: &proof}); err != nil {
		return windependents.TaskRunProof{}, err
	}
	return proof, nil
}
func (s *Store) acknowledgeTaskExecutions(report Observation) error {
	p, err := s.readTaskExecutions()
	if err != nil {
		return err
	}
	if p.JobID == 0 {
		return nil
	}
	if p.JobID != report.JobID {
		return nil
	}
	// A failed native or functional result can be retried by the server.
	// Retain every fence until a successful terminal report is accepted.
	if report.Outcome != "verified" && report.Outcome != "executed" {
		if (report.Outcome == "failed" || report.Outcome == "verify_failed") && completedTaskExecution(p) {
			return s.archiveCompletedTaskExecution(p)
		}
		return nil
	}
	for _, state := range p.Steps {
		if state.Proof == nil {
			return nil
		}
	}
	if err := s.root.Remove(taskExecutionFile); err != nil {
		return err
	}
	return syncDirectory(s.root)
}

func (s *Store) validateTaskExecutionReport(report Observation) error {
	p, err := s.readTaskExecutions()
	if err != nil {
		return err
	}
	if p.JobID == 0 {
		return nil
	}
	if p.JobID != report.JobID {
		// Other host subsystems remain available while this task needs recovery.
		return nil
	}
	if report.Outcome == "verified" || report.Outcome == "executed" {
		for _, state := range p.Steps {
			if state.Proof == nil {
				return errors.New("reportstate: unresolved task start cannot be reported as completed")
			}
		}
	}
	return nil
}
