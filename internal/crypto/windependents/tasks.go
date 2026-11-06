// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf8"
)

type Task struct {
	Path         string `json:"path"`
	AccountSID   string `json:"account_sid"`
	ConfigSHA256 string `json:"config_sha256"`
	Enabled      bool   `json:"enabled"`
	LogonType    uint32 `json:"logon_type"`
	ActionCount  uint32 `json:"action_count"`
}
type TaskExecutionPolicy struct{ VerificationPaths []string }
type TaskActionResult struct {
	RecordID   uint64 `json:"record_id"`
	ResultCode uint32 `json:"result_code"`
}

// TaskRunProof binds success to native start, action and completion records for
// one fresh instance. A previous/global LastTaskResult cannot satisfy it.
type TaskRunProof struct {
	Path               string             `json:"path"`
	AccountSID         string             `json:"account_sid"`
	InstanceID         string             `json:"instance_id"`
	StartRecordID      uint64             `json:"start_record_id"`
	CompletionRecordID uint64             `json:"completion_record_id"`
	Actions            []TaskActionResult `json:"actions"`
}
type taskDriver interface {
	discover(context.Context, string) ([]Task, error)
	inspect(context.Context, string) (Task, error)
	update(context.Context, Task, []byte) error
	run(context.Context, Task) (TaskRunProof, error)
}
type Tasks struct {
	driver       taskDriver
	verification map[string]bool
}

func NewTasks(policy TaskExecutionPolicy) (*Tasks, error) {
	return newTasks(newNativeTaskDriver(), policy)
}
func newTasks(driver taskDriver, policy TaskExecutionPolicy) (*Tasks, error) {
	if len(policy.VerificationPaths) > 256 {
		return nil, errors.New("windows task: verification allowlist exceeds bound")
	}
	allowed := map[string]bool{}
	for _, path := range policy.VerificationPaths {
		key := strings.ToLower(path)
		if !validTaskPath(path) || allowed[key] {
			return nil, errors.New("windows task: invalid/duplicate verification authorization")
		}
		allowed[key] = true
	}
	return &Tasks{driver: driver, verification: allowed}, nil
}
func validTaskPath(path string) bool {
	if len(path) < 2 || len(path) > 1024 || !utf8.ValidString(path) || path[0] != '\\' || strings.Contains(path, "/") {
		return false
	}
	parts := strings.Split(path[1:], "\\")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || len(part) > 256 {
			return false
		}
		for _, r := range part {
			if r < 32 || r == 127 {
				return false
			}
		}
	}
	return true
}
func validateTask(task Task) error {
	hash, err := hex.DecodeString(task.ConfigSHA256)
	if !validTaskPath(task.Path) || !validAccountSID(task.AccountSID) || err != nil || len(hash) != 32 || task.ConfigSHA256 != strings.ToLower(task.ConfigSHA256) || (task.LogonType < 1 || task.LogonType > 6) || task.ActionCount == 0 || task.ActionCount > 32 {
		return errors.New("windows task: invalid frozen native task authority")
	}
	return nil
}
func sameTaskBinding(left, right Task) bool {
	return left.Path == right.Path && left.AccountSID == right.AccountSID && left.ConfigSHA256 == right.ConfigSHA256 && left.Enabled == right.Enabled && left.LogonType == right.LogonType && left.ActionCount == right.ActionCount
}
func (t *Tasks) Discover(ctx context.Context, sid string) ([]Task, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validAccountSID(sid) {
		return nil, errors.New("windows task: invalid selected account SID")
	}
	tasks, err := t.driver.discover(ctx, sid)
	if err != nil {
		return nil, err
	}
	if len(tasks) > 256 {
		return nil, errors.New("windows task: selected dependent count exceeds bound")
	}
	seen := map[string]bool{}
	for _, task := range tasks {
		key := strings.ToLower(task.Path)
		if validateTask(task) != nil || task.AccountSID != sid || seen[key] {
			return nil, errors.New("windows task: incomplete or inconsistent native inventory")
		}
		seen[key] = true
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].Path < tasks[j].Path })
	return tasks, nil
}
func (t *Tasks) inspectBound(ctx context.Context, task Task) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateTask(task); err != nil {
		return err
	}
	actual, err := t.driver.inspect(ctx, task.Path)
	if err != nil {
		return err
	}
	if !sameTaskBinding(task, actual) {
		return errors.New("windows task: frozen native identity or definition changed")
	}
	return nil
}
func (t *Tasks) UpdatePassword(ctx context.Context, task Task, password []byte) error {
	if task.LogonType != 1 {
		return errors.New("windows task: native logon mode does not store a supported password")
	}
	if err := validateServicePassword(password); err != nil {
		return err
	}
	if err := t.inspectBound(ctx, task); err != nil {
		return err
	}
	held, err := secret.NewFrom(password)
	if err != nil {
		return err
	}
	defer held.Destroy()
	return held.Use(func(value []byte) error { return t.driver.update(ctx, task, value) })
}
func canonicalTaskInstance(value string) (string, bool) {
	if len(value) == 38 && value[0] == '{' && value[len(value)-1] == '}' {
		value = value[1 : len(value)-1]
	}
	if len(value) != 36 {
		return "", false
	}
	compact := make([]byte, 0, 32)
	for i := 0; i < len(value); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return "", false
			}
			continue
		}
		compact = append(compact, value[i])
	}
	decoded, err := hex.DecodeString(string(compact))
	if err != nil || len(decoded) != 16 {
		return "", false
	}
	nonzero := false
	for _, b := range decoded {
		nonzero = nonzero || b != 0
	}
	return strings.ToLower(value), nonzero
}
func validateTaskRunProof(task Task, proof TaskRunProof) error {
	if _, ok := canonicalTaskInstance(proof.InstanceID); !ok || proof.Path != task.Path || proof.AccountSID != task.AccountSID || proof.StartRecordID == 0 || proof.CompletionRecordID <= proof.StartRecordID || len(proof.Actions) != int(task.ActionCount) {
		return errors.New("windows task: missing or foreign per-instance execution proof")
	}
	seen := map[uint64]bool{}
	for _, action := range proof.Actions {
		if action.RecordID <= proof.StartRecordID || action.RecordID >= proof.CompletionRecordID || seen[action.RecordID] || action.ResultCode != 0 {
			return errors.New("windows task: failed or inconsistent native action completion")
		}
		seen[action.RecordID] = true
	}
	return nil
}
func (t *Tasks) RunAndVerify(ctx context.Context, task Task) (TaskRunProof, error) {
	if task.LogonType != 1 || !t.verification[strings.ToLower(task.Path)] || !task.Enabled {
		return TaskRunProof{}, errors.New("windows task: exact local verification execution was not authorized or task is disabled")
	}
	if err := t.inspectBound(ctx, task); err != nil {
		return TaskRunProof{}, err
	}
	proof, err := t.driver.run(ctx, task)
	if err != nil {
		return TaskRunProof{}, err
	}
	if err := validateTaskRunProof(task, proof); err != nil {
		return TaskRunProof{}, &TaskExecutionError{InstanceID: proof.InstanceID, Cause: err}
	}
	return proof, nil
}

// TaskExecutionError means a start was attempted. Retrying RunAndVerify is not
// safe: the caller must retain its durable attempt fence and observe the bound
// instance, or report uncertainty when no instance reply survived.
type TaskExecutionError struct {
	InstanceID string
	Cause      error
}

func (e *TaskExecutionError) Error() string {
	return "windows task: execution was attempted; completion needs observation or recovery, never a blind repeat"
}
func (e *TaskExecutionError) Unwrap() error { return e.Cause }

type taskInstanceObserver interface {
	observe(context.Context, Task, string) (TaskRunProof, bool, error)
}

func (t *Tasks) ObserveInstance(ctx context.Context, task Task, instance string) (TaskRunProof, bool, error) {
	canonical, ok := canonicalTaskInstance(instance)
	if !ok {
		return TaskRunProof{}, false, errors.New("windows task: invalid observation instance")
	}
	if err := t.inspectBound(ctx, task); err != nil {
		return TaskRunProof{}, false, err
	}
	observer, ok := t.driver.(taskInstanceObserver)
	if !ok {
		return TaskRunProof{}, false, errors.New("windows task: native instance observation unavailable")
	}
	proof, ready, err := observer.observe(ctx, task, canonical)
	if err != nil || !ready {
		return TaskRunProof{}, false, err
	}
	if observed, ok := canonicalTaskInstance(proof.InstanceID); !ok || observed != canonical {
		return TaskRunProof{}, false, errors.New("windows task: observed instance differs")
	}
	if err := validateTaskRunProof(task, proof); err != nil {
		return TaskRunProof{}, false, err
	}
	return proof, true, nil
}
