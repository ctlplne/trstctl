// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

type taskRecoveryLostStart struct{ runs int }

func (f *taskRecoveryLostStart) RunAndVerifyRetained(context.Context, windependents.Task, func(string) error) (windependents.TaskRunProof, error) {
	f.runs++
	return windependents.TaskRunProof{}, &windependents.TaskExecutionError{Cause: errors.New("owned lost native reply")}
}
func (f *taskRecoveryLostStart) ObserveInstance(context.Context, windependents.Task, string) (windependents.TaskRunProof, bool, error) {
	return windependents.TaskRunProof{}, false, errors.New("unknown instance cannot be guessed")
}

type taskRecoveryObserver struct{ calls int }

func (f *taskRecoveryObserver) ObserveTerminalInstance(_ context.Context, task windependents.Task, instance string) (windependents.TaskTerminalObservation, bool, error) {
	f.calls++
	now := time.Now().UTC()
	return windependents.TaskTerminalObservation{Proof: windependents.TaskRunProof{Path: task.Path, AccountSID: task.AccountSID, InstanceID: instance, StartedAt: now, CompletedAt: now, StartRecordID: 10, CompletionRecordID: 12, Actions: []windependents.TaskActionResult{{RecordID: 11, ResultCode: 1}}}, Quiescent: true, AllInstancesVisible: true, ObservedAt: time.Now().UTC()}, true, nil
}
func TestAgentTaskRecoveryUsesExistingIdentityAndReadOnlyNativeProofA267(t *testing.T) {
	dir := t.TempDir()
	ca, e := mtls.NewCA("owned-recovery-ca")
	if e != nil {
		t.Fatal(e)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if e = os.WriteFile(caFile, ca.BundlePEM(), 0o600); e != nil {
		t.Fatal(e)
	}
	o := agentOptions{caBundle: caFile, commonName: "owned-task-agent", serverName: "owned-server", keyPath: filepath.Join(dir, "agent.key"), certPath: filepath.Join(dir, "agent.crt")}
	id, e := mtls.GenerateAgentKey(o.commonName)
	if e != nil {
		t.Fatal(e)
	}
	defer id.Destroy()
	csr, e := id.CSR()
	if e != nil {
		t.Fatal(e)
	}
	cert, e := ca.SignClientCSRWithTenant(csr, "owned-task-tenant", []string{mtls.AgentRoleHost}, time.Hour, "https://trstctl.com/agent/tenant-registration/v1/owned-task-tenant/owned-registration")
	if e != nil {
		t.Fatal(e)
	}
	if e = id.UseCertificate(cert); e != nil {
		t.Fatal(e)
	}
	if e = id.Save(o.keyPath, o.certPath); e != nil {
		t.Fatal(e)
	}
	if _, e := taskExecutionCommandFor(t.Context(), o, taskRecoveryCommand{Action: "inspect"}, nil, nil); e == nil {
		t.Fatal("inspection invented missing private report state")
	}
	missingPath, e := pendingReportsDir(o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(missingPath); !os.IsNotExist(e) {
		t.Fatal("inspection created a replacement report directory")
	}
	s, e := openAgentReportState(o, id, ca.BundlePEM(), o.serverName, true)
	if e != nil {
		t.Fatal(e)
	}
	task := windependents.Task{Path: "\\owned\\task", AccountSID: "S-1-5-21-1-2-3-1001", ConfigSHA256: strings.Repeat("a", 64), Enabled: true, LogonType: 1, ActionCount: 1}
	lost := &taskRecoveryLostStart{}
	if _, e = s.ExecuteTaskOnce(t.Context(), 761, "forward", task, lost); e == nil {
		t.Fatal("lost reply became success")
	}
	path, e := pendingReportsDir(o)
	if e != nil {
		t.Fatal(e)
	}
	command := taskRecoveryCommand{Action: "inspect"}
	observer := &taskRecoveryObserver{}
	actor := func() (string, error) { return "owned-local-admin", nil }
	if _, e = taskExecutionCommandFor(t.Context(), o, command, observer, actor); e == nil {
		t.Fatal("recovery bypassed running agent store lock")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	actual := taskInspectionSubprocess(t, o)
	if !strings.Contains(string(actual), `"job_id":761`) || strings.Contains(string(actual), "required --enroll-url") {
		t.Fatal("actual offline entry point lost the existing task fence")
	}
	raw, e := taskExecutionCommandFor(t.Context(), o, command, observer, actor)
	if e != nil || !strings.Contains(string(raw), `"job_id":761`) || observer.calls != 0 {
		t.Fatal("offline inspection lost exact fence or called native mutation", e)
	}
	command = taskRecoveryCommand{Action: "reconcile", JobID: 761, StepID: "forward", Instance: "{A1234567-1234-1234-1234-123456789ABC}", Reason: "observe exact terminal task before inverse"}
	raw, e = taskExecutionCommandFor(t.Context(), o, command, observer, actor)
	if e != nil || !json.Valid(raw) || !strings.Contains(string(raw), `"original_start_unknown":true`) || lost.runs != 1 || observer.calls != 1 {
		t.Fatal("offline recovery did not preserve original uncertainty", e)
	}
	if _, e = taskExecutionCommandFor(t.Context(), o, command, observer, actor); e != nil || observer.calls != 1 {
		t.Fatal("one-shot retry replaced first observation", e)
	}
	changed := o
	changed.serverName = "another-server"
	if _, e = taskExecutionCommandFor(t.Context(), changed, taskRecoveryCommand{Action: "inspect"}, observer, actor); e == nil {
		t.Fatal("other server opened native task history")
	}
	if e = os.Remove(filepath.Join(path, "sealing.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = taskExecutionCommandFor(t.Context(), o, taskRecoveryCommand{Action: "inspect"}, observer, actor); e == nil {
		t.Fatal("missing journal key was replaced")
	}
	if _, e = os.Stat(filepath.Join(path, "sealing.key")); !os.IsNotExist(e) {
		t.Fatal("recovery invented another sealing key")
	}
}

func taskInspectionSubprocess(t *testing.T, o agentOptions) []byte {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	srcRoot, err := os.OpenRoot(filepath.Dir(executable))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srcRoot.Close() }()
	source, err := srcRoot.Open(filepath.Base(executable))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	directory := filepath.Join(filepath.Dir(o.keyPath), "entrypoint-helper")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	destRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = destRoot.Close() }()
	dest, err := destRoot.OpenFile("task-recovery-helper.exe", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(dest, source)
	closeErr := dest.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy current entry-point test binary", copyErr, closeErr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "./task-recovery-helper.exe", "-test.run=^TestAgentCLIArgumentBoundary$", "--", "--task-execution", "inspect", "--name", "owned-task-agent", "--server-name", "owned-server", "--ca-bundle", "../ca.pem", "--key", "../agent.key", "--cert", "../agent.crt")
	child.Dir = directory
	child.Env = append(os.Environ(), "TRSTCTL_TEST_Agent_ARGS_HELPER=1")
	raw, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("actual stopped-agent inspection failed: %v %s", err, raw)
	}
	return raw
}
