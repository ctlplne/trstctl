// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"unsafe"
)

var nativeTaskWorkDirectory = flag.String("a267-task-work", "", "exact owned native task work directory")

type nativeTaskWorkReceipt struct {
	Nonce  string `json:"nonce"`
	SID    string `json:"sid"`
	PID    uint32 `json:"pid"`
	Result string `json:"result"`
}

func validNativeTaskWorkPath(path string) bool {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || !filepath.IsAbs(path) {
		return false
	}
	name := filepath.Base(path)
	const prefix = "trstctl-a267-task-work-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	decoded, err := hex.DecodeString(suffix)
	return err == nil && len(decoded) == 4 && suffix == strings.ToLower(suffix) && strings.EqualFold(filepath.Clean(path), filepath.Join(root, prefix+suffix))
}
func TestWindowsTaskWorkA267(t *testing.T) {
	if *nativeTaskWorkDirectory == "" {
		t.Skip("native owned task action only")
	}
	path := *nativeTaskWorkDirectory
	if !validNativeTaskWorkPath(path) {
		t.Fatal("invalid owned task work path")
	}
	file, err := os.Open(filepath.Join(path, "nonce")) // #nosec G304 -- fixed public nonce under the exact native ProgramData fixture path with validated random suffix; no credential file (CWE-22)
	if err != nil {
		t.Fatal("owned task nonce unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 33))
	_ = file.Close()
	if err != nil || len(raw) != 32 {
		t.Fatal("owned task nonce invalid")
	}
	if value, err := hex.DecodeString(string(raw)); err != nil || len(value) != 16 {
		t.Fatal("owned task nonce format invalid")
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal("owned task token unavailable")
	}
	user, err := token.GetTokenUser()
	_ = token.Close()
	if err != nil {
		t.Fatal("owned task identity unavailable")
	}
	receipt := nativeTaskWorkReceipt{Nonce: string(raw), SID: user.User.Sid.String(), PID: windows.GetCurrentProcessId(), Result: crypto.SHA256Hex(append([]byte("task-work:"), raw...))}
	wire, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "receipt.json"), wire, 0o600); err != nil {
		t.Fatal("owned task work receipt write failed")
	}
}
func nativeOwnedTaskWorkDirectory(t *testing.T, suffix, sid string) string {
	t.Helper()
	if decoded, err := hex.DecodeString(suffix); err != nil || len(decoded) != 4 || !validAccountSID(sid) {
		t.Fatal("invalid owned task fixture identity")
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "trstctl-a267-task-work-"+suffix)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGWGX;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := windows.CreateDirectory(nativeOwnedWide(t, path), &attributes); err != nil {
		t.Fatal("owned protected task work directory creation failed")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error("owned task work directory cleanup failed")
		}
	})
	return path
}
func nativeTaskNewPublicNonce(t *testing.T, work string) string {
	t.Helper()
	random, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random)
	if err := os.WriteFile(filepath.Join(work, "nonce"), []byte(nonce), 0o600); err != nil {
		t.Fatal(err)
	}
	return nonce
}
func nativeTaskVerifyWork(t *testing.T, work, nonce, sid string) {
	t.Helper()
	if !validNativeTaskWorkPath(work) {
		t.Fatal("invalid owned task receipt path")
	}
	file, err := os.Open(filepath.Join(work, "receipt.json")) // #nosec G304 -- fixed bounded public receipt inside the exclusively created native protected fixture directory, exact path revalidated (CWE-22)
	if err != nil {
		t.Fatal("native task did not produce functional work")
	}
	defer func() { _ = file.Close() }()
	var receipt nativeTaskWorkReceipt
	if err := json.NewDecoder(io.LimitReader(file, 4096)).Decode(&receipt); err != nil || receipt.Nonce != nonce || receipt.SID != sid || receipt.PID == 0 || receipt.Result != crypto.SHA256Hex([]byte("task-work:"+nonce)) {
		t.Fatal("native task work was stale, foreign or incomplete")
	}
}
func nativeCreateOwnedTask(t *testing.T, ctx context.Context, name, account, binary, work string, password []byte) string {
	t.Helper()
	path := "\\" + name
	err := withAutomation(ctx, func() error {
		scheduler, err := newLocalTaskScheduler(ctx)
		if err != nil {
			return err
		}
		defer scheduler.destroy()
		root, err := taskRoot(scheduler)
		if err != nil {
			return err
		}
		defer root.destroy()
		definition, err := scheduler.object("NewTask", 1, automationInteger(0))
		if err != nil {
			return err
		}
		defer definition.destroy()
		principal, err := definition.object("Principal", 2)
		if err != nil {
			return err
		}
		defer principal.destroy()
		username, err := newAutomationPublicString(account)
		if err != nil {
			return err
		}
		defer func() { _ = username.destroy() }()
		if err := principal.set("UserId", username.variant()); err != nil {
			return err
		}
		if err := principal.set("LogonType", automationInteger(1)); err != nil {
			return err
		}
		settings, err := definition.object("Settings", 2)
		if err != nil {
			return err
		}
		defer settings.destroy()
		for _, property := range []string{"Enabled", "AllowDemandStart"} {
			if err := settings.set(property, automationNativeBool(true)); err != nil {
				return err
			}
		}
		for _, property := range []string{"DisallowStartIfOnBatteries", "StopIfGoingOnBatteries"} {
			if err := settings.set(property, automationNativeBool(false)); err != nil {
				return err
			}
		}
		limit, err := newAutomationPublicString("PT1M")
		if err != nil {
			return err
		}
		defer func() { _ = limit.destroy() }()
		if err := settings.set("ExecutionTimeLimit", limit.variant()); err != nil {
			return err
		}
		actions, err := definition.object("Actions", 2)
		if err != nil {
			return err
		}
		defer actions.destroy()
		action, err := actions.object("Create", 1, automationInteger(0))
		if err != nil {
			return err
		}
		defer action.destroy()
		executable, err := newAutomationPublicString(binary)
		if err != nil {
			return err
		}
		defer func() { _ = executable.destroy() }()
		if err := action.set("Path", executable.variant()); err != nil {
			return err
		}
		// Direct native executable arguments contain only owned public paths/flags.
		args, err := newAutomationPublicString("-test.run=^TestWindowsTaskWorkA267$ -a267-task-work=" + syscall.EscapeArg(work))
		if err != nil {
			return err
		}
		defer func() { _ = args.destroy() }()
		if err := action.set("Arguments", args.variant()); err != nil {
			return err
		}
		taskName, err := newAutomationPublicString(name)
		if err != nil {
			return err
		}
		defer func() { _ = taskName.destroy() }()
		credential, err := newAutomationPassword(password)
		if err != nil {
			return err
		}
		defer func() { _ = credential.destroy() }()
		task, err := root.object("RegisterTaskDefinition", 1, taskName.variant(), automationVariant{VT: 9, Value: definition.pointer}, automationInteger(2|32), username.variant(), credential.variant(), automationInteger(1), automationVariant{})
		if err != nil {
			return err
		}
		task.destroy()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := withAutomation(bounded, func() error {
			scheduler, err := newLocalTaskScheduler(bounded)
			if err != nil {
				return err
			}
			defer scheduler.destroy()
			root, err := taskRoot(scheduler)
			if err != nil {
				return err
			}
			defer root.destroy()
			name, err := newAutomationPublicString(path)
			if err != nil {
				return err
			}
			defer func() { _ = name.destroy() }()
			task, err := root.object("GetTask", 1, name.variant())
			if err != nil {
				return err
			}
			value, _ := task.call("Stop", 1, automationInteger(0))
			value.destroy()
			task.destroy()
			value, err = root.call("DeleteTask", 1, name.variant(), automationInteger(0))
			value.destroy()
			return err
		})
		if err != nil {
			t.Error("exact owned task cleanup failed")
		}
	})
	return path
}
func TestNativeWindowsTaskLifecycleA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_WINDOWS_TASKS") != "1" {
		t.Skip("native owned scheduled task lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	if err := taskEventsEnabled(); err != nil {
		t.Fatal(err)
	}
	random, err := crypto.RandomBytes(4)
	if err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random)
	name := "trst267_" + suffix
	taskName := "trstctl-a267-task-" + suffix
	old, next := nativeOwnedPassword(t), nativeOwnedPassword(t)
	sid := nativeCreateOwnedAccount(t, name, old.Bytes())
	nativeGrantOwnedAccountRight(t, sid, "SeBatchLogonRight")
	binary := nativeOwnedServiceBinary(t, suffix, sid.String())
	work := nativeOwnedTaskWorkDirectory(t, suffix, sid.String())
	path := nativeCreateOwnedTask(t, ctx, taskName, ".\\"+name, binary, work, old.Bytes())
	adapter, err := NewTasks(TaskExecutionPolicy{VerificationPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	found, err := adapter.Discover(ctx, sid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Path != path || found[0].LogonType != 1 {
		t.Fatal("native selected-account task discovery differs")
	}
	target := found[0]
	firstNonce := nativeTaskNewPublicNonce(t, work)
	first, err := adapter.RunAndVerify(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	nativeTaskVerifyWork(t, work, firstNonce, sid.String())
	altered := target
	altered.ConfigSHA256 = strings.Repeat("0", 64)
	if err := adapter.UpdatePassword(ctx, altered, next.Bytes()); err == nil {
		t.Fatal("altered native task definition admitted")
	}
	nativeSetOwnedPassword(t, name, next.Bytes())
	if err := adapter.UpdatePassword(ctx, target, next.Bytes()); err != nil {
		t.Fatal(err)
	}
	nextNonce := nativeTaskNewPublicNonce(t, work)
	var retainedInstance string
	second, err := adapter.RunAndVerifyRetained(ctx, target, func(instance string) error {
		retainedInstance = instance
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if retainedInstance == "" || retainedInstance != second.InstanceID {
		t.Fatal("native instance was not retained before completion")
	}
	if second.InstanceID == first.InstanceID {
		t.Fatal("task rotation reused stale instance evidence")
	}
	nativeTaskVerifyWork(t, work, nextNonce, sid.String())
	observed, ready, err := adapter.ObserveInstance(ctx, target, second.InstanceID)
	if err != nil || !ready || observed.CompletionRecordID != second.CompletionRecordID {
		t.Fatal("read-only native instance recovery differs")
	}
	// Observation must not launch another task or replace its work receipt.
	nativeTaskVerifyWork(t, work, nextNonce, sid.String())
	if nativeOwnedSignIn(t, name, old.Bytes()) || !nativeOwnedSignIn(t, name, next.Bytes()) {
		t.Fatal("native task rotation did not refuse/accept exact credentials")
	}
	nativeSetOwnedPassword(t, name, old.Bytes())
	if err := adapter.UpdatePassword(ctx, target, old.Bytes()); err != nil {
		t.Fatal(err)
	}
	restoreNonce := nativeTaskNewPublicNonce(t, work)
	restored, err := adapter.RunAndVerify(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if restored.InstanceID == second.InstanceID {
		t.Fatal("native task recovery reused successor evidence")
	}
	nativeTaskVerifyWork(t, work, restoreNonce, sid.String())
	if !nativeOwnedSignIn(t, name, old.Bytes()) || nativeOwnedSignIn(t, name, next.Bytes()) {
		t.Fatal("native task recovery did not restore/refuse exact credentials")
	}
	t.Log("A267_WINDOWS_TASK_OK: native discovery, frozen definition/ACL, password update, per-instance events, functional work, read-only recovery and predecessor restore; local SAM is not an AD forest")
}
