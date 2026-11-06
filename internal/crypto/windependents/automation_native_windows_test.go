// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf16"
	"unsafe"
)

func TestNativeAutomationBoundaryA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_WINDOWS_AUTOMATION") != "1" {
		t.Skip("native Automation proof not requested")
	}
	password := []byte("Tr5!owned-café-密碼-🙂")
	defer secret.Wipe(password)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	err := withAutomation(ctx, func() error {
		private, err := newAutomationPassword(password)
		if err != nil {
			return err
		}
		defer func() { _ = private.destroy() }()
		expected := utf16.Encode([]rune(string(password))) // synthetic owned fixture only; production never creates a password string
		if len(private.raw) != (len(expected)+1)*2 {
			return errors.New("owned native BSTR length differs")
		}
		for i, unit := range expected {
			if automationUTF16Unit(private.raw, i) != unit {
				return errors.New("owned native BSTR encoding differs")
			}
		}
		if duplicate, err := newAutomationPassword(password); err == nil {
			_ = duplicate.destroy()
			return errors.New("nested private native lease did not reject promptly")
		}
		type workingSetInfo struct{ Address, Flags uintptr }
		info := workingSetInfo{Address: private.pointer}
		ok, _, _ := windows.NewLazySystemDLL("psapi.dll").NewProc("QueryWorkingSetEx").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)) // #nosec G103 -- exact PSAPI output for the current process and live locked owned BSTR, no material is copied (CWE-242)
		if ok == 0 || info.Flags&1 == 0 || info.Flags&(1<<22) == 0 {
			return errors.New("owned native password BSTR was not locked")
		}
		if err := private.destroy(); err != nil {
			return err
		}
		if err := private.destroy(); err != nil || private.pointer != 0 || private.raw != nil {
			return errors.New("owned native password BSTR release was not idempotent")
		}
		scheduler, err := newLocalTaskScheduler(ctx)
		if err != nil {
			return err
		}
		defer scheduler.destroy()
		if connected, err := scheduler.boolean("Connected"); err != nil || !connected {
			return errors.New("local native Task Scheduler did not connect")
		}
		rootName, err := newAutomationPublicString("\\")
		if err != nil {
			return err
		}
		defer func() { _ = rootName.destroy() }()
		folder, err := scheduler.object("GetFolder", 1, rootName.variant())
		if err != nil {
			return err
		}
		defer folder.destroy()
		if path, err := folder.publicText("Path"); err != nil || path != "\\" {
			return errors.New("local native Task Scheduler root binding differs")
		}
		tasks, err := folder.object("GetTasks", 1, automationInteger(1))
		if err != nil {
			return err
		}
		defer tasks.destroy()
		if count, err := tasks.integer("Count"); err != nil || count < 0 || count > 8192 {
			return errors.New("local native Task Scheduler count exceeds bound")
		}
		// Exercise property assignment only on an unregistered in-memory definition.
		definition, err := scheduler.object("NewTask", 1, automationInteger(0))
		if err != nil {
			return err
		}
		defer definition.destroy()
		settings, err := definition.object("Settings", 2)
		if err != nil {
			return err
		}
		defer settings.destroy()
		if err := settings.set("Enabled", automationNativeBool(false)); err != nil {
			return err
		}
		if enabled, err := settings.boolean("Enabled"); err != nil || enabled {
			return errors.New("native Automation property put was not read back")
		}
		if err := settings.set("Enabled", automationNativeBool(true)); err != nil {
			return err
		}
		if enabled, err := settings.boolean("Enabled"); err != nil || !enabled {
			return errors.New("native Automation property restoration failed")
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
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		publicPath, err := newAutomationPublicString(executable)
		if err != nil {
			return err
		}
		defer func() { _ = publicPath.destroy() }()
		if err := action.set("Path", publicPath.variant()); err != nil {
			return err
		}
		// No task is registered or run; only serialize this owned definition.
		xml, err := definition.stringLease("XmlText", true)
		if err != nil {
			return err
		}
		defer func() { _ = xml.destroy() }()
		if len(xml.raw) == 0 {
			return errors.New("native definition produced no private XML")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if err := withAutomation(canceled, func() error { t.Error("canceled Automation session ran"); return nil }); err == nil {
		t.Fatal("canceled native session admitted")
	}
	t.Log("A267_WINDOWS_AUTOMATION_OK: locked native BSTR, strict Automation, local read-only scheduler and in-memory definition; task rotation is separate")
}
