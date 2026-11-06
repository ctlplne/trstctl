//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
)

func (nativeServiceDriver) stop(ctx context.Context, expected Service) (Runtime, error) {
	handle, err := openNativeService(expected.Name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP)
	if err != nil {
		return Runtime{}, err
	}
	defer func() { _ = windows.CloseServiceHandle(handle) }()
	snapshot, err := inspectServiceHandle(ctx, handle, expected.Name, expected.AccountSID)
	if err != nil {
		return Runtime{}, err
	}
	defer snapshot.destroy()
	if !sameServiceBinding(expected, snapshot.Service) {
		return Runtime{}, errors.New("windows service: frozen configuration changed before stop")
	}
	status, err := nativeServiceStatus(handle)
	if err != nil {
		return Runtime{}, err
	}
	if !expected.WasRunning {
		if status.CurrentState != windows.SERVICE_STOPPED {
			return Runtime{}, errors.New("windows service: originally stopped state changed")
		}
		return Runtime{}, nil
	}
	if status.CurrentState != windows.SERVICE_STOPPED && status.CurrentState != windows.SERVICE_STOP_PENDING {
		var stopped windows.SERVICE_STATUS
		if err := windows.ControlService(handle, windows.SERVICE_CONTROL_STOP, &stopped); err != nil {
			return Runtime{}, errors.New("windows service: stop refused; selected dependency order requires recovery")
		}
	}
	if _, err = waitServiceState(ctx, handle, windows.SERVICE_STOPPED); err != nil {
		return Runtime{}, err
	}
	return Runtime{}, nil
}
func (nativeServiceDriver) start(ctx context.Context, expected Service) (Runtime, error) {
	handle, err := openNativeService(expected.Name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_START)
	if err != nil {
		return Runtime{}, err
	}
	defer func() { _ = windows.CloseServiceHandle(handle) }()
	snapshot, err := inspectServiceHandle(ctx, handle, expected.Name, expected.AccountSID)
	if err != nil {
		return Runtime{}, err
	}
	defer snapshot.destroy()
	if !sameServiceBinding(expected, snapshot.Service) {
		return Runtime{}, errors.New("windows service: frozen configuration changed before start")
	}
	status, err := nativeServiceStatus(handle)
	if err != nil {
		return Runtime{}, err
	}
	if !expected.WasRunning {
		if status.CurrentState != windows.SERVICE_STOPPED {
			return Runtime{}, errors.New("windows service: originally stopped state changed")
		}
		return Runtime{}, nil
	}
	if status.CurrentState == windows.SERVICE_RUNNING {
		return verifiedServiceProcess(handle, expected.AccountSID)
	}
	if status.CurrentState != windows.SERVICE_STOPPED {
		return Runtime{}, errors.New("windows service: start phase is not stopped or recoverably running")
	}
	if err := ctx.Err(); err != nil {
		return Runtime{}, err
	}
	if err := windows.StartService(handle, 0, nil); err != nil {
		return Runtime{}, errors.New("windows service: native start failed")
	}
	if _, err := waitServiceState(ctx, handle, windows.SERVICE_RUNNING); err != nil {
		return Runtime{}, err
	}
	return verifiedServiceProcess(handle, expected.AccountSID)
}
