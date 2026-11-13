// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// sendServiceControl asks the Service Control Manager to send a service a
// reload control, opening the service with only the right that control needs:
// SERVICE_PAUSE_CONTINUE for PARAMCHANGE, SERVICE_USER_DEFINED_CONTROL for a
// code from 128 to 255. A service that doesn't take the control, or isn't
// running, refuses it, and the reload reports that.
func sendServiceControl(name string, code uint32) error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("secretrender: connect to the service control manager: %w", err)
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("secretrender: service name %q: %w", name, err)
	}
	access := uint32(windows.SERVICE_PAUSE_CONTINUE)
	if code >= 128 {
		access = windows.SERVICE_USER_DEFINED_CONTROL
	}
	service, err := windows.OpenService(scm, wide, access)
	if err != nil {
		return fmt.Errorf("secretrender: open service %s: %w", name, err)
	}
	defer func() { _ = windows.CloseServiceHandle(service) }()
	var status windows.SERVICE_STATUS
	if err := windows.ControlService(service, code, &status); err != nil {
		return fmt.Errorf("secretrender: service %s refused reload control %d: %w", name, code, err)
	}
	return nil
}
