// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"errors"
	"runtime"
	"strings"
)

// A Windows service reload (A238-L3): Windows has no reload signals, so a
// template can name a service the Service Control Manager sends a control.
// serviceReloads says whether this platform offers it, and controlService
// sends one; tests replace both.
var (
	serviceReloads = runtime.GOOS == "windows"
	controlService = sendServiceControl
)

// serviceParamChange is SERVICE_CONTROL_PARAMCHANGE: read your parameters
// again, the Windows counterpart of a reload signal.
const serviceParamChange = 6

// control is the code a service reload sends.
func (h Hook) control() uint32 {
	if h.ServiceControl != 0 {
		return h.ServiceControl
	}
	return serviceParamChange
}

// ways counts how many reload methods the hook names.
func (h Hook) ways() int {
	n := 0
	for _, set := range []bool{len(h.Command) > 0, h.Signal != "", h.Service != ""} {
		if set {
			n++
		}
	}
	return n
}

func (h Hook) validService() error {
	switch {
	case h.ServiceControl != 0 && (h.Service == "" || h.ServiceControl < 128 || h.ServiceControl > 255):
		return errors.New("service_control is a code from 128 to 255 that the named service defines")
	case h.Service == "":
		return nil
	case !serviceReloads:
		return errors.New("reload service is a Windows service control; use a command or a signal here")
	case len(h.Service) > 256 || strings.ContainsAny(h.Service, `/\`):
		return errors.New("reload service is a service name: at most 256 characters, no slashes")
	}
	return nil
}
