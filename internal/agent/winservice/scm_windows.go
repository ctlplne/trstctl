// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package winservice

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// The service's recovery policy: after its first, second and each later
// failure the SCM restarts it after these delays, and the failure count
// resets after a day without one. An error exit counts as a failure, not only
// a crash. The service sets the policy on itself whenever it starts (Run) and
// Install sets it at registration. An MSI cannot carry it: Windows
// Installer's failure-action table opens the service without SERVICE_START,
// which a restart action needs, and the install fails with error 1939.
var recoveryDelays = [...]time.Duration{30 * time.Second, time.Minute, 5 * time.Minute}

const recoveryResetSeconds = 24 * 60 * 60

// Install registers the service described by spec with the Windows Service
// Control Manager. It is the registration the MSI performs via its
// ServiceInstall element; the same call is available for manual installation.
func Install(spec Spec) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("winservice: connect to SCM: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	if existing, err := m.OpenService(spec.Name); err == nil {
		_ = existing.Close()
		return fmt.Errorf("winservice: service %q already exists", spec.Name)
	}

	start := uint32(mgr.StartAutomatic)
	if !spec.AutomaticStart {
		start = uint32(mgr.StartManual)
	}
	s, err := m.CreateService(spec.Name, spec.ExePath, mgr.Config{
		DisplayName: spec.DisplayName,
		Description: spec.Description,
		StartType:   start,
	}, spec.Arguments...)
	if err != nil {
		return fmt.Errorf("winservice: create service %q: %w", spec.Name, err)
	}
	defer func() { _ = s.Close() }()
	if err := applyRecovery(s); err != nil {
		_ = s.Delete()
		return err
	}
	return nil
}

// setRecovery gives the named service its recovery policy, asking the SCM
// only for the rights that takes: SERVICE_CHANGE_CONFIG, and SERVICE_START
// because the actions restart the service.
func setRecovery(name string) error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("winservice: connect to SCM: %w", err)
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winservice: service name %q: %w", name, err)
	}
	h, err := windows.OpenService(scm, n, windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_START)
	if err != nil {
		return fmt.Errorf("winservice: open service %q: %w", name, err)
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer func() { _ = s.Close() }()
	return applyRecovery(s)
}

func applyRecovery(s *mgr.Service) error {
	actions := make([]mgr.RecoveryAction, 0, len(recoveryDelays))
	for _, delay := range recoveryDelays {
		actions = append(actions, mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: delay})
	}
	if err := s.SetRecoveryActions(actions, recoveryResetSeconds); err != nil {
		return fmt.Errorf("winservice: set recovery actions on %q: %w", s.Name, err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("winservice: count error exits as failures on %q: %w", s.Name, err)
	}
	return nil
}

// Uninstall removes the named service from the SCM.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("winservice: connect to SCM: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("winservice: open service %q: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Delete(); err != nil {
		return fmt.Errorf("winservice: delete service %q: %w", name, err)
	}
	return nil
}

// handler adapts the agent's run loop to the svc.Handler contract, translating
// SCM stop/shutdown requests into context cancellation.
type handler struct {
	loop func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.loop(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				status <- svc.Status{State: svc.StopPending}
				<-done
				return false, 0
			default:
			}
		case err := <-done:
			// A clean return is a normal stop. A non-nil error is a service
			// failure, so return a non-zero Win32 exit code. That distinction is
			// what lets the SCM recovery policy restart the agent after a
			// transient first-boot or control-plane failure instead of silently
			// leaving an automatic service stopped.
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

// Run runs the agent loop under the Windows SCM as service name, returning when
// the service is stopped. It first sets the service's recovery policy, before
// the SCM sees it running, so a failure of this first run is covered. That is
// best effort: a service account an administrator has denied the right to
// change its own configuration keeps the policy it was given, and still runs.
func Run(name string, loop func(ctx context.Context) error) error {
	_ = setRecovery(name)
	return svc.Run(name, &handler{loop: loop})
}
