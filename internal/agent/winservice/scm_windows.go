// SPDX-License-Identifier: MPL-2.0

//go:build windows

package winservice

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install registers the service described by spec with the Windows Service
// Control Manager. It is the registration the MSI performs via its
// ServiceInstall element; the same call is available for manual installation.
func Install(spec Spec) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("winservice: connect to SCM: %w", err)
	}
	defer m.Disconnect()

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
	defer s.Close()
	return nil
}

// Uninstall removes the named service from the SCM.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("winservice: connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("winservice: open service %q: %w", name, err)
	}
	defer s.Close()
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
		case <-done:
			// The loop exited on its own; report stopped.
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

// Run runs the agent loop under the Windows SCM as service name, returning when
// the service is stopped.
func Run(name string, loop func(ctx context.Context) error) error {
	return svc.Run(name, &handler{loop: loop})
}
