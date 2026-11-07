// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"time"
)

func (nativeTaskDriver) observeTerminal(ctx context.Context, expected Task, instance string) (TaskTerminalObservation, bool, error) {
	if err := taskEventsEnabled(); err != nil {
		return TaskTerminalObservation{}, false, err
	}
	events, err := readNativeTaskEvents(ctx, instance)
	if err != nil {
		return TaskTerminalObservation{}, false, err
	}
	proof, ready, err := taskTerminalProofFromEvents(expected, instance, events)
	if err != nil || !ready {
		return TaskTerminalObservation{}, false, err
	}
	// GetInstances is security-context filtered. A zero count from an ordinary
	// token cannot establish quiescence. Check the effective token on the same
	// locked Automation thread that reads the registered task's instances.
	// https://learn.microsoft.com/windows/win32/taskschd/registeredtask-getinstances
	err = withNativeTask(ctx, expected.Path, func(_ *automationObject, snapshot *nativeTaskSnapshot) error {
		if !sameTaskBinding(expected, snapshot.Task) {
			return errors.New("windows task: terminal task configuration changed")
		}
		admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return err
		}
		member, err := windows.Token(0).IsMember(admin)
		if err != nil || !member {
			return errors.New("windows task: full elevated administrator visibility is required for quiescence")
		}
		active, err := snapshot.object.object("GetInstances", 1, automationInteger(0))
		if err != nil {
			return err
		}
		defer active.destroy()
		count, err := active.integer("Count")
		if err != nil || count != 0 {
			return errors.New("windows task: an active or unobservable instance prevents closing the execution fence")
		}
		return nil
	})
	if err != nil {
		return TaskTerminalObservation{}, false, err
	}
	return TaskTerminalObservation{Proof: proof, Quiescent: true, AllInstancesVisible: true, ObservedAt: time.Now().UTC()}, true, nil
}
