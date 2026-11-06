// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"errors"
	"time"
)

type nativeTaskDriver struct{}

func newNativeTaskDriver() taskDriver { return nativeTaskDriver{} }

type nativeTaskSnapshot struct {
	Task
	object, definition, principal *automationObject
	user, sddl                    *automationBSTR
	allowDemand                   bool
}

func (s *nativeTaskSnapshot) destroy() {
	if s.user != nil {
		_ = s.user.destroy()
	}
	if s.sddl != nil {
		_ = s.sddl.destroy()
	}
	s.principal.destroy()
	s.definition.destroy()
	s.object.destroy()
}
func taskRoot(scheduler *automationObject) (*automationObject, error) {
	path, err := newAutomationPublicString("\\")
	if err != nil {
		return nil, err
	}
	defer func() { _ = path.destroy() }()
	return scheduler.object("GetFolder", 1, path.variant())
}
func taskPublicObject(parent *automationObject, method, path string) (*automationObject, error) {
	name, err := newAutomationPublicString(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = name.destroy() }()
	return parent.object(method, 1, name.variant())
}
func snapshotNativeTask(object *automationObject, selectedSID string) (nativeTaskSnapshot, error) {
	snapshot := nativeTaskSnapshot{object: object}
	success := false
	defer func() {
		if !success {
			snapshot.destroy()
		}
	}()
	path, err := object.publicText("Path")
	if err != nil || !validTaskPath(path) {
		return nativeTaskSnapshot{}, errors.New("windows task: invalid native task path")
	}
	snapshot.Path = path
	snapshot.definition, err = object.object("Definition", 2)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	snapshot.principal, err = snapshot.definition.object("Principal", 2)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	logon, err := snapshot.principal.integer("LogonType")
	if err != nil || logon < 0 || logon > 6 {
		return nativeTaskSnapshot{}, errors.New("windows task: native logon type is unreadable")
	}
	snapshot.LogonType = uint32(logon & 0xffffffff)
	snapshot.user, err = snapshot.principal.stringLease("UserId", false)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	user, err := snapshot.user.publicText()
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	if user == "" && (logon == 0 || logon == 4) && selectedSID != "" {
		// A group/empty principal does not store this selected user's password.
		// It cannot be mistaken for a complete selected-account record.
		success = true
		return snapshot, nil
	}
	if user == "" {
		return nativeTaskSnapshot{}, errors.New("windows task: native principal is unreadable; inventory is incomplete")
	}
	sid, err := resolveNativeTaskSID(user)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	snapshot.AccountSID = sid
	if selectedSID != "" && sid != selectedSID {
		success = true
		return snapshot, nil
	}
	if logon == 0 {
		return nativeTaskSnapshot{}, errors.New("windows task: selected native principal has no configured logon type")
	}
	enabled, err := object.boolean("Enabled")
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	snapshot.Enabled = enabled
	settings, err := snapshot.definition.object("Settings", 2)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	defer settings.destroy()
	configuredEnabled, err := settings.boolean("Enabled")
	if err != nil || configuredEnabled != enabled {
		return nativeTaskSnapshot{}, errors.New("windows task: native enabled state differs from its definition")
	}
	snapshot.allowDemand, err = settings.boolean("AllowDemandStart")
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	actions, err := snapshot.definition.object("Actions", 2)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	defer actions.destroy()
	count, err := actions.integer("Count")
	if err != nil || count < 1 || count > 32 {
		return nativeTaskSnapshot{}, errors.New("windows task: native action count exceeds bound")
	}
	snapshot.ActionCount = uint32(count & 0xffffffff)
	descriptor, err := object.call("GetSecurityDescriptor", 1, automationInteger(7))
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	if descriptor.VT != 8 {
		descriptor.destroy()
		return nativeTaskSnapshot{}, errors.New("windows task: native security descriptor unavailable")
	}
	snapshot.sddl, err = takeAutomationBSTR(descriptor.Value, false)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	xml, err := snapshot.definition.stringLease("XmlText", true)
	if err != nil {
		return nativeTaskSnapshot{}, err
	}
	enabledFlag := uint32(0)
	if enabled {
		enabledFlag = 1
	}
	// Close private XML before allocating any password BSTR. The existing native
	// definition object is reused for updates; no XML/arguments become strings.
	snapshot.ConfigSHA256 = nativeConfigurationHash("trstctl/windows-task/config/v1", path, sid, []uint32{snapshot.LogonType, snapshot.ActionCount, enabledFlag}, [][]byte{xml.raw, snapshot.sddl.raw})
	if err := xml.destroy(); err != nil {
		return nativeTaskSnapshot{}, err
	}
	success = true
	return snapshot, nil
}
func withNativeTask(ctx context.Context, path string, run func(*automationObject, *nativeTaskSnapshot) error) error {
	return withAutomation(ctx, func() error {
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
		object, err := taskPublicObject(root, "GetTask", path)
		if err != nil {
			return err
		}
		snapshot, err := snapshotNativeTask(object, "")
		if err != nil {
			return err
		}
		defer snapshot.destroy()
		return run(root, &snapshot)
	})
}
func (nativeTaskDriver) inspect(ctx context.Context, path string) (Task, error) {
	var result Task
	err := withNativeTask(ctx, path, func(_ *automationObject, snapshot *nativeTaskSnapshot) error { result = snapshot.Task; return nil })
	return result, err
}
func (nativeTaskDriver) discover(ctx context.Context, sid string) ([]Task, error) {
	var found []Task
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
		folders, total := 0, 0
		var visit func(*automationObject, int) error
		visit = func(folder *automationObject, depth int) error {
			folders++
			if folders > 512 || depth > 16 {
				return errors.New("windows task: folder census exceeds bound")
			}
			tasks, err := folder.object("GetTasks", 1, automationInteger(1))
			if err != nil {
				return err
			}
			defer tasks.destroy()
			count, err := tasks.integer("Count")
			if err != nil || count < 0 || count > 8192 || int64(total)+count > 8192 {
				return errors.New("windows task: native task census exceeds bound")
			}
			total += int(count)
			for i := uint32(1); i <= uint32(count&0xffffffff); i++ {
				object, err := tasks.object("Item", 2, automationInteger(i))
				if err != nil {
					return err
				}
				snapshot, err := snapshotNativeTask(object, sid)
				if err != nil {
					return err
				}
				if snapshot.AccountSID == sid {
					found = append(found, snapshot.Task)
				}
				snapshot.destroy()
				if len(found) > 256 {
					return errors.New("windows task: selected dependent count exceeds bound")
				}
			}
			children, err := folder.object("GetFolders", 1, automationInteger(0))
			if err != nil {
				return err
			}
			defer children.destroy()
			count, err = children.integer("Count")
			if err != nil || count < 0 || count > 512 {
				return errors.New("windows task: native folder count exceeds bound")
			}
			for i := uint32(1); i <= uint32(count&0xffffffff); i++ {
				child, err := children.object("Item", 2, automationInteger(i))
				if err != nil {
					return err
				}
				err = visit(child, depth+1)
				child.destroy()
				if err != nil {
					return err
				}
			}
			return nil
		}
		return visit(root, 0)
	})
	return found, err
}
func (nativeTaskDriver) update(ctx context.Context, expected Task, password []byte) error {
	return withNativeTask(ctx, expected.Path, func(root *automationObject, snapshot *nativeTaskSnapshot) error {
		if expected.LogonType != 1 || !sameTaskBinding(expected, snapshot.Task) {
			return errors.New("windows task: native authority changed or task does not store a supported password")
		}
		name, err := newAutomationPublicString(expected.Path)
		if err != nil {
			return err
		}
		defer func() { _ = name.destroy() }()
		credential, err := newAutomationPassword(password)
		if err != nil {
			return err
		}
		defer func() { _ = credential.destroy() }()
		// Update only, do not grant an ACE or fire registration triggers. Reuse the
		// existing definition and exact original security descriptor/principal.
		updated, err := root.object("RegisterTaskDefinition", 1, name.variant(), automationVariant{VT: 9, Value: snapshot.definition.pointer}, automationInteger(4|16|32), snapshot.user.variant(), credential.variant(), automationInteger(1), snapshot.sddl.variant())
		if err != nil {
			return err
		}
		if err := credential.destroy(); err != nil {
			updated.destroy()
			return err
		}
		readback, err := snapshotNativeTask(updated, "")
		if err != nil {
			return err
		}
		defer readback.destroy()
		if !sameTaskBinding(expected, readback.Task) {
			return errors.New("windows task: native definition/security readback differs after password update")
		}
		return nil
	})
}
func (nativeTaskDriver) run(ctx context.Context, expected Task) (TaskRunProof, error) {
	var instance string
	err := withNativeTask(ctx, expected.Path, func(_ *automationObject, snapshot *nativeTaskSnapshot) error {
		if expected.LogonType != 1 || !sameTaskBinding(expected, snapshot.Task) || !snapshot.Enabled || !snapshot.allowDemand {
			return errors.New("windows task: frozen native verification action is unavailable")
		}
		if err := taskEventsEnabled(); err != nil {
			return err
		}
		active, err := snapshot.object.object("GetInstances", 1, automationInteger(0))
		if err != nil {
			return err
		}
		count, err := active.integer("Count")
		active.destroy()
		if err != nil || count != 0 {
			return errors.New("windows task: an active instance prevents a fresh verification run; no duplicate execution attempted")
		}
		running, err := snapshot.object.object("Run", 1, automationVariant{})
		if err != nil {
			return &TaskExecutionError{Cause: err}
		}
		defer running.destroy()
		binding, err := running.publicText("InstanceGuid")
		if err != nil {
			return &TaskExecutionError{Cause: errors.New("windows task: execution started without a recoverable instance binding")}
		}
		canonical, ok := canonicalTaskInstance(binding)
		if !ok {
			return &TaskExecutionError{Cause: errors.New("windows task: execution returned an invalid instance binding")}
		}
		instance = canonical
		return nil
	})
	if err != nil {
		return TaskRunProof{}, err
	}
	// Release the Automation apartment/gate before waiting for native completion.
	// Another task or IIS update must not wait behind this task's useful work.
	deadline, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := readNativeTaskEvents(deadline, instance)
		if err != nil {
			return TaskRunProof{}, &TaskExecutionError{InstanceID: instance, Cause: err}
		}
		result, ready, err := taskProofFromEvents(expected, instance, events)
		if err != nil {
			return TaskRunProof{}, &TaskExecutionError{InstanceID: instance, Cause: err}
		}
		if ready {
			return result, nil
		}
		select {
		case <-deadline.Done():
			return TaskRunProof{}, &TaskExecutionError{InstanceID: instance, Cause: errors.New("windows task: execution completion is unproven")}
		case <-ticker.C:
		}
	}
}

func (nativeTaskDriver) observe(ctx context.Context, expected Task, instance string) (TaskRunProof, bool, error) {
	if err := taskEventsEnabled(); err != nil {
		return TaskRunProof{}, false, err
	}
	events, err := readNativeTaskEvents(ctx, instance)
	if err != nil {
		return TaskRunProof{}, false, err
	}
	return taskProofFromEvents(expected, instance, events)
}
