//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"errors"
)

const nativeIISRoot = "MACHINE/WEBROOT/APPHOST"
const nativeIISPools = "system.applicationHost/applicationPools"

type nativePoolDriver struct{}

func newNativePoolDriver() poolDriver { return nativePoolDriver{} }

type nativePoolSnapshot struct {
	Pool
	object, process, password *automationObject
}

func (s *nativePoolSnapshot) destroy() { s.password.destroy(); s.process.destroy(); s.object.destroy() }
func withIISPools(ctx context.Context, run func(*automationObject, *automationObject) error) error {
	return withIISCollection(ctx, nativeIISPools, run)
}
func withIISCollection(ctx context.Context, sectionID string, run func(*automationObject, *automationObject) error) error {
	if sectionID != nativeIISPools && sectionID != "system.applicationHost/sites" {
		return errors.New("windows pool: native configuration section is not allowlisted")
	}
	return withAutomation(ctx, func() error {
		manager, err := newLocalIISManager(ctx)
		if err != nil {
			return err
		}
		defer manager.destroy()
		sectionName, err := newAutomationPublicString(sectionID)
		if err != nil {
			return err
		}
		defer func() { _ = sectionName.destroy() }()
		root, err := newAutomationPublicString(nativeIISRoot)
		if err != nil {
			return err
		}
		defer func() { _ = root.destroy() }()
		section, err := manager.object("GetAdminSection", 1, sectionName.variant(), root.variant())
		if err != nil {
			return err
		}
		defer section.destroy()
		collection, err := section.object("Collection", 2)
		if err != nil {
			return err
		}
		defer collection.destroy()
		return run(manager, collection)
	})
}
func findNativePool(collection *automationObject, name string) (*automationObject, error) {
	count, err := collection.integer("Count")
	if err != nil || count < 0 || count > 1024 {
		return nil, errors.New("windows pool: native pool census exceeds bound")
	}
	for i := uint32(0); i < uint32(count&0xffffffff); i++ {
		element, err := collection.object("Item", 2, automationInteger(i))
		if err != nil {
			return nil, err
		}
		actual, err := iisPublicProperty(element, "name")
		if err != nil {
			element.destroy()
			return nil, err
		}
		if actual == name {
			return element, nil
		}
		element.destroy()
	}
	return nil, errors.New("windows pool: selected native pool is absent")
}
func snapshotNativePool(object *automationObject, selectedSID string) (nativePoolSnapshot, error) {
	snapshot := nativePoolSnapshot{object: object}
	success := false
	defer func() {
		if !success {
			snapshot.destroy()
		}
	}()
	name, err := iisPublicProperty(object, "name")
	if err != nil || !validPoolName(name) {
		return nativePoolSnapshot{}, errors.New("windows pool: invalid native name")
	}
	snapshot.Name = name
	snapshot.process, err = iisChild(object, "processModel")
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	identity, err := iisIntegerProperty(snapshot.process, "identityType")
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	if identity != 3 {
		if selectedSID != "" {
			success = true
			return snapshot, nil
		}
		return nativePoolSnapshot{}, errors.New("windows pool: native pool does not use a specific password account")
	}
	username, err := iisPublicProperty(snapshot.process, "userName")
	if err != nil || username == "" {
		return nativePoolSnapshot{}, errors.New("windows pool: native account identity unavailable")
	}
	sid, err := resolveNativeTaskSID(username)
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	snapshot.AccountSID = sid
	if selectedSID != "" && sid != selectedSID {
		success = true
		return snapshot, nil
	}
	snapshot.password, err = iisProperty(snapshot.process, "password")
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	snapshot.EncryptionProvider, err = iisPublicMetadata(snapshot.password, "encryptionProvider")
	if err != nil || snapshot.EncryptionProvider == "" {
		return nativePoolSnapshot{}, errors.New("windows pool: native credential encryption provider is unavailable")
	}
	protected, err := iisMetadata(snapshot.password, "isPropertyEncrypted")
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	snapshot.PasswordProtected, err = protected.boolean()
	protected.destroy()
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	state, err := iisIntegerProperty(object, "state")
	if err != nil || (state != 1 && state != 3) {
		return nativePoolSnapshot{}, errors.New("windows pool: transient/unknown state requires rediscovery")
	}
	snapshot.WasStarted = state == 1
	snapshot.ConfigSHA256, err = nativePoolConfigurationHash(snapshot.Pool, object)
	if err != nil {
		return nativePoolSnapshot{}, err
	}
	success = true
	return snapshot, nil
}
func withNativePool(ctx context.Context, name string, run func(*automationObject, *nativePoolSnapshot) error) error {
	return withIISPools(ctx, func(manager, collection *automationObject) error {
		object, err := findNativePool(collection, name)
		if err != nil {
			return err
		}
		snapshot, err := snapshotNativePool(object, "")
		if err != nil {
			return err
		}
		defer snapshot.destroy()
		return run(manager, &snapshot)
	})
}
func (nativePoolDriver) inspect(ctx context.Context, name string) (Pool, error) {
	var pool Pool
	err := withNativePool(ctx, name, func(_ *automationObject, snapshot *nativePoolSnapshot) error { pool = snapshot.Pool; return nil })
	return pool, err
}
func (nativePoolDriver) discover(ctx context.Context, sid string) ([]Pool, error) {
	var found []Pool
	err := withIISPools(ctx, func(_ *automationObject, collection *automationObject) error {
		count, err := collection.integer("Count")
		if err != nil || count < 0 || count > 1024 {
			return errors.New("windows pool: native pool census exceeds bound")
		}
		for i := uint32(0); i < uint32(count&0xffffffff); i++ {
			object, err := collection.object("Item", 2, automationInteger(i))
			if err != nil {
				return err
			}
			snapshot, err := snapshotNativePool(object, sid)
			if err != nil {
				return err
			}
			if snapshot.AccountSID == sid {
				found = append(found, snapshot.Pool)
			}
			snapshot.destroy()
			if len(found) > 256 {
				return errors.New("windows pool: selected dependent count exceeds bound")
			}
		}
		return nil
	})
	return found, err
}
func (driver nativePoolDriver) update(ctx context.Context, expected Pool, password []byte) (Pool, error) {
	err := withNativePool(ctx, expected.Name, func(manager *automationObject, snapshot *nativePoolSnapshot) error {
		if !samePoolBinding(expected, snapshot.Pool) {
			return errors.New("windows pool: native identity/configuration/provider changed before update")
		}
		if !expected.WasStarted && snapshot.WasStarted {
			return errors.New("windows pool: stopped mutation authority changed")
		}
		provider, err := newAutomationPublicString(expected.EncryptionProvider)
		if err != nil {
			return err
		}
		defer func() { _ = provider.destroy() }()
		metadata, err := newAutomationPublicString("encryptionProvider")
		if err != nil {
			return err
		}
		defer func() { _ = metadata.destroy() }()
		value, err := snapshot.password.call("SetMetadata", 1, metadata.variant(), provider.variant())
		if err != nil {
			return err
		}
		value.destroy()
		credential, err := newAutomationPassword(password)
		if err != nil {
			return err
		}
		defer func() { _ = credential.destroy() }()
		if err := snapshot.password.set("Value", credential.variant()); err != nil {
			return err
		}
		value, err = manager.call("CommitChanges", 1)
		value.destroy()
		if err != nil {
			return err
		}
		return credential.destroy()
	})
	if err != nil {
		return Pool{}, err
	}
	// Reopen a new manager after the write, without reading password.Value.
	readback, err := driver.inspect(ctx, expected.Name)
	if err != nil {
		return Pool{}, err
	}
	if !samePoolBinding(expected, readback) || !readback.PasswordProtected {
		return Pool{}, errors.New("windows pool: fresh native encrypted readback differs")
	}
	return readback, nil
}
func executePoolMethod(element *automationObject, name string) error {
	methods, err := element.object("Methods", 2)
	if err != nil {
		return err
	}
	defer methods.destroy()
	key, err := newAutomationPublicString(name)
	if err != nil {
		return err
	}
	defer func() { _ = key.destroy() }()
	method, err := methods.object("Item", 2, key.variant())
	if err != nil {
		return err
	}
	defer method.destroy()
	call, err := method.object("CreateInstance", 1)
	if err != nil {
		return err
	}
	defer call.destroy()
	value, err := call.call("Execute", 1)
	value.destroy()
	return err
}
