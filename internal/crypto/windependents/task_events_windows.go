// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unsafe"
)

var nativeTaskEventsDLL = windows.NewLazySystemDLL("wevtapi.dll")

func closeTaskEvent(handle uintptr) {
	if handle != 0 {
		_, _, _ = nativeTaskEventsDLL.NewProc("EvtClose").Call(handle)
	}
}
func taskEventsEnabled() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	path, err := windows.UTF16PtrFromString(nativeTaskChannel)
	if err != nil {
		return err
	}
	config, _, _ := nativeTaskEventsDLL.NewProc("EvtOpenChannelConfig").Call(0, uintptr(unsafe.Pointer(path)), 0) // #nosec G103 -- fixed local scheduler channel; live UTF-16 public path and native handle (CWE-242)
	if config == 0 {
		return errors.New("windows task: operational log configuration unavailable")
	}
	defer closeTaskEvent(config)
	var value taskEventVariant
	var used uint32
	ok, _, _ := nativeTaskEventsDLL.NewProc("EvtGetChannelConfigProperty").Call(config, 0, 0, unsafe.Sizeof(value), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&used))) // #nosec G103 -- exact 16-byte EVT_VARIANT output and size for the fixed Enabled property (CWE-242)
	if ok == 0 || used != 16 {
		return errors.New("windows task: operational log enabled state unavailable")
	}
	enabled, err := value.boolean()
	if err != nil || !enabled {
		return errors.New("windows task: operational log must be enabled by the host operator before verification")
	}
	return nil
}
func taskEventPointerOffset(raw []byte, value taskEventVariant, need int) (int, error) {
	if value.Count != 0 || need < 0 || need > len(raw) || len(raw) == 0 {
		return 0, errors.New("windows task: invalid native metadata view")
	}
	pointer := uintptr(value.Value)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		pointer = uintptr(value.Value & 0xffffffff)
	}
	base := uintptr(unsafe.Pointer(&raw[0])) // #nosec G103 -- owned nonempty bounded native render buffer; only checked offset arithmetic (CWE-242)
	if pointer < base || pointer-base > uintptr(len(raw)-need) {
		return 0, errors.New("windows task: native metadata pointer escaped its render buffer")
	}
	return int(pointer - base), nil
}
func taskEventText(raw []byte, value taskEventVariant) (string, error) {
	if value.Type != 1 || value.Count != 0 {
		return "", errors.New("windows task: native event text has an unexpected type")
	}
	offset, err := taskEventPointerOffset(raw, value, 2)
	if err != nil {
		return "", err
	}
	wide, err := nativeWideBytes(raw, offset, false)
	if err != nil {
		return "", err
	}
	return publicNativeText(wide)
}
func taskEventInstance(raw []byte, value taskEventVariant) (string, error) {
	if value.Type == 1 {
		return taskEventText(raw, value)
	}
	if value.Type != 15 || value.Count != 0 {
		return "", errors.New("windows task: native event instance has an unexpected type")
	}
	offset, err := taskEventPointerOffset(raw, value, 16)
	if err != nil {
		return "", err
	}
	data := raw[offset : offset+16]
	guid := windows.GUID{Data1: binary.LittleEndian.Uint32(data), Data2: binary.LittleEndian.Uint16(data[4:]), Data3: binary.LittleEndian.Uint16(data[6:])}
	copy(guid.Data4[:], data[8:])
	return guid.String(), nil
}
func resolveNativeTaskSID(account string) (string, error) {
	switch strings.ToLower(account) {
	case "system", "localsystem", "nt authority\\system":
		return "S-1-5-18", nil
	case "localservice", "nt authority\\localservice":
		return "S-1-5-19", nil
	case "networkservice", "nt authority\\networkservice":
		return "S-1-5-20", nil
	}
	if strings.HasPrefix(account, "S-") {
		value, err := windows.StringToSid(account)
		if err != nil {
			return "", errors.New("windows task: native account SID is invalid")
		}
		return value.String(), nil
	}
	value, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return "", errors.New("windows task: native account SID could not be resolved")
	}
	return value.String(), nil
}
func taskEventAccountSID(raw []byte, value taskEventVariant) (string, error) {
	if value.Type == 1 {
		account, err := taskEventText(raw, value)
		if err != nil {
			return "", err
		}
		return resolveNativeTaskSID(account)
	}
	if value.Type != 19 || value.Count != 0 {
		return "", errors.New("windows task: native start account has an unexpected type")
	}
	offset, err := taskEventPointerOffset(raw, value, 8)
	if err != nil {
		return "", err
	}
	count := int(raw[offset+1])
	if raw[offset] != 1 || count > 15 || offset+8+4*count > len(raw) {
		return "", errors.New("windows task: native start SID exceeds its buffer")
	}
	sid := (*windows.SID)(unsafe.Pointer(&raw[offset])) // #nosec G103 -- complete SID revision/subauthority length is checked inside the live owned render buffer (CWE-242)
	if !sid.IsValid() {
		return "", errors.New("windows task: invalid native start SID")
	}
	return sid.String(), nil
}
func taskEventResult(raw []byte, value taskEventVariant) (uint32, bool, error) {
	if value.Type == 0 && value.Count == 0 {
		return 0, false, nil
	}
	if value.Type == 1 {
		text, err := taskEventText(raw, value)
		if err != nil {
			return 0, false, err
		}
		radix := 10
		if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
			radix = 16
			text = text[2:]
		}
		result, err := strconv.ParseUint(text, radix, 32)
		if err != nil {
			return 0, false, errors.New("windows task: invalid native action result")
		}
		return uint32(result & 0xffffffff), true, nil
	}
	result, err := value.unsigned()
	if err != nil || result > 0xffffffff {
		return 0, false, errors.New("windows task: invalid native action result type")
	}
	return uint32(result & 0xffffffff), true, nil
}

var taskEventValuePaths = []string{"Event/System/EventID", "Event/System/EventRecordID", "Event/EventData/Data[@Name='TaskName']", "Event/EventData/Data[@Name='UserContext']", "Event/EventData/Data[@Name='InstanceId']", "Event/EventData/Data[@Name='TaskInstanceId']", "Event/EventData/Data[@Name='ResultCode']"}

func taskEventRenderContext() (uintptr, error) {
	paths := make([]*uint16, len(taskEventValuePaths))
	for i, path := range taskEventValuePaths {
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return 0, err
		}
		paths[i] = wide
	}
	handle, _, _ := nativeTaskEventsDLL.NewProc("EvtCreateRenderContext").Call(7, uintptr(unsafe.Pointer(&paths[0])), 0) // #nosec G103 -- seven fixed metadata-only XPath selectors, live through synchronous context creation (CWE-242)
	runtime.KeepAlive(paths)
	if handle == 0 {
		return 0, errors.New("windows task: selected event metadata context unavailable")
	}
	return handle, nil
}
func renderNativeTaskEvent(contextHandle, eventHandle uintptr) (nativeTaskEvent, error) {
	held, err := secret.New(64 << 10)
	if err != nil {
		return nativeTaskEvent{}, err
	}
	defer held.Destroy()
	raw := held.Bytes()
	var used, count uint32
	ok, _, _ := nativeTaskEventsDLL.NewProc("EvtRender").Call(contextHandle, eventHandle, 0, 64<<10, uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count))) // #nosec G103 -- owned locked 64 KiB buffer and sized metadata-only EVT_VARIANT outputs (CWE-242)
	if ok == 0 || count != 7 || used < 7*16 || used > 64<<10 {
		return nativeTaskEvent{}, errors.New("windows task: selected native event metadata exceeded its bound")
	}
	values := unsafe.Slice((*taskEventVariant)(unsafe.Pointer(&raw[0])), 7) // #nosec G103 -- exact seven 16-byte native variants validated against returned property count and buffer length (CWE-242)
	id, err := values[0].unsigned()
	if err != nil || (id != 100 && id != 102 && id != 201) {
		return nativeTaskEvent{}, errors.New("windows task: unexpected native completion event")
	}
	record, err := values[1].unsigned()
	if err != nil || record == 0 {
		return nativeTaskEvent{}, errors.New("windows task: native event record identity missing")
	}
	path, err := taskEventText(raw, values[2])
	if err != nil {
		return nativeTaskEvent{}, err
	}
	instanceValue := values[4]
	if id == 201 {
		instanceValue = values[5]
	}
	instance, err := taskEventInstance(raw, instanceValue)
	if err != nil {
		return nativeTaskEvent{}, err
	}
	event := nativeTaskEvent{EventID: uint32(id & 0xffffffff), RecordID: record, Path: path, InstanceID: instance}
	if id == 100 {
		event.AccountSID, err = taskEventAccountSID(raw, values[3])
		if err != nil {
			return nativeTaskEvent{}, err
		}
	}
	if id == 201 {
		event.ResultCode, event.ResultPresent, err = taskEventResult(raw, values[6])
		if err != nil {
			return nativeTaskEvent{}, err
		}
	}
	return event, nil
}
func readNativeTaskEvents(ctx context.Context, instance string) ([]nativeTaskEvent, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	query, err := taskEventQuery(instance)
	if err != nil {
		return nil, err
	}
	wide, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}
	handle, _, _ := nativeTaskEventsDLL.NewProc("EvtQuery").Call(0, 0, uintptr(unsafe.Pointer(wide)), 0x101) // #nosec G103 -- validated GUID/fixed schema structured query, local channel only, used and closed on this OS thread (CWE-242)
	if handle == 0 {
		return nil, errors.New("windows task: native completion query failed")
	}
	defer closeTaskEvent(handle)
	renderContext, err := taskEventRenderContext()
	if err != nil {
		return nil, err
	}
	defer closeTaskEvent(renderContext)
	var events []nativeTaskEvent
	for page := 0; page < 9; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var handles [16]uintptr
		var count uint32
		ok, _, nativeErr := nativeTaskEventsDLL.NewProc("EvtNext").Call(handle, 16, uintptr(unsafe.Pointer(&handles[0])), 0, 0, uintptr(unsafe.Pointer(&count))) // #nosec G103 -- fixed 16-handle output array, zero wait and sized count; every returned native event is closed (CWE-242)
		if ok == 0 {
			if errors.Is(nativeErr, windows.ERROR_NO_MORE_ITEMS) || errors.Is(nativeErr, windows.ERROR_TIMEOUT) {
				return events, nil
			}
			return nil, errors.New("windows task: native completion enumeration failed")
		}
		if count == 0 || count > 16 {
			return nil, errors.New("windows task: native completion enumeration returned invalid count")
		}
		var renderErr error
		for i := uint32(0); i < count; i++ {
			if renderErr == nil {
				event, err := renderNativeTaskEvent(renderContext, handles[i])
				if err != nil {
					renderErr = err
				} else {
					events = append(events, event)
				}
			}
			closeTaskEvent(handles[i])
		}
		if renderErr != nil {
			return nil, renderErr
		}
		if len(events) > 128 {
			return nil, errors.New("windows task: native completion evidence exceeds bound")
		}
	}
	return nil, errors.New("windows task: native completion page bound exceeded")
}
