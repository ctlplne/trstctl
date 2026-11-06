// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"sync"
	"syscall"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf8"
	"unsafe"
)

var automationOLE = windows.NewLazySystemDLL("ole32.dll")
var automationStrings = windows.NewLazySystemDLL("oleaut32.dll")
var automationGate = make(chan struct{}, 1)

// Windows heap pages can contain several BSTRs. Only one private BSTR lease is
// live at a time; freeing public arguments never calls VirtualUnlock.
var privateBSTRGate sync.Mutex
var automationDispatchIID = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var automationNullGUID windows.GUID

type automationBSTR struct {
	pointer uintptr
	raw     []byte
	release func() error
	private bool
}

func automationStringLength(pointer uintptr) uint32 {
	length, _, _ := automationStrings.NewProc("SysStringLen").Call(pointer)
	return uint32(length & 0xffffffff)
}
func freeAutomationBSTR(pointer uintptr) {
	if pointer == 0 {
		return
	}
	// Wipe even an oversized native result before its allocator can cache it.
	// SysStringLen is trusted allocator metadata; each view stays bounded.
	size := uintptr(automationStringLength(pointer))*2 + 2
	for offset := uintptr(0); offset < size; {
		count := size - offset
		if count > (1<<20)-1 {
			count = 1 << 20
		}
		raw := unsafe.Slice((*byte)(unsafe.Add(nil, pointer+offset)), int(count)) // #nosec G103 -- owned native BSTR allocator length, wiped in views no larger than 1 MiB before SysFreeString; no password string (CWE-242)
		secret.Wipe(raw)
		offset += count
	}
	_, _, _ = automationStrings.NewProc("SysFreeString").Call(pointer)
}
func (s *automationBSTR) destroy() error {
	if s.pointer == 0 {
		return nil
	}
	pointer := s.pointer
	s.pointer = 0
	var err error
	if s.release != nil {
		err = s.release()
		s.release = nil
	}
	freeAutomationBSTR(pointer)
	s.raw = nil
	if s.private {
		s.private = false
		privateBSTRGate.Unlock()
	}
	return err
}
func takeAutomationBSTR(pointer uintptr, private bool) (*automationBSTR, error) {
	if pointer == 0 {
		return &automationBSTR{}, nil
	}
	count := automationStringLength(pointer)
	if count > (1<<20)-1 {
		freeAutomationBSTR(pointer)
		return nil, errors.New("windows Automation: native string exceeds bound")
	}
	lease := &automationBSTR{pointer: pointer, private: private}
	if private && !privateBSTRGate.TryLock() {
		freeAutomationBSTR(pointer)
		return nil, errors.New("windows Automation: another private native buffer is still borrowed")
	}
	lease.raw = unsafe.Slice((*byte)(unsafe.Add(nil, pointer)), int(count)*2+2) // #nosec G103 -- owned SysAllocStringLen or COM BSTR, native length capped below 1 Mi UTF-16 units and locked before private use (CWE-242)
	if private {
		release, err := secret.LockNativeWindowsBuffer(lease.raw)
		if err != nil {
			freeAutomationBSTR(pointer)
			privateBSTRGate.Unlock()
			return nil, err
		}
		lease.release = release
	}
	return lease, nil
}
func newAutomationPassword(password []byte) (*automationBSTR, error) {
	wide, err := lockedWindowsPassword(password)
	if err != nil {
		return nil, err
	}
	defer wide.Destroy()
	count := len(wide.Bytes())/2 - 1
	pointer, _, _ := automationStrings.NewProc("SysAllocStringLen").Call(0, uintptr(count))
	if pointer == 0 {
		return nil, errors.New("windows Automation: native password allocation failed")
	}
	lease, err := takeAutomationBSTR(pointer, true)
	if err != nil {
		return nil, err
	}
	copy(lease.raw, wide.Bytes())
	return lease, nil
}
func newAutomationPublicString(value string) (*automationBSTR, error) {
	if len(value) > 1<<20 || !utf8.ValidString(value) {
		return nil, errors.New("windows Automation: public string exceeds bound")
	}
	wide, err := windows.UTF16FromString(value)
	if err != nil {
		return nil, errors.New("windows Automation: invalid public string")
	}
	pointer, _, _ := automationStrings.NewProc("SysAllocStringLen").Call(uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)-1)) // #nosec G103 -- public-only UTF-16 input stays alive through the synchronous native allocation; passwords use a separate locked path (CWE-242)
	runtime.KeepAlive(wide)
	if pointer == 0 {
		return nil, errors.New("windows Automation: native public allocation failed")
	}
	return takeAutomationBSTR(pointer, false)
}
func (s *automationBSTR) variant() automationVariant {
	return automationVariant{VT: 8, Value: s.pointer}
}
func (s *automationBSTR) publicText() (string, error) {
	if len(s.raw) == 0 {
		return "", nil
	}
	return publicNativeText(s.raw[:len(s.raw)-2])
}
func withAutomation(ctx context.Context, run func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case automationGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-automationGate }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, _ := automationOLE.NewProc("CoInitializeEx").Call(0, 0)
	if result != 0 && result != 1 {
		return errors.New("windows Automation: native apartment unavailable")
	}
	defer func() { _, _, _ = automationOLE.NewProc("CoUninitialize").Call() }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return run()
}

type automationObject struct {
	pointer uintptr
	ctx     context.Context
}
type automationDispatchParams struct {
	arguments         *automationVariant
	named             *int32
	count, namedCount uint32
}
type automationException struct {
	code, reserved                uint16
	source, description, helpFile uintptr
	helpContext                   uint32
	reservedPointer, deferred     uintptr
	status                        int32
}

func (e *automationException) destroy() {
	if e.deferred != 0 {
		_, _, _ = syscall.SyscallN(e.deferred, uintptr(unsafe.Pointer(e))) // #nosec G103 -- SDK EXCEPINFO deferred callback receives its live exact output struct; all returned strings are wiped without logging (CWE-242)
		e.deferred = 0
	}
	freeAutomationBSTR(e.source)
	freeAutomationBSTR(e.description)
	freeAutomationBSTR(e.helpFile)
	e.source = 0
	e.description = 0
	e.helpFile = 0
}
func automationFailed(result uintptr) bool { return result&0x80000000 != 0 }
func automationHRESULT(result uintptr) error {
	return fmt.Errorf("windows Automation: native call failed (0x%08x)", result&0xffffffff)
}
func newLocalTaskScheduler(ctx context.Context) (*automationObject, error) {
	name, err := windows.UTF16PtrFromString("Schedule.Service")
	if err != nil {
		return nil, err
	}
	var clsid windows.GUID
	result, _, _ := automationOLE.NewProc("CLSIDFromProgID").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&clsid))) // #nosec G103 -- fixed local Schedule.Service identifier and sized SDK GUID output, no caller-selected COM class (CWE-242)
	if automationFailed(result) {
		return nil, automationHRESULT(result)
	}
	var pointer uintptr
	result, _, _ = automationOLE.NewProc("CoCreateInstance").Call(uintptr(unsafe.Pointer(&clsid)), 0, 1, uintptr(unsafe.Pointer(&automationDispatchIID)), uintptr(unsafe.Pointer(&pointer))) // #nosec G103 -- fixed local scheduler class, exact IDispatch IID and native interface output, released in the same apartment (CWE-242)
	if automationFailed(result) || pointer == 0 {
		return nil, errors.New("windows Automation: local Task Scheduler unavailable")
	}
	object := &automationObject{pointer: pointer, ctx: ctx}
	value, err := object.call("Connect", 1, automationVariant{}, automationVariant{}, automationVariant{}, automationVariant{})
	if err != nil {
		object.destroy()
		return nil, err
	}
	value.destroy()
	return object, nil
}
func (o *automationObject) method(index int) uintptr {
	table := *(*uintptr)(unsafe.Add(nil, o.pointer))
	return (*[7]uintptr)(unsafe.Add(nil, table))[index]
}
func (o *automationObject) destroy() {
	if o == nil || o.pointer == 0 {
		return
	}
	_, _, _ = syscall.SyscallN(o.method(2), o.pointer)
	o.pointer = 0
}
func (v *automationVariant) destroy() {
	if v.VT == 8 {
		freeAutomationBSTR(v.Value)
	} else if v.VT == 9 && v.Value != 0 {
		(&automationObject{pointer: v.Value}).destroy()
	} else {
		_, _, _ = automationStrings.NewProc("VariantClear").Call(uintptr(unsafe.Pointer(v))) // #nosec G103 -- exact live native VARIANT layout; native allocator clears non-text result ownership, text is wiped separately (CWE-242)
	}
	*v = automationVariant{}
}
func (o *automationObject) call(name string, flags uint16, args ...automationVariant) (automationVariant, error) {
	if err := o.ctx.Err(); err != nil {
		return automationVariant{}, err
	}
	if o.pointer == 0 || len(name) == 0 || len(name) > 64 || len(args) > 16 || (flags != 1 && flags != 2 && flags != 4) {
		return automationVariant{}, errors.New("windows Automation: invalid typed invocation")
	}
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return automationVariant{}, err
	}
	var id int32
	result, _, _ := syscall.SyscallN(o.method(5), o.pointer, uintptr(unsafe.Pointer(&automationNullGUID)), uintptr(unsafe.Pointer(&wide)), 1, 0x400, uintptr(unsafe.Pointer(&id))) // #nosec G103 -- live fixed IDispatch vtable, public method name, sized GUID/DISPID outputs and one bounded name (CWE-242)
	if automationFailed(result) {
		return automationVariant{}, automationHRESULT(result)
	}
	reversed := make([]automationVariant, len(args))
	params := automationDispatchParams{}
	for i := range args {
		reversed[len(args)-1-i] = args[i]
		params.count++
	}
	if len(reversed) > 0 {
		params.arguments = &reversed[0]
	}
	named := int32(-3)
	if flags == 4 {
		if len(args) != 1 {
			return automationVariant{}, errors.New("windows Automation: invalid property assignment")
		}
		params.named = &named
		params.namedCount = 1
	}
	var value automationVariant
	var exception automationException
	var badArgument uint32
	result, _, _ = syscall.SyscallN(o.method(6), o.pointer, automationDISPID(id), uintptr(unsafe.Pointer(&automationNullGUID)), 0x400, uintptr(flags), uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&exception)), uintptr(unsafe.Pointer(&badArgument))) // #nosec G103 -- exact IDispatch ABI, at most 16 reversed typed arguments and live sized result/exception outputs; password BSTR lease remains locked (CWE-242)
	runtime.KeepAlive(reversed)
	runtime.KeepAlive(args)
	exception.destroy()
	if automationFailed(result) {
		value.destroy()
		return automationVariant{}, automationHRESULT(result)
	}
	if err := o.ctx.Err(); err != nil {
		value.destroy()
		return automationVariant{}, err
	}
	return value, nil
}
func (o *automationObject) object(name string, flags uint16, args ...automationVariant) (*automationObject, error) {
	value, err := o.call(name, flags, args...)
	if err != nil {
		return nil, err
	}
	if value.VT != 9 || value.Value == 0 {
		value.destroy()
		return nil, errors.New("windows Automation: expected native object")
	}
	return &automationObject{pointer: value.Value, ctx: o.ctx}, nil
}
func (o *automationObject) integer(name string) (int64, error) {
	value, err := o.call(name, 2)
	if err != nil {
		return 0, err
	}
	defer value.destroy()
	return value.integer()
}
func (o *automationObject) boolean(name string) (bool, error) {
	value, err := o.call(name, 2)
	if err != nil {
		return false, err
	}
	defer value.destroy()
	return value.boolean()
}
func (o *automationObject) stringLease(name string, private bool) (*automationBSTR, error) {
	value, err := o.call(name, 2)
	if err != nil {
		return nil, err
	}
	if value.VT != 8 {
		value.destroy()
		return nil, errors.New("windows Automation: expected native text")
	}
	return takeAutomationBSTR(value.Value, private)
}
func (o *automationObject) publicText(name string) (string, error) {
	value, err := o.stringLease(name, false)
	if err != nil {
		return "", err
	}
	defer func() { _ = value.destroy() }()
	return value.publicText()
}
func (o *automationObject) set(name string, value automationVariant) error {
	result, err := o.call(name, 4, value)
	if err != nil {
		return err
	}
	result.destroy()
	return nil
}
func automationNativeBool(value bool) automationVariant {
	bits := uintptr(0)
	if value {
		bits = 0xffff
	}
	return automationVariant{VT: 11, Value: bits}
}

// Windows ABI payloads use little-endian UTF-16; read one unit without creating
// a password string. Used by the native proof as well as typed native metadata.
func automationUTF16Unit(raw []byte, index int) uint16 {
	return binary.LittleEndian.Uint16(raw[index*2:])
}
