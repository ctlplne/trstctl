//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	netapi     = windows.NewLazySystemDLL("netapi32.dll")
	getRole    = netapi.NewProc("DsRoleGetPrimaryDomainInformation")
	freeRole   = netapi.NewProc("DsRoleFreeMemory")
	getModals  = netapi.NewProc("NetUserModalsGet")
	getMembers = netapi.NewProc("NetLocalGroupGetMembers")
	bufferSize = netapi.NewProc("NetApiBufferSize")
)

type nativeDriver struct{}

func newNativeDriver() driver { return nativeDriver{} }

type nativeModals2 struct {
	Name *uint16
	SID  *windows.SID
}
type nativeMember0 struct{ SID *windows.SID }
type nativeUser23 struct {
	Name, FullName, Comment *uint16
	Flags                   uint32
	SID                     *windows.SID
}

func nativeError(operation string, code uintptr) error {
	return fmt.Errorf("windows local accounts: %s: %w", operation, syscall.Errno(code))
}
func freeNetBuffer(raw *byte) {
	if raw != nil {
		_ = windows.NetApiBufferFree(raw)
	}
}
func netBuffer(raw *byte, minimum uintptr) ([]byte, error) {
	if raw == nil {
		return nil, ErrInventory
	}
	var size uint32
	status, _, _ := bufferSize.Call(uintptr(unsafe.Pointer(raw)), uintptr(unsafe.Pointer(&size))) // #nosec G103 -- synchronous native buffer-size query; raw is owned by NetAPI until the caller frees it (CWE-242)
	if status != 0 {
		return nil, nativeError("buffer size", status)
	}
	if uintptr(size) < minimum || size > MaxInventoryBytes {
		return nil, ErrInventoryBound
	}
	return unsafe.Slice(raw, int(size)), nil // #nosec G103 -- borrowed read-only view uses NetApiBufferSize-confirmed length, capped at 1 MiB; caller retains and frees the allocation (CWE-242)
}
func pointerOffset(raw []byte, pointer unsafe.Pointer, minimum int) (int, error) {
	if len(raw) == 0 || pointer == nil {
		return 0, ErrInventory
	}
	base := uintptr(unsafe.Pointer(&raw[0])) // #nosec G103 -- borrowed nonempty NetAPI buffer base; offset arithmetic never becomes a new pointer (CWE-242)
	address := uintptr(pointer)
	if address < base || address-base > uintptr(len(raw)) {
		return 0, ErrInventory
	}
	offset := address - base
	if offset > MaxInventoryBytes || minimum < 0 || uintptr(minimum) > uintptr(len(raw))-offset {
		return 0, ErrInventory
	}
	return int(offset), nil
}
func sidAt(raw []byte, pointer *windows.SID) (string, error) {
	offset, err := pointerOffset(raw, unsafe.Pointer(pointer), 8) // #nosec G103 -- SDK SID pointer is range checked against the borrowed native allocation before byte decoding (CWE-242)
	if err != nil {
		return "", err
	}
	return nativeSIDBytes(raw[offset:])
}
func wideAt(raw []byte, pointer *uint16, limit int) (string, error) {
	offset, err := pointerOffset(raw, unsafe.Pointer(pointer), 2) // #nosec G103 -- SDK UTF-16 pointer is range checked before bounded, terminated public-name decoding (CWE-242)
	if err != nil || offset%2 != 0 {
		return "", ErrInventory
	}
	return nativeWideBytes(raw[offset:], limit)
}
func (nativeDriver) Machine(ctx context.Context) (Machine, error) {
	if err := ctx.Err(); err != nil {
		return Machine{}, err
	}
	var role *byte
	status, _, _ := getRole.Call(0, 1, uintptr(unsafe.Pointer(&role))) // #nosec G103 -- local DSROLE basic result pointer for one synchronous SDK call; separately freed below (CWE-242)
	if role != nil {
		defer func() { _, _, _ = freeRole.Call(uintptr(unsafe.Pointer(role))) }() // #nosec G103 -- exactly the pointer allocated by DsRoleGetPrimaryDomainInformation, including any partial error result (CWE-242)
	}
	if status != 0 {
		return Machine{}, nativeError("machine role", status)
	}
	if role == nil {
		return Machine{}, ErrInventory
	}
	// MachineRole is the first DWORD of DSROLE_PRIMARY_DOMAIN_INFO_BASIC.
	machineRole := binary.LittleEndian.Uint32(unsafe.Slice(role, 4)) // #nosec G103 -- successful local DSROLE basic result guarantees this four-byte prefix; pointer is non-nil and separately freed (CWE-242)
	if machineRole > 3 {
		return Machine{Role: machineRole}, nil
	}
	var raw *byte
	status, _, _ = getModals.Call(0, 2, uintptr(unsafe.Pointer(&raw))) // #nosec G103 -- local SAM public domain-name/SID result, no remote server parameter (CWE-242)
	defer freeNetBuffer(raw)
	if status != 0 {
		return Machine{}, nativeError("local SAM identity", status)
	}
	blob, err := netBuffer(raw, unsafe.Sizeof(nativeModals2{}))
	if err != nil {
		return Machine{}, err
	}
	fields := (*nativeModals2)(unsafe.Pointer(raw)) // #nosec G103 -- exact SDK prefix fits the checked allocation; each pointed field is independently bounded (CWE-242)
	name, err := wideAt(blob, fields.Name, 255)
	if err != nil {
		return Machine{}, err
	}
	sid, err := sidAt(blob, fields.SID)
	if err != nil {
		return Machine{}, err
	}
	return Machine{Name: name, SID: sid, Role: machineRole}, nil
}
func (nativeDriver) Administrators(ctx context.Context, accept func(Member) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	builtin, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	name, _, use, err := builtin.LookupAccount("")
	if err != nil || use != windows.SidTypeAlias {
		return ErrInventory
	}
	group, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var resume uintptr
	var retained error
	for {
		var raw *byte
		var read, total uint32
		previous := resume
		status, _, _ := getMembers.Call(0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&raw)), 64<<10, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume))) // #nosec G103 -- local-only paged alias read, fixed SDK scalar/output pointers, bounded preferred reply size (CWE-242)
		runtime.KeepAlive(group)
		pageErr := func() error {
			defer freeNetBuffer(raw)
			if status != 0 && status != uintptr(windows.ERROR_MORE_DATA) {
				return nativeError("administrator membership", status)
			}
			// Drain every native resume page after refusal/cancellation. NetAPI requires
			// enumeration to finish even after a callback error, preventing RPC leaks.
			if retained != nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if read == 0 {
				if status != 0 {
					return ErrInventory
				}
				return nil
			}
			blob, err := netBuffer(raw, unsafe.Sizeof(nativeMember0{}))
			if err != nil {
				return err
			}
			if uint64(read) > uint64(len(blob))/uint64(unsafe.Sizeof(nativeMember0{})) {
				return ErrInventory
			}
			entries := unsafe.Slice((*nativeMember0)(unsafe.Pointer(raw)), int(read)) // #nosec G103 -- SDK array count is checked against the exact allocation before creating a borrowed view (CWE-242)
			for _, entry := range entries {
				sid, err := sidAt(blob, entry.SID)
				if err != nil {
					return err
				}
				// Level zero returns SIDs only. Foreign domain members are not
				// resolved to names; User independently confirms local candidates.
				use := uint32(0)
				if strings.HasPrefix(sid, "S-1-5-32-") && len(strings.Split(sid, "-")) == 5 {
					use = windows.SidTypeAlias
				}
				if err := accept(Member{SID: sid, Use: use}); err != nil {
					return err
				}
			}
			return nil
		}()
		if retained == nil && pageErr != nil {
			retained = pageErr
		}
		if status != uintptr(windows.ERROR_MORE_DATA) {
			return retained
		}
		if resume == previous {
			return ErrInventory
		}
	}
}
func (nativeDriver) User(ctx context.Context, sid string) (Account, error) {
	if err := ctx.Err(); err != nil {
		return Account{}, err
	}
	selected, err := windows.StringToSid(sid)
	if err != nil {
		return Account{}, ErrInventory
	}
	name, _, use, err := selected.LookupAccount("")
	if err != nil || use != windows.SidTypeUser {
		return Account{}, ErrInventory
	}
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Account{}, err
	}
	var raw *byte
	err = windows.NetUserGetInfo(nil, wide, 23, &raw)
	runtime.KeepAlive(wide)
	defer freeNetBuffer(raw)
	if err != nil {
		return Account{}, fmt.Errorf("windows local accounts: local user read: %w", err)
	}
	blob, err := netBuffer(raw, unsafe.Sizeof(nativeUser23{}))
	if err != nil {
		return Account{}, err
	}
	fields := (*nativeUser23)(unsafe.Pointer(raw)) // #nosec G103 -- checked USER_INFO_23 allocation; only public name, flags and SID are read (CWE-242)
	actualSID, err := sidAt(blob, fields.SID)
	if err != nil || actualSID != sid {
		return Account{}, ErrInventory
	}
	actualName, err := wideAt(blob, fields.Name, 20)
	if err != nil {
		return Account{}, err
	}
	return Account{Name: actualName, SID: actualSID, Enabled: fields.Flags&0x2 == 0, Locked: fields.Flags&0x10 != 0, PasswordRequired: fields.Flags&0x20 == 0}, nil
}
