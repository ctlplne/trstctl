//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

type nativeRotationDriver struct{}

func newNativeRotationDriver() rotationDriver { return nativeRotationDriver{} }

// nativeUser4 follows USER_INFO_4's SDK ABI. The password pointer is never read.
type nativeUser4 struct {
	Name, Password                                                  *uint16
	PasswordAge, Privilege                                          uint32
	Home, Comment                                                   *uint16
	Flags                                                           uint32
	Script                                                          *uint16
	AuthFlags                                                       uint32
	FullName, UserComment, Parameters, Workstations                 *uint16
	LastLogon, LastLogoff, AccountExpires, MaxStorage, UnitsPerWeek uint32
	LogonHours                                                      *byte
	BadPasswordCount, Logons                                        uint32
	LogonServer                                                     *uint16
	CountryCode, CodePage                                           uint32
	SID                                                             *windows.SID
	PrimaryGroupID                                                  uint32
	Profile, HomeDrive                                              *uint16
	PasswordExpired                                                 uint32
}
type nativeModals0 struct{ MinimumLength, MaximumAge, MinimumAge, ForceLogoff, HistoryLength uint32 }
type nativeModals3 struct{ Duration, ObservationWindow, Threshold uint32 }

func readNativePasswordPolicy() (uint32, uint32, error) {
	var passwordRaw, lockoutRaw *byte
	code, _, _ := getModals.Call(0, 0, uintptr(unsafe.Pointer(&passwordRaw))) // #nosec G103 -- local-only public password policy result, freed below; no secret or remote target (CWE-242)
	defer freeNetBuffer(passwordRaw)
	if code != 0 {
		return 0, 0, nativeError("password policy", code)
	}
	if _, err := netBuffer(passwordRaw, unsafe.Sizeof(nativeModals0{})); err != nil {
		return 0, 0, err
	}
	password := (*nativeModals0)(unsafe.Pointer(passwordRaw))               // #nosec G103 -- exact USER_MODALS_INFO_0 prefix fits NetApiBufferSize-checked native allocation (CWE-242)
	code, _, _ = getModals.Call(0, 3, uintptr(unsafe.Pointer(&lockoutRaw))) // #nosec G103 -- local-only public lockout policy result with SDK level 3 and owned output pointer (CWE-242)
	defer freeNetBuffer(lockoutRaw)
	if code != 0 {
		return 0, 0, nativeError("lockout policy", code)
	}
	if _, err := netBuffer(lockoutRaw, unsafe.Sizeof(nativeModals3{})); err != nil {
		return 0, 0, err
	}
	lockout := (*nativeModals3)(unsafe.Pointer(lockoutRaw)) // #nosec G103 -- exact USER_MODALS_INFO_3 prefix fits the checked allocation; read-only scalar fields (CWE-242)
	return password.MinimumLength, lockout.Threshold, nil
}
func (nativeRotationDriver) Inspect(ctx context.Context, b RotationBinding) (RotationState, error) {
	var none RotationState
	if b.Validate() != nil {
		return none, ErrRotationInvalid
	}
	d := nativeDriver{}
	before, err := d.Machine(ctx)
	if err != nil {
		return none, err
	}
	if before != b.Machine {
		return none, ErrRotationInvalid
	}
	found := false
	err = d.Administrators(ctx, func(member Member) error {
		if member.SID == b.Account.SID {
			if found || (member.Use != 0 && member.Use != 1) {
				return ErrInventory
			}
			found = true
		}
		return nil
	})
	if err != nil {
		return none, err
	}
	if !found {
		return none, ErrRotationInvalid
	}
	user, err := d.User(ctx, b.Account.SID)
	if err != nil {
		return none, err
	}
	if user != b.Account {
		return none, ErrRotationInvalid
	}
	name, err := windows.UTF16PtrFromString(b.Account.Name)
	if err != nil {
		return none, ErrRotationInvalid
	}
	var raw *byte
	err = windows.NetUserGetInfo(nil, name, 4, &raw)
	runtime.KeepAlive(name)
	defer freeNetBuffer(raw)
	if err != nil {
		return none, err
	}
	blob, err := netBuffer(raw, unsafe.Sizeof(nativeUser4{}))
	if err != nil {
		return none, err
	}
	data := (*nativeUser4)(unsafe.Pointer(raw)) // #nosec G103 -- exact USER_INFO_4 ABI in checked allocation; only public identity/flags/counters are accessed, never Password (CWE-242)
	sid, err := sidAt(blob, data.SID)
	if err != nil || sid != b.Account.SID {
		return none, ErrRotationInvalid
	}
	actualName, err := wideAt(blob, data.Name, 20)
	if err != nil || actualName != b.Account.Name || data.PasswordExpired != 0 {
		return none, ErrRotationInvalid
	}
	current := Account{Name: actualName, SID: sid, Enabled: data.Flags&0x2 == 0, Locked: data.Flags&0x10 != 0, PasswordRequired: data.Flags&0x20 == 0}
	if current != b.Account {
		return none, ErrRotationInvalid
	}
	minimum, threshold, err := readNativePasswordPolicy()
	if err != nil {
		return none, err
	}
	after, err := d.Machine(ctx)
	if err != nil {
		return none, err
	}
	if after != before {
		return none, ErrRotationInvalid
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return RotationState{Binding: RotationBinding{Machine: after, Account: current}, MinimumPasswordLength: minimum, LockoutThreshold: threshold, BadPasswordCount: data.BadPasswordCount}, nil
}
func (d nativeRotationDriver) SetPassword(ctx context.Context, b RotationBinding, value []byte) error {
	state, err := d.Inspect(ctx, b)
	if err != nil || !rotationBudget(state) {
		return ErrRotationInvalid
	}
	wide, err := lockedPasswordUTF16(value)
	if err != nil {
		return err
	}
	defer wide.Destroy()
	name, err := windows.UTF16PtrFromString(b.Account.Name)
	if err != nil {
		return ErrRotationInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return wide.Use(func(raw []byte) error {
		info := struct{ Password *uint16 }{(*uint16)(unsafe.Pointer(&raw[0]))} // #nosec G103 -- aligned locked UTF-16 byte buffer, terminated and borrowed through Use for the synchronous SDK call (CWE-242)
		var parameter uint32
		code, _, _ := netapi.NewProc("NetUserSetInfo").Call(0, uintptr(unsafe.Pointer(name)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter))) // #nosec G103 -- local-only password field, fixed SDK level, exact preflighted public account name; no flags, membership, shell or remote target (CWE-242)
		runtime.KeepAlive(name)
		runtime.KeepAlive(raw)
		if code != 0 {
			return nativeError("local password reset", code)
		}
		return nil
	})
}
func (d nativeRotationDriver) Authenticate(ctx context.Context, b RotationBinding, value []byte) (string, error) {
	state, err := d.Inspect(ctx, b)
	if err != nil || !rotationBudget(state) {
		return "", ErrRotationInvalid
	}
	wide, err := lockedPasswordUTF16(value)
	if err != nil {
		return "", err
	}
	defer wide.Destroy()
	name, err := windows.UTF16PtrFromString(b.Account.Name)
	if err != nil {
		return "", ErrRotationInvalid
	}
	local, err := windows.UTF16PtrFromString(".")
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var sid string
	err = wide.Use(func(raw []byte) error {
		var token windows.Token
		ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(local)), uintptr(unsafe.Pointer(&raw[0])), 3, 0, uintptr(unsafe.Pointer(&token))) // #nosec G103 -- one bounded local-SAM LOGON_NETWORK authentication, which does not cache credentials; live locked password bytes only (CWE-242)
		runtime.KeepAlive(name)
		runtime.KeepAlive(local)
		runtime.KeepAlive(raw)
		if ok == 0 {
			if errors.Is(callErr, windows.ERROR_LOGON_FAILURE) {
				return ErrCredentialRejected
			}
			return ErrRotationInvalid
		}
		user, err := token.GetTokenUser()
		if err != nil {
			_ = token.Close()
			return ErrRotationInvalid
		}
		sid = user.User.Sid.String()
		if err := token.Close(); err != nil {
			return ErrRotationInvalid
		}
		if sid != b.Account.SID {
			return ErrRotationInvalid
		}
		return nil
	})
	return sid, err
}
