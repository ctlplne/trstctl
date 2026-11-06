// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unsafe"
)

type nativeServiceDriver struct{}

func newNativeServiceDriver() serviceDriver { return nativeServiceDriver{} }
func openLocalSCM(access uint32) (windows.Handle, error) {
	return windows.OpenSCManager(nil, nil, access)
}
func openNativeService(name string, access uint32) (windows.Handle, error) {
	scm, err := openLocalSCM(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, errors.New("windows service: local manager unavailable")
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, errors.New("windows service: invalid native name")
	}
	handle, err := windows.OpenService(scm, wide, access)
	if err != nil {
		return 0, errors.New("windows service: selected native object unavailable")
	}
	return handle, nil
}

type nativeServiceSnapshot struct {
	Service
	held    *secret.Buffer
	account *uint16
}

func (s *nativeServiceSnapshot) destroy() {
	if s.held != nil {
		s.held.Destroy()
		s.held = nil
		s.account = nil
	}
}
func nativeStringAt(raw []byte, pointer *uint16, multi bool) ([]byte, error) {
	if pointer == nil {
		return nil, nil
	}
	base := uintptr(unsafe.Pointer(&raw[0]))    // #nosec G103 -- owned nonempty native query buffer address; only offset arithmetic, never converted back to a pointer (CWE-242)
	address := uintptr(unsafe.Pointer(pointer)) // #nosec G103 -- SDK-returned UTF-16 pointer is range/alignment/termination checked against the owned buffer before a byte view (CWE-242)
	if address < base || address-base > uintptr(len(raw)-2) {
		return nil, errors.New("windows service: invalid native field pointer")
	}
	return nativeWideBytes(raw, int(address-base), multi)
}
func nativeServiceStatus(handle windows.Handle) (windows.SERVICE_STATUS_PROCESS, error) {
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err := windows.QueryServiceStatusEx(handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed) // #nosec G103 -- exact SDK status struct size and lifetime for a synchronous local status call (CWE-242)
	if err != nil {
		return status, errors.New("windows service: native status unavailable")
	}
	return status, nil
}
func inspectServiceHandle(ctx context.Context, handle windows.Handle, name, selectedSID string) (nativeServiceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nativeServiceSnapshot{}, err
	}
	held, err := secret.New(64 << 10)
	if err != nil {
		return nativeServiceSnapshot{}, err
	}
	success := false
	defer func() {
		if !success {
			held.Destroy()
		}
	}()
	raw := held.Bytes()
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&raw[0])) // #nosec G103 -- page-aligned locked 64 KiB query buffer exceeds the SDK struct and remains alive through all bounded field reads (CWE-242)
	var needed uint32
	if err := windows.QueryServiceConfig(handle, config, 64<<10, &needed); err != nil {
		return nativeServiceSnapshot{}, errors.New("windows service: native configuration unavailable")
	}
	if config.ServiceType&windows.SERVICE_WIN32 == 0 || config.ServiceType&windows.SERVICE_DRIVER != 0 {
		return nativeServiceSnapshot{}, errors.New("windows service: selected object is not a user service")
	}
	pointers := []*uint16{config.BinaryPathName, config.LoadOrderGroup, config.Dependencies, config.ServiceStartName, config.DisplayName}
	fields := make([][]byte, len(pointers))
	for i, pointer := range pointers {
		field, e := nativeStringAt(raw, pointer, i == 2)
		if e != nil {
			return nativeServiceSnapshot{}, e
		}
		fields[i] = field
	}
	accountName, err := publicNativeText(fields[3])
	if err != nil {
		return nativeServiceSnapshot{}, err
	}
	sid := ""
	switch strings.ToLower(accountName) {
	case "localsystem", "nt authority\\system":
		sid = "S-1-5-18"
	case "nt authority\\localservice", "localservice":
		sid = "S-1-5-19"
	case "nt authority\\networkservice", "networkservice":
		sid = "S-1-5-20"
	default:
		value, _, _, e := windows.LookupSID("", accountName)
		if e != nil {
			return nativeServiceSnapshot{}, errors.New("windows service: logon account SID could not be resolved; coverage is incomplete")
		}
		sid = value.String()
	}
	// Unrelated services may be starting/stopping. Their runtime state cannot
	// hide a selected dependent, and need not make this account's scan fail.
	if selectedSID != "" && sid != selectedSID {
		success = true
		return nativeServiceSnapshot{Service: Service{Name: name, AccountSID: sid}, held: held}, nil
	}
	var dependencies []string
	for offset := 0; offset < len(fields[2]); {
		field, e := nativeWideBytes(fields[2], offset, false)
		if e != nil {
			return nativeServiceSnapshot{}, e
		}
		if len(field) == 0 {
			break
		}
		name, e := publicNativeText(field)
		if e != nil || !validServiceName(name) || len(dependencies) >= 128 {
			return nativeServiceSnapshot{}, errors.New("windows service: dependency list exceeds native bounds")
		}
		dependencies = append(dependencies, name)
		offset += len(field) + 2
	}
	status, err := nativeServiceStatus(handle)
	if err != nil {
		return nativeServiceSnapshot{}, err
	}
	if status.CurrentState != windows.SERVICE_RUNNING && status.CurrentState != windows.SERVICE_STOPPED {
		return nativeServiceSnapshot{}, errors.New("windows service: transient native state requires rediscovery")
	}
	hash := serviceConfigurationHash(name, sid, []uint32{config.ServiceType, config.StartType, config.ErrorControl, config.TagId}, fields)
	success = true
	return nativeServiceSnapshot{Service: Service{Name: name, AccountSID: sid, ConfigSHA256: hash, Dependencies: dependencies, WasRunning: status.CurrentState == windows.SERVICE_RUNNING}, held: held, account: config.ServiceStartName}, nil
}
func (driver nativeServiceDriver) inspect(ctx context.Context, name string) (Service, error) {
	return driver.inspectSelected(ctx, name, "")
}
func (nativeServiceDriver) inspectSelected(ctx context.Context, name, selectedSID string) (Service, error) {
	handle, err := openNativeService(name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return Service{}, err
	}
	defer func() { _ = windows.CloseServiceHandle(handle) }()
	snapshot, err := inspectServiceHandle(ctx, handle, name, selectedSID)
	if err != nil {
		return Service{}, err
	}
	defer snapshot.destroy()
	return snapshot.Service, nil
}
func (driver nativeServiceDriver) discover(ctx context.Context, sid string) ([]Service, error) {
	scm, err := openLocalSCM(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, errors.New("windows service: local enumeration unavailable")
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()
	raw := make([]byte, 512<<10)
	var resume uint32
	var found []Service
	total := uint32(0)
	for page := 0; page < 64; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var needed, count uint32
		err := windows.EnumServicesStatusEx(scm, 0, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &raw[0], 512<<10, &needed, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, errors.New("windows service: enumeration failed; coverage is incomplete")
		}
		entrySize := uint32(unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{}))
		if count > (512<<10)/entrySize || total+count > 8192 {
			return nil, errors.New("windows service: enumeration exceeds bound")
		}
		total += count
		entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&raw[0])), int(count)) // #nosec G103 -- SDK count is bounded by both returned-buffer capacity and total census before creating the native entry view (CWE-242)
		for _, entry := range entries {
			encoded, e := nativeStringAt(raw, entry.ServiceName, false)
			if e != nil {
				return nil, e
			}
			name, e := publicNativeText(encoded)
			if e != nil || !validServiceName(name) {
				return nil, errors.New("windows service: invalid enumerated name")
			}
			target, e := driver.inspectSelected(ctx, name, sid)
			if e != nil {
				return nil, e
			}
			if target.AccountSID == sid {
				found = append(found, target)
				if len(found) > 256 {
					return nil, errors.New("windows service: managed dependent count exceeds bound")
				}
			}
		}
		if err == nil {
			return found, nil
		}
		if count == 0 {
			return nil, errors.New("windows service: enumeration made no progress")
		}
	}
	return nil, errors.New("windows service: enumeration page bound exceeded")
}
func (nativeServiceDriver) update(ctx context.Context, expected Service, password []byte) error {
	handle, err := openNativeService(expected.Name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_CHANGE_CONFIG)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseServiceHandle(handle) }()
	snapshot, err := inspectServiceHandle(ctx, handle, expected.Name, expected.AccountSID)
	if err != nil {
		return err
	}
	defer snapshot.destroy()
	if !sameServiceBinding(expected, snapshot.Service) {
		return errors.New("windows service: frozen native configuration changed before update")
	}
	wide, err := lockedWindowsPassword(password)
	if err != nil {
		return err
	}
	defer wide.Destroy()
	if err := ctx.Err(); err != nil {
		return err
	}
	err = wide.Use(func(raw []byte) error {
		return windows.ChangeServiceConfig(handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, snapshot.account, (*uint16)(unsafe.Pointer(&raw[0])), nil) // #nosec G103 -- password pointer borrows the locked UTF-16 buffer through Use; frozen account pointer stays in the live locked query buffer (CWE-242)
	})
	runtime.KeepAlive(snapshot.held)
	if err != nil {
		return errors.New("windows service: native password update failed or is uncertain")
	}
	return nil
}
func waitServiceState(ctx context.Context, handle windows.Handle, want uint32) (windows.SERVICE_STATUS_PROCESS, error) {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := nativeServiceStatus(handle)
		if err != nil {
			return status, err
		}
		if status.CurrentState == want {
			return status, nil
		}
		if want == windows.SERVICE_RUNNING && status.CurrentState == windows.SERVICE_STOPPED {
			return status, errors.New("windows service: start failed before a running process existed")
		}
		select {
		case <-bounded.Done():
			return status, errors.New("windows service: native transition deadline exceeded")
		case <-ticker.C:
		}
	}
}
func verifiedServiceProcess(handle windows.Handle, expectedSID string) (Runtime, error) {
	status, err := nativeServiceStatus(handle)
	if err != nil || status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 {
		return Runtime{}, errors.New("windows service: no running native process")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId)
	if err != nil {
		return Runtime{}, errors.New("windows service: native process unavailable for identity proof")
	}
	defer func() { _ = windows.CloseHandle(process) }()
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return Runtime{}, errors.New("windows service: native process token unavailable")
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != expectedSID {
		return Runtime{}, errors.New("windows service: process account SID differs from managed account")
	}
	after, err := nativeServiceStatus(handle)
	if err != nil || after.CurrentState != windows.SERVICE_RUNNING || after.ProcessId != status.ProcessId {
		return Runtime{}, errors.New("windows service: process changed during identity proof")
	}
	return Runtime{Running: true, ProcessID: status.ProcessId, AccountSID: expectedSID}, nil
}
func (nativeServiceDriver) restart(ctx context.Context, expected Service) (Runtime, error) {
	handle, err := openNativeService(expected.Name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP|windows.SERVICE_START)
	if err != nil {
		return Runtime{}, err
	}
	defer func() { _ = windows.CloseServiceHandle(handle) }()
	snapshot, err := inspectServiceHandle(ctx, handle, expected.Name, expected.AccountSID)
	if err != nil {
		return Runtime{}, err
	}
	defer snapshot.destroy()
	if !sameServiceBinding(expected, snapshot.Service) {
		return Runtime{}, errors.New("windows service: frozen native configuration changed before restart")
	}
	if !expected.WasRunning {
		if snapshot.WasRunning {
			return Runtime{}, errors.New("windows service: stopped-state binding changed")
		}
		return Runtime{}, nil
	}
	if snapshot.WasRunning {
		var status windows.SERVICE_STATUS
		if err := windows.ControlService(handle, windows.SERVICE_CONTROL_STOP, &status); err != nil {
			return Runtime{}, errors.New("windows service: stop failed; dependent ordering or service state requires recovery")
		}
		if _, err := waitServiceState(ctx, handle, windows.SERVICE_STOPPED); err != nil {
			return Runtime{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Runtime{}, err
	}
	if err := windows.StartService(handle, 0, nil); err != nil {
		return Runtime{}, errors.New("windows service: native start failed")
	}
	if _, err := waitServiceState(ctx, handle, windows.SERVICE_RUNNING); err != nil {
		return Runtime{}, err
	}
	return verifiedServiceProcess(handle, expected.AccountSID)
}
