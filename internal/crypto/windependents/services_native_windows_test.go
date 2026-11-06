// SPDX-License-Identifier: BUSL-1.1
//go:build windows

package windependents

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unsafe"
)

var nativeFixtureService = flag.String("a267-service-name", "", "owned SCM fixture name")
var nativeFixtureAddress = flag.String("a267-service-address", "", "owned loopback functional fixture")

type nativeWorkReceipt struct {
	SID    string `json:"sid"`
	PID    uint32 `json:"pid"`
	Result string `json:"result"`
}
type nativeWorkService struct{}

func (nativeWorkService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	listener, err := net.Listen("tcp", *nativeFixtureAddress)
	if err != nil {
		return false, 1
	}
	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		_ = listener.Close()
		return false, 2
	}
	user, err := token.GetTokenUser()
	_ = token.Close()
	if err != nil {
		_ = listener.Close()
		return false, 3
	}
	sid := user.User.Sid.String()
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if r.Method != http.MethodGet || r.URL.Path != "/work" || len(nonce) != 32 {
			http.Error(w, "invalid owned work", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(nativeWorkReceipt{SID: sid, PID: windows.GetCurrentProcessId(), Result: crypto.SHA256Hex([]byte("service-work:" + nonce))})
	})}
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			status <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			_ = server.Close()
			<-done
			return false, 0
		}
	}
	_ = server.Close()
	<-done
	return false, 0
}
func TestWindowsServiceFixtureA267(t *testing.T) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		t.Skip("SCM fixture process only")
	}
	if *nativeFixtureService == "" || !strings.HasPrefix(*nativeFixtureAddress, "127.0.0.1:") {
		t.Fatal("invalid owned service fixture")
	}
	if err := svc.Run(*nativeFixtureService, nativeWorkService{}); err != nil {
		t.Fatal("owned native service dispatcher failed")
	}
}

func nativeOwnedPassword(t *testing.T) *secret.Buffer {
	t.Helper()
	random, err := crypto.RandomBytes(24)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(random)
	held, err := secret.New(4 + hex.EncodedLen(len(random)))
	if err != nil {
		t.Fatal(err)
	}
	copy(held.Bytes(), []byte("Tr5!"))
	hex.Encode(held.Bytes()[4:], random)
	t.Cleanup(held.Destroy)
	return held
}
func nativeOwnedWide(t *testing.T, value string) *uint16 {
	t.Helper()
	out, err := windows.UTF16PtrFromString(value)
	if err != nil {
		t.Fatal("invalid owned public name")
	}
	return out
}
func nativeCreateOwnedAccount(t *testing.T, name string, password []byte) *windows.SID {
	t.Helper()
	wide, err := lockedWindowsPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	defer wide.Destroy()
	type userInfo1 struct {
		Name, Password         *uint16
		PasswordAge, Privilege uint32
		HomeDirectory, Comment *uint16
		Flags                  uint32
		ScriptPath             *uint16
	}
	info := userInfo1{Name: nativeOwnedWide(t, name), Password: (*uint16)(unsafe.Pointer(&wide.Bytes()[0])), Privilege: 1, Flags: 0x200 | 0x10000} // #nosec G103 -- SDK USER_INFO_1 points only to the owned public name and live locked password buffer (CWE-242)
	var parameter uint32
	api := windows.NewLazySystemDLL("netapi32.dll")
	code, _, _ := api.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter))) // #nosec G103 -- exact SDK USER_INFO_1 and output scalar for a synchronous local test-account creation; password stays locked (CWE-242)
	runtime.KeepAlive(wide)
	if code != 0 {
		t.Fatalf("owned native account creation failed: status=%d parameter=%d", code, parameter)
	}
	t.Cleanup(func() {
		result, _, _ := api.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(info.Name))) // #nosec G103 -- exact name of the successfully created test-owned account; no enumeration or global cleanup (CWE-242)
		if result != 0 {
			t.Errorf("owned native account cleanup failed: %d", result)
		}
	})
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		t.Fatal("owned native SID lookup failed")
	}
	nativeAddOwnedUserGroup(t, sid)
	nativeGrantOwnedServiceRight(t, sid)
	return sid
}

func nativeAddOwnedUserGroup(t *testing.T, sid *windows.SID) {
	t.Helper()
	group, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	groupName, _, _, err := group.LookupAccount("")
	if err != nil {
		t.Fatal("native Users group lookup failed")
	}
	member := struct{ SID *windows.SID }{sid}
	result, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(nativeOwnedWide(t, groupName))), 0, uintptr(unsafe.Pointer(&member)), 1) // #nosec G103 -- exact newly created test SID added to the native Users group; deletion removes only its own membership (CWE-242)
	if result != 0 && result != 1378 {
		t.Fatalf("owned native Users membership failed: %d", result)
	}
}

func nativeGrantOwnedServiceRight(t *testing.T, sid *windows.SID) {
	t.Helper()
	type objectAttributes struct {
		Length                          uint32
		Root                            uintptr
		ObjectName                      uintptr
		Attributes                      uint32
		SecurityDescriptor, SecurityQOS uintptr
	}
	type unicodeString struct {
		Length, MaximumLength uint16
		Buffer                *uint16
	}
	attribute := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}
	var handle uintptr
	api := windows.NewLazySystemDLL("advapi32.dll")
	code, _, _ := api.NewProc("LsaOpenPolicy").Call(0, uintptr(unsafe.Pointer(&attribute)), 0x810, uintptr(unsafe.Pointer(&handle))) // #nosec G103 -- sized SDK LSA_OBJECT_ATTRIBUTES and handle output; local policy only for test-owned SID rights (CWE-242)
	if code != 0 {
		t.Fatalf("owned LSA policy open failed: %d", code)
	}
	defer func() { _, _, _ = api.NewProc("LsaClose").Call(handle) }()
	right := unicodeString{Buffer: nativeOwnedWide(t, "SeServiceLogonRight")}
	// LSA_UNICODE_STRING length is bytes, excluding its terminator.
	right.Length = uint16(len("SeServiceLogonRight") * 2)
	right.MaximumLength = right.Length + 2
	code, _, _ = api.NewProc("LsaAddAccountRights").Call(handle, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&right)), 1) // #nosec G103 -- live native owned-account SID and length-framed public LSA right; synchronous local API (CWE-242)
	if code != 0 {
		t.Fatalf("owned service logon right failed: %d", code)
	}
	t.Cleanup(func() {
		var policy uintptr
		result, _, _ := api.NewProc("LsaOpenPolicy").Call(0, uintptr(unsafe.Pointer(&attribute)), 0x810, uintptr(unsafe.Pointer(&policy))) // #nosec G103 -- sized SDK LSA_OBJECT_ATTRIBUTES and handle output; local policy only for test-owned SID rights (CWE-242)
		if result != 0 {
			t.Errorf("owned LSA cleanup open failed: %d", result)
			return
		}
		defer func() { _, _, _ = api.NewProc("LsaClose").Call(policy) }()
		result, _, _ = api.NewProc("LsaRemoveAccountRights").Call(policy, uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&right)), 1) // #nosec G103 -- exact test-owned account SID and the single right this fixture added, with all-rights deletion disabled (CWE-242)
		if result != 0 {
			t.Errorf("owned LSA right cleanup failed: %d", result)
		}
	})
}
func nativeSetOwnedPassword(t *testing.T, name string, password []byte) {
	t.Helper()
	wide, err := lockedWindowsPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	defer wide.Destroy()
	info := struct{ Password *uint16 }{(*uint16)(unsafe.Pointer(&wide.Bytes()[0]))} // #nosec G103 -- SDK USER_INFO_1003 borrows the live locked UTF-16 predecessor/successor buffer (CWE-242)
	var parameter uint32
	code, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserSetInfo").Call(0, uintptr(unsafe.Pointer(nativeOwnedWide(t, name))), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter))) // #nosec G103 -- exact test-owned user, SDK level 1003 and live locked UTF-16 password; no password string or file (CWE-242)
	runtime.KeepAlive(wide)
	if code != 0 {
		t.Fatalf("owned native password reset failed: status=%d parameter=%d", code, parameter)
	}
}
func nativeOwnedSignIn(t *testing.T, name string, password []byte) bool {
	t.Helper()
	wide, err := lockedWindowsPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	defer wide.Destroy()
	var token windows.Token
	result, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(nativeOwnedWide(t, name))), uintptr(unsafe.Pointer(nativeOwnedWide(t, "."))), uintptr(unsafe.Pointer(&wide.Bytes()[0])), 3, 0, uintptr(unsafe.Pointer(&token))) // #nosec G103 -- one bounded sign-in for the test-owned local account using a live locked UTF-16 password and token output (CWE-242)
	runtime.KeepAlive(wide)
	if result != 0 {
		_ = token.Close()
	}
	return result != 0
}
func nativeOwnedServiceBinary(t *testing.T, suffix, sid string) string {
	t.Helper()
	decodedSuffix, suffixErr := hex.DecodeString(suffix)
	if suffixErr != nil || len(decodedSuffix) != 4 || suffix != strings.ToLower(suffix) || !validAccountSID(sid) {
		t.Fatal("invalid owned fixture identity")
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || !filepath.IsAbs(programData) {
		t.Fatal("native ProgramData path unavailable")
	}
	directory := filepath.Join(programData, "trstctl-a267-"+suffix)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := windows.CreateDirectory(nativeOwnedWide(t, directory), &attributes); err != nil {
		t.Fatal("create exact owned protected service directory failed")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error("remove exact owned service fixture failed")
		}
	})
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(source) // #nosec G304 -- os.Executable identifies this native test binary; copied code is public, no caller path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	binary := filepath.Join(directory, "service-test.exe")
	out, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed filename in the exclusively created native protected test directory, O_EXCL refuses substitution (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy owned public service fixture failed")
	}
	return binary
}
func nativeFunctionalWork(t *testing.T, ctx context.Context, address string, expected Runtime) {
	t.Helper()
	random, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/work?nonce="+nonce, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			var receipt nativeWorkReceipt
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&receipt)
			_ = response.Body.Close()
			if response.StatusCode == 200 && decodeErr == nil && receipt.SID == expected.AccountSID && receipt.PID == expected.ProcessID && receipt.Result == crypto.SHA256Hex([]byte("service-work:"+nonce)) {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned functional service work canceled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("fresh native service process did not complete functional work")
}
func TestNativeWindowsServiceLifecycleA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_WINDOWS_SERVICES") != "1" {
		t.Skip("native owned Windows service lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	random, err := crypto.RandomBytes(4)
	if err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random)
	name := "trst267_" + suffix
	serviceName := "trstctl-a267-" + suffix
	old, next := nativeOwnedPassword(t), nativeOwnedPassword(t)
	sid := nativeCreateOwnedAccount(t, name, old.Bytes())
	binary := nativeOwnedServiceBinary(t, suffix, sid.String())
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	_ = reserved.Close()
	command := fmt.Sprintf("\"%s\" -test.run=^TestWindowsServiceFixtureA267$ -a267-service-name=%s -a267-service-address=%s", binary, serviceName, address)
	scm, err := openLocalSCM(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()
	wide, err := lockedWindowsPassword(old.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateService(scm, nativeOwnedWide(t, serviceName), nativeOwnedWide(t, serviceName), windows.SERVICE_ALL_ACCESS, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_NORMAL, nativeOwnedWide(t, command), nil, nil, nil, nativeOwnedWide(t, ".\\"+name), (*uint16)(unsafe.Pointer(&wide.Bytes()[0]))) // #nosec G103 -- exact new fixture service and live locked initial UTF-16 credential; only owned service is created (CWE-242)
	wide.Destroy()
	if err != nil {
		t.Fatal("owned native service creation failed")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		status, e := nativeServiceStatus(handle)
		var process windows.Handle
		if e == nil && status.ProcessId != 0 {
			process, _ = windows.OpenProcess(windows.SYNCHRONIZE, false, status.ProcessId)
		}
		if e == nil && status.CurrentState != windows.SERVICE_STOPPED {
			var stopped windows.SERVICE_STATUS
			_ = windows.ControlService(handle, windows.SERVICE_CONTROL_STOP, &stopped)
			_, _ = waitServiceState(bounded, handle, windows.SERVICE_STOPPED)
		}
		if process != 0 {
			result, waitErr := windows.WaitForSingleObject(process, 15000)
			_ = windows.CloseHandle(process)
			if waitErr != nil || result != windows.WAIT_OBJECT_0 {
				t.Error("owned native service process did not exit")
			}
		}
		if e := windows.DeleteService(handle); e != nil && !errors.Is(e, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			t.Error("delete exact owned native service failed")
		}
		_ = windows.CloseServiceHandle(handle)
	})
	if err := windows.StartService(handle, 0, nil); err != nil {
		t.Fatal("owned native fixture start failed")
	}
	if _, err := waitServiceState(ctx, handle, windows.SERVICE_RUNNING); err != nil {
		t.Fatal(err)
	}
	initial, err := verifiedServiceProcess(handle, sid.String())
	if err != nil {
		t.Fatal(err)
	}
	nativeFunctionalWork(t, ctx, address, initial)
	adapter := NewServices()
	found, err := adapter.Discover(ctx, sid.String())
	if err != nil || len(found) != 1 || found[0].Name != serviceName {
		t.Fatal("native selected-SID service discovery failed")
	}
	target := found[0]
	tampered := target
	tampered.ConfigSHA256 = strings.Repeat("0", 64)
	if err := adapter.UpdatePassword(ctx, tampered, next.Bytes()); err == nil {
		t.Fatal("changed native binding admitted")
	}
	nativeSetOwnedPassword(t, name, next.Bytes())
	if err := adapter.UpdatePassword(ctx, target, next.Bytes()); err != nil {
		t.Fatal(err)
	}
	successor, err := adapter.RestartAndVerifyIdentity(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if successor.ProcessID == initial.ProcessID {
		t.Fatal("native service process was not replaced")
	}
	nativeFunctionalWork(t, ctx, address, successor)
	if nativeOwnedSignIn(t, name, old.Bytes()) {
		t.Fatal("old native account credential was accepted after rotation")
	}
	if !nativeOwnedSignIn(t, name, next.Bytes()) {
		t.Fatal("new native account credential was rejected")
	}
	nativeSetOwnedPassword(t, name, old.Bytes())
	if err := adapter.UpdatePassword(ctx, target, old.Bytes()); err != nil {
		t.Fatal(err)
	}
	restored, err := adapter.RestartAndVerifyIdentity(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	nativeFunctionalWork(t, ctx, address, restored)
	if !nativeOwnedSignIn(t, name, old.Bytes()) || nativeOwnedSignIn(t, name, next.Bytes()) {
		t.Fatal("native service recovery did not restore/refuse the exact credentials")
	}
	t.Log("A267_WINDOWS_SERVICE_OK: native discovery, credential update, fresh process SID, functional work and recovery; local SAM is not an AD forest")
}
