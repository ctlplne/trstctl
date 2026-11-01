// SPDX-License-Identifier: MPL-2.0

//go:build cgo

// Command pkcs11 is libtrstctl-pkcs11, a PKCS #11 module through which
// jarsigner, osslsigncode and other PKCS #11 signing tools sign with a key
// held in trstctl's isolated signer. Build it with
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libtrstctl-pkcs11.so ./pkcs11
//
// The PIN is a trstctl API token with keys:read and keys:write. TRSTCTL_URL
// names the control plane, TRSTCTL_CA_FILE optional roots for its TLS
// certificate, and TRSTCTL_PKCS11_KEYS the code-signing keys (comma-separated)
// the token offers; each needs a certificate chain configured in trstctl.
package main

/*
#include <string.h>
#include "ck.h"
*/
import "C"

import (
	"os"
	"strings"
	"sync"
	"unsafe"

	"trstctl.com/clients/signing/internal/token"
	"trstctl.com/clients/signing/trstctlsign"
)

const (
	slotID                   = 1
	ckUnavailableInformation = ^C.CK_ULONG(0)
)

var (
	mu  sync.Mutex
	tok *token.Token
)

func main() {}

func current() *token.Token {
	mu.Lock()
	defer mu.Unlock()
	return tok
}

// pad fills a fixed-size, blank-padded PKCS #11 text field.
func pad(dst unsafe.Pointer, size int, text string) {
	field := unsafe.Slice((*byte)(dst), size)
	for i := range field {
		field[i] = ' '
	}
	copy(field, text)
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	if C.sizeof_CK_ULONG != 8 {
		return token.CKR_GENERAL_ERROR
	}
	if pInitArgs != nil && (*C.CK_C_INITIALIZE_ARGS)(pInitArgs).pReserved != nil {
		return token.CKR_ARGUMENTS_BAD
	}
	mu.Lock()
	defer mu.Unlock()
	if tok != nil {
		return token.CKR_CRYPTOKI_ALREADY_INITIALIZED
	}
	base, caFile := os.Getenv("TRSTCTL_URL"), os.Getenv("TRSTCTL_CA_FILE")
	tok = token.New(token.Config{
		KeyIDs: strings.Split(os.Getenv("TRSTCTL_PKCS11_KEYS"), ","),
		Connect: func(apiToken string) (token.API, error) {
			client, err := trstctlsign.NewClient(base, apiToken, caFile)
			if err != nil {
				return nil, err
			}
			return client, nil
		},
		Log: os.Stderr,
	})
	return token.CKR_OK
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	if pReserved != nil {
		return token.CKR_ARGUMENTS_BAD
	}
	mu.Lock()
	defer mu.Unlock()
	if tok == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	tok.CloseAllSessions()
	tok = nil
	return token.CKR_OK
}

//export C_GetInfo
func C_GetInfo(pInfo *C.CK_INFO) C.CK_RV {
	if current() == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	pInfo.cryptokiVersion = C.CK_VERSION{major: 2, minor: 40}
	pad(unsafe.Pointer(&pInfo.manufacturerID[0]), 32, "trstctl")
	pInfo.flags = 0
	pad(unsafe.Pointer(&pInfo.libraryDescription[0]), 32, "trstctl code signing")
	pInfo.libraryVersion = C.CK_VERSION{major: 1, minor: 0}
	return token.CKR_OK
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList *C.CK_SLOT_ID, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if current() == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulCount == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	if pSlotList == nil {
		*pulCount = 1
		return token.CKR_OK
	}
	if *pulCount < 1 {
		*pulCount = 1
		return token.CKR_BUFFER_TOO_SMALL
	}
	*pSlotList = slotID
	*pulCount = 1
	return token.CKR_OK
}

//export C_GetSlotInfo
func C_GetSlotInfo(slot C.CK_SLOT_ID, pInfo *C.CK_SLOT_INFO) C.CK_RV {
	if current() == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slot != slotID {
		return token.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	pad(unsafe.Pointer(&pInfo.slotDescription[0]), 64, "trstctl code-signing API")
	pad(unsafe.Pointer(&pInfo.manufacturerID[0]), 32, "trstctl")
	pInfo.flags = token.CKF_TOKEN_PRESENT
	pInfo.hardwareVersion = C.CK_VERSION{major: 1, minor: 0}
	pInfo.firmwareVersion = C.CK_VERSION{major: 1, minor: 0}
	return token.CKR_OK
}

//export C_GetTokenInfo
func C_GetTokenInfo(slot C.CK_SLOT_ID, pInfo *C.CK_TOKEN_INFO) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slot != slotID {
		return token.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	all, rw := t.SessionCount()
	pad(unsafe.Pointer(&pInfo.label[0]), 32, "trstctl")
	pad(unsafe.Pointer(&pInfo.manufacturerID[0]), 32, "trstctl")
	pad(unsafe.Pointer(&pInfo.model[0]), 16, "code signing")
	pad(unsafe.Pointer(&pInfo.serialNumber[0]), 16, "1")
	pInfo.flags = token.CKF_WRITE_PROTECTED | token.CKF_LOGIN_REQUIRED | token.CKF_USER_PIN_INITIALIZED | token.CKF_TOKEN_INITIALIZED
	pInfo.ulMaxSessionCount, pInfo.ulSessionCount = 0, C.CK_ULONG(all)
	pInfo.ulMaxRwSessionCount, pInfo.ulRwSessionCount = 0, C.CK_ULONG(rw)
	pInfo.ulMaxPinLen, pInfo.ulMinPinLen = 4096, 1
	pInfo.ulTotalPublicMemory, pInfo.ulFreePublicMemory = ckUnavailableInformation, ckUnavailableInformation
	pInfo.ulTotalPrivateMemory, pInfo.ulFreePrivateMemory = ckUnavailableInformation, ckUnavailableInformation
	pInfo.hardwareVersion = C.CK_VERSION{major: 1, minor: 0}
	pInfo.firmwareVersion = C.CK_VERSION{major: 1, minor: 0}
	pad(unsafe.Pointer(&pInfo.utcTime[0]), 16, "")
	return token.CKR_OK
}

//export C_GetMechanismList
func C_GetMechanismList(slot C.CK_SLOT_ID, pMechanismList *C.CK_MECHANISM_TYPE, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if current() == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slot != slotID {
		return token.CKR_SLOT_ID_INVALID
	}
	if pulCount == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	mechanisms := token.Mechanisms()
	if pMechanismList == nil {
		*pulCount = C.CK_ULONG(len(mechanisms))
		return token.CKR_OK
	}
	if int(*pulCount) < len(mechanisms) {
		*pulCount = C.CK_ULONG(len(mechanisms))
		return token.CKR_BUFFER_TOO_SMALL
	}
	out := unsafe.Slice(pMechanismList, len(mechanisms))
	for i, m := range mechanisms {
		out[i] = C.CK_MECHANISM_TYPE(m)
	}
	*pulCount = C.CK_ULONG(len(mechanisms))
	return token.CKR_OK
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(slot C.CK_SLOT_ID, mechanism C.CK_MECHANISM_TYPE, pInfo *C.CK_MECHANISM_INFO) C.CK_RV {
	if current() == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slot != slotID {
		return token.CKR_SLOT_ID_INVALID
	}
	if pInfo == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	minBits, maxBits, flags, rv := token.MechanismInfo(uint64(mechanism))
	if rv != token.CKR_OK {
		return C.CK_RV(rv)
	}
	pInfo.ulMinKeySize, pInfo.ulMaxKeySize, pInfo.flags = C.CK_ULONG(minBits), C.CK_ULONG(maxBits), C.CK_FLAGS(flags)
	return token.CKR_OK
}

//export C_OpenSession
func C_OpenSession(slot C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession *C.CK_SESSION_HANDLE) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slot != slotID {
		return token.CKR_SLOT_ID_INVALID
	}
	if phSession == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	handle, rv := t.OpenSession(uint64(flags))
	if rv == token.CKR_OK {
		*phSession = C.CK_SESSION_HANDLE(handle)
	}
	return C.CK_RV(rv)
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return C.CK_RV(t.CloseSession(uint64(hSession)))
}

//export C_CloseAllSessions
func C_CloseAllSessions(slot C.CK_SLOT_ID) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if slot != slotID {
		return token.CKR_SLOT_ID_INVALID
	}
	return C.CK_RV(t.CloseAllSessions())
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo *C.CK_SESSION_INFO) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	state, flags, rv := t.SessionInfo(uint64(hSession))
	if rv == token.CKR_OK {
		pInfo.slotID, pInfo.state, pInfo.flags, pInfo.ulDeviceError = slotID, C.CK_STATE(state), C.CK_FLAGS(flags), 0
	}
	return C.CK_RV(rv)
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	var pin []byte
	if pPin != nil && ulPinLen > 0 {
		pin = C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen))
	}
	return C.CK_RV(t.Login(uint64(hSession), uint64(userType), pin))
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return C.CK_RV(t.Logout(uint64(hSession)))
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pTemplate == nil && ulCount > 0 {
		return token.CKR_ARGUMENTS_BAD
	}
	result := C.CK_RV(token.CKR_OK)
	template := unsafe.Slice(pTemplate, int(ulCount))
	for i := range template {
		// Write through the caller's array: each length and value is answered in
		// place, which the two-call pattern (lengths, then values) relies on.
		attr := &template[i]
		value, rv := t.AttributeValue(uint64(hSession), uint64(hObject), uint64(attr._type))
		switch {
		case rv == token.CKR_SESSION_HANDLE_INVALID || rv == token.CKR_OBJECT_HANDLE_INVALID:
			return C.CK_RV(rv)
		case rv != token.CKR_OK:
			attr.ulValueLen, result = ckUnavailableInformation, C.CK_RV(rv)
		case attr.pValue == nil:
			attr.ulValueLen = C.CK_ULONG(len(value))
		case int(attr.ulValueLen) < len(value):
			attr.ulValueLen, result = ckUnavailableInformation, token.CKR_BUFFER_TOO_SMALL
		default:
			if len(value) > 0 {
				C.memcpy(unsafe.Pointer(attr.pValue), unsafe.Pointer(&value[0]), C.size_t(len(value)))
			}
			attr.ulValueLen = C.CK_ULONG(len(value))
		}
	}
	return result
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pTemplate == nil && ulCount > 0 {
		return token.CKR_ARGUMENTS_BAD
	}
	var template []token.Attribute
	for _, attr := range unsafe.Slice(pTemplate, int(ulCount)) {
		var value []byte
		if attr.pValue != nil && attr.ulValueLen > 0 {
			value = C.GoBytes(unsafe.Pointer(attr.pValue), C.int(attr.ulValueLen))
		}
		template = append(template, token.Attribute{Type: uint64(attr._type), Value: value})
	}
	return C.CK_RV(t.FindInit(uint64(hSession), template))
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject *C.CK_OBJECT_HANDLE, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulObjectCount == nil || (phObject == nil && ulMaxObjectCount > 0) {
		return token.CKR_ARGUMENTS_BAD
	}
	handles, rv := t.Find(uint64(hSession), int(ulMaxObjectCount))
	if rv != token.CKR_OK {
		return C.CK_RV(rv)
	}
	out := unsafe.Slice(phObject, len(handles))
	for i, h := range handles {
		out[i] = C.CK_OBJECT_HANDLE(h)
	}
	*pulObjectCount = C.CK_ULONG(len(handles))
	return token.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return C.CK_RV(t.FindFinal(uint64(hSession)))
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pMechanism == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	return C.CK_RV(t.SignInit(uint64(hSession), uint64(pMechanism.mechanism), uint64(hKey)))
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulSignatureLen == nil || (pData == nil && ulDataLen > 0) {
		return token.CKR_ARGUMENTS_BAD
	}
	var data []byte
	if ulDataLen > 0 {
		data = C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	}
	sig, needed, rv := t.Sign(uint64(hSession), data, int(*pulSignatureLen), pSignature == nil)
	return writeSignature(sig, needed, rv, pSignature, pulSignatureLen)
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pPart == nil && ulPartLen > 0 {
		return token.CKR_ARGUMENTS_BAD
	}
	var part []byte
	if ulPartLen > 0 {
		part = C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	}
	return C.CK_RV(t.SignUpdate(uint64(hSession), part))
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	t := current()
	if t == nil {
		return token.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulSignatureLen == nil {
		return token.CKR_ARGUMENTS_BAD
	}
	sig, needed, rv := t.SignFinal(uint64(hSession), int(*pulSignatureLen), pSignature == nil)
	return writeSignature(sig, needed, rv, pSignature, pulSignatureLen)
}

func writeSignature(sig []byte, needed int, rv uint64, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	switch {
	case rv == token.CKR_OK && pSignature == nil, rv == token.CKR_BUFFER_TOO_SMALL:
		*pulSignatureLen = C.CK_ULONG(needed)
	case rv == token.CKR_OK:
		C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
		*pulSignatureLen = C.CK_ULONG(len(sig))
	}
	return C.CK_RV(rv)
}
