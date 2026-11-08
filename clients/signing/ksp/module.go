// SPDX-License-Identifier: MPL-2.0

//go:build cgo

// Command ksp is trstctl-ksp, a Windows CNG key storage provider through
// which signtool and other CNG signing tools sign with a key held in
// trstctl's isolated signer. The private key never leaves the signer: the
// provider sends the hash to trstctl's code-signing API and returns the
// signature, checked against the key's certificate first. Build it for 64-bit
// Windows with a MinGW-w64 compiler:
//
//	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -buildmode=c-shared -o trstctl-ksp.dll ./ksp
//
// TRSTCTL_URL names the control plane, TRSTCTL_TOKEN or TRSTCTL_TOKEN_FILE an
// API token with keys:read and keys:write, TRSTCTL_CA_FILE optional roots for
// its TLS certificate, and TRSTCTL_KSP_KEYS the code-signing keys
// (comma-separated) the provider offers as key containers, each needing a
// certificate chain configured in trstctl. A signature waiting for approval
// is held open for up to TRSTCTL_APPROVAL_WAIT (ten minutes by default).
package main

/*
#include <stdlib.h>
#include <string.h>
#include "ksp.h"
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"trstctl.com/clients/signing/internal/kspinfo"
	"trstctl.com/clients/signing/trstctlsign"
)

// ProviderName is the name the provider is registered and opened under.
const ProviderName = kspinfo.ProviderName

// CNG status values (winerror.h) and the flags and constants the provider
// uses.
const (
	nteBadFlags         = 0x80090009
	nteBadKeyset        = 0x80090016
	nteInvalidHandle    = 0x80090026
	nteInvalidParameter = 0x80090027
	nteBufferTooSmall   = 0x80090028
	nteNotSupported     = 0x80090029
	nteNoMoreItems      = 0x8009002A
	ntePerm             = 0x80090010
	nteFail             = 0x80090020
	nteNoMemory         = 0x8009000E

	bcryptPadPKCS1 = 0x2
	bcryptPadPSS   = 0x8

	ncryptAllowSigningFlag   = 0x2
	ncryptImplHardwareFlag   = 0x1
	ncryptSignatureOperation = 0x10
	bcryptSignatureInterface = 0x5

	bcryptRSAPublicMagic   = 0x31415352 // "RSA1"
	bcryptECDSAP256PubMagi = 0x31534345 // "ECS1"
)

func status(code uint32) C.KSP_STATUS { return C.KSP_STATUS(int32(code)) }

func main() {}

// signingKey is one opened key container: a trstctl code-signing key with
// its certificate chain.
type signingKey struct {
	id     string
	public crypto.PublicKey
	group  string // RSA or ECDSA
	alg    string // RSA or ECDSA_P256
	bits   int
	leaf   []byte
}

type provider struct {
	client *trstctlsign.Client
	keyIDs []string
}

type handles struct {
	mu        sync.Mutex
	next      uintptr
	providers map[uintptr]*provider
	keys      map[uintptr]*signingKey
}

var open = &handles{providers: map[uintptr]*provider{}, keys: map[uintptr]*signingKey{}}

func (h *handles) addProvider(p *provider) uintptr {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	h.providers[h.next] = p
	return h.next
}

func (h *handles) addKey(k *signingKey) uintptr {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	h.keys[h.next] = k
	return h.next
}

func (h *handles) provider(handle C.KSP_HANDLE) *provider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers[uintptr(handle)]
}

func (h *handles) key(handle C.KSP_HANDLE) *signingKey {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.keys[uintptr(handle)]
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "trstctl-ksp: "+format+"\n", args...)
}

// tracing is set by TRSTCTL_KSP_TRACE: every call CNG makes is logged with
// its names, flags and result, which shows what a signing tool asked of the
// provider.
var tracing = os.Getenv("TRSTCTL_KSP_TRACE") != ""

func traced(call string, rv C.KSP_STATUS, details ...any) C.KSP_STATUS {
	if !tracing {
		return rv
	}
	parts := make([]string, 0, len(details))
	for _, d := range details {
		switch v := d.(type) {
		case C.KSP_LPCWSTR:
			parts = append(parts, fmt.Sprintf("%q", goString(v)))
		case C.KSP_DWORD:
			parts = append(parts, fmt.Sprintf("0x%X", uint32(v)))
		}
	}
	logf("trace %s(%s) -> 0x%X", call, strings.Join(parts, ", "), uint32(rv))
	return rv
}

// goString reads a NUL-terminated UTF-16 string, bounded.
func goString(p C.KSP_LPCWSTR) string {
	if p == nil {
		return ""
	}
	var units []uint16
	for ptr := unsafe.Pointer(p); len(units) < 4096; ptr = unsafe.Add(ptr, 2) {
		u := *(*uint16)(ptr)
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// wide encodes s as NUL-terminated UTF-16LE bytes.
func wide(s string) []byte {
	units := append(utf16.Encode([]rune(s)), 0)
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

func dword(v uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, v)
	return out
}

// output answers CNG's two-call convention: a NULL buffer asks for the size,
// a short one is refused with the size it needs.
func output(value []byte, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD) C.KSP_STATUS {
	if pcbResult == nil {
		return status(nteInvalidParameter)
	}
	*pcbResult = C.KSP_DWORD(len(value))
	if pbOutput == nil {
		return 0
	}
	if int(cbOutput) < len(value) {
		return status(nteBufferTooSmall)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(pbOutput)), len(value)), value)
	return 0
}

func configuredKeys() []string {
	var out []string
	for _, id := range strings.Split(os.Getenv("TRSTCTL_KSP_KEYS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

//export kspOpenProvider
func kspOpenProvider(phProvider *C.KSP_HANDLE, pszProviderName C.KSP_LPCWSTR, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("OpenProvider", openProvider(phProvider, pszProviderName, dwFlags), pszProviderName, dwFlags)
}

func openProvider(phProvider *C.KSP_HANDLE, pszProviderName C.KSP_LPCWSTR, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if phProvider == nil {
		return status(nteInvalidParameter)
	}
	if name := goString(pszProviderName); name != "" && !strings.EqualFold(name, ProviderName) {
		return status(nteInvalidParameter)
	}
	client, err := trstctlsign.FromEnv()
	if err != nil {
		logf("%v", err)
		return status(nteFail)
	}
	client.Pending = func(message string) { logf("waiting for approval: %s", message) }
	*phProvider = C.KSP_HANDLE(open.addProvider(&provider{client: client, keyIDs: configuredKeys()}))
	return 0
}

// loadKey reads a configured key's certificate chain from trstctl.
func (p *provider) loadKey(id string) (*signingKey, C.KSP_STATUS) {
	offered := false
	for _, k := range p.keyIDs {
		offered = offered || k == id
	}
	if !offered {
		return nil, status(nteBadKeyset)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cert, err := p.client.KeyCertificate(ctx, id)
	if err != nil {
		logf("key %s: %v", id, err)
		return nil, status(nteBadKeyset)
	}
	chain := cert.ChainDER()
	if len(chain) == 0 {
		logf("key %s has no certificate chain configured in trstctl", id)
		return nil, status(nteBadKeyset)
	}
	pub, err := x509.ParsePKIXPublicKey(cert.PublicKeyDER)
	if err != nil {
		logf("key %s: public key: %v", id, err)
		return nil, status(nteBadKeyset)
	}
	k := &signingKey{id: id, public: pub, leaf: chain[0]}
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			logf("key %s: only ECDSA P-256 is offered", id)
			return nil, status(nteNotSupported)
		}
		k.group, k.alg, k.bits = "ECDSA", "ECDSA_P256", 256
	case *rsa.PublicKey:
		k.group, k.alg, k.bits = "RSA", "RSA", pk.N.BitLen()
	default:
		logf("key %s: unsupported key type", id)
		return nil, status(nteNotSupported)
	}
	return k, 0
}

//export kspOpenKey
func kspOpenKey(hProvider C.KSP_HANDLE, phKey *C.KSP_HANDLE, pszKeyName C.KSP_LPCWSTR, dwLegacyKeySpec C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("OpenKey", openKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags), pszKeyName, dwLegacyKeySpec, dwFlags)
}

func openKey(hProvider C.KSP_HANDLE, phKey *C.KSP_HANDLE, pszKeyName C.KSP_LPCWSTR, dwLegacyKeySpec C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	p := open.provider(hProvider)
	if p == nil {
		return status(nteInvalidHandle)
	}
	if phKey == nil || pszKeyName == nil {
		return status(nteInvalidParameter)
	}
	k, rv := p.loadKey(goString(pszKeyName))
	if rv != 0 {
		return rv
	}
	*phKey = C.KSP_HANDLE(open.addKey(k))
	return 0
}

//export kspCreatePersistedKey
func kspCreatePersistedKey(hProvider C.KSP_HANDLE, phKey *C.KSP_HANDLE, pszAlgId C.KSP_LPCWSTR, pszKeyName C.KSP_LPCWSTR, dwLegacyKeySpec C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("CreatePersistedKey", createPersistedKey(hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags), pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags)
}

func createPersistedKey(hProvider C.KSP_HANDLE, phKey *C.KSP_HANDLE, pszAlgId C.KSP_LPCWSTR, pszKeyName C.KSP_LPCWSTR, dwLegacyKeySpec C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	// Keys are made in trstctl's signer, never through the provider.
	return status(nteNotSupported)
}

//export kspGetProviderProperty
func kspGetProviderProperty(hProvider C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("GetProviderProperty", getProviderProperty(hProvider, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags), pszProperty, dwFlags)
}

func getProviderProperty(hProvider C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil {
		return status(nteInvalidHandle)
	}
	var value []byte
	switch goString(pszProperty) {
	case "Name":
		value = wide(ProviderName)
	case "Version":
		value = dword(0x00010000)
	case "Impl Type":
		value = dword(ncryptImplHardwareFlag)
	case "Max Name Length":
		value = dword(255)
	default:
		return status(nteNotSupported)
	}
	return output(value, pbOutput, cbOutput, pcbResult)
}

//export kspGetKeyProperty
func kspGetKeyProperty(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("GetKeyProperty", getKeyProperty(hProvider, hKey, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags), pszProperty, dwFlags)
}

func getKeyProperty(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil {
		return status(nteInvalidHandle)
	}
	k := open.key(hKey)
	if k == nil {
		return status(nteInvalidHandle)
	}
	var value []byte
	switch goString(pszProperty) {
	case "Algorithm Group":
		value = wide(k.group)
	case "Algorithm Name":
		value = wide(k.alg)
	case "Length":
		value = dword(uint32(k.bits)) // #nosec G115 -- RSA and P-256 key sizes fit 32 bits
	case "Key Usage":
		value = dword(ncryptAllowSigningFlag)
	case "Export Policy":
		value = dword(0) // never exportable
	case "Name", "Unique Name":
		value = wide(k.id)
	case "Key Type":
		value = dword(0) // a user key, not a machine key
	case "Impl Type":
		value = dword(ncryptImplHardwareFlag)
	case "SmartCardKeyCertificate":
		value = append([]byte(nil), k.leaf...)
	default:
		return status(nteNotSupported)
	}
	return output(value, pbOutput, cbOutput, pcbResult)
}

// settableProperties are the window and context hints CNG callers set; the
// provider shows no UI, so it records nothing.
var settableProperties = map[string]bool{"HWND Handle": true, "Use Context": true, "Window Handle": true}

//export kspSetProviderProperty
func kspSetProviderProperty(hProvider C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("SetProviderProperty", setProviderProperty(hProvider, pszProperty, pbInput, cbInput, dwFlags), pszProperty, dwFlags)
}

func setProviderProperty(hProvider C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil {
		return status(nteInvalidHandle)
	}
	if settableProperties[goString(pszProperty)] {
		return 0
	}
	return status(nteNotSupported)
}

//export kspSetKeyProperty
func kspSetKeyProperty(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("SetKeyProperty", setKeyProperty(hProvider, hKey, pszProperty, pbInput, cbInput, dwFlags), pszProperty, dwFlags)
}

func setKeyProperty(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pszProperty C.KSP_LPCWSTR, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil || open.key(hKey) == nil {
		return status(nteInvalidHandle)
	}
	if settableProperties[goString(pszProperty)] {
		return 0
	}
	return status(nteNotSupported)
}

//export kspFinalizeKey
func kspFinalizeKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("FinalizeKey", finalizeKey(hProvider, hKey, dwFlags), dwFlags)
}

func finalizeKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspDeleteKey
func kspDeleteKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("DeleteKey", deleteKey(hProvider, hKey, dwFlags), dwFlags)
}

func deleteKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspFreeProvider
func kspFreeProvider(hProvider C.KSP_HANDLE) C.KSP_STATUS {
	return traced("FreeProvider", freeProvider(hProvider))
}

func freeProvider(hProvider C.KSP_HANDLE) C.KSP_STATUS {
	open.mu.Lock()
	defer open.mu.Unlock()
	if open.providers[uintptr(hProvider)] == nil {
		return status(nteInvalidHandle)
	}
	delete(open.providers, uintptr(hProvider))
	return 0
}

//export kspFreeKey
func kspFreeKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE) C.KSP_STATUS {
	return traced("FreeKey", freeKey(hProvider, hKey))
}

func freeKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE) C.KSP_STATUS {
	open.mu.Lock()
	defer open.mu.Unlock()
	if open.keys[uintptr(hKey)] == nil {
		return status(nteInvalidHandle)
	}
	delete(open.keys, uintptr(hKey))
	return 0
}

//export kspFreeBuffer
func kspFreeBuffer(pvInput unsafe.Pointer) C.KSP_STATUS {
	return traced("FreeBuffer", freeBuffer(pvInput))
}

func freeBuffer(pvInput unsafe.Pointer) C.KSP_STATUS {
	C.free(pvInput)
	return 0
}

//export kspEncrypt
func kspEncrypt(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, pPaddingInfo unsafe.Pointer, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("Encrypt", encrypt(hProvider, hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags), dwFlags)
}

func encrypt(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, pPaddingInfo unsafe.Pointer, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspDecrypt
func kspDecrypt(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, pPaddingInfo unsafe.Pointer, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("Decrypt", decrypt(hProvider, hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags), dwFlags)
}

func decrypt(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pbInput *C.KSP_BYTE, cbInput C.KSP_DWORD, pPaddingInfo unsafe.Pointer, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspIsAlgSupported
func kspIsAlgSupported(hProvider C.KSP_HANDLE, pszAlgId C.KSP_LPCWSTR, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("IsAlgSupported", isAlgSupported(hProvider, pszAlgId, dwFlags), pszAlgId, dwFlags)
}

func isAlgSupported(hProvider C.KSP_HANDLE, pszAlgId C.KSP_LPCWSTR, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	switch goString(pszAlgId) {
	case "RSA", "ECDSA_P256":
		return 0
	}
	return status(nteNotSupported)
}

// cWide copies s as NUL-terminated UTF-16 into C memory at dst.
func cWide(dst unsafe.Pointer, s string) {
	encoded := wide(s)
	copy(unsafe.Slice((*byte)(dst), len(encoded)), encoded)
}

//export kspEnumAlgorithms
func kspEnumAlgorithms(hProvider C.KSP_HANDLE, dwAlgOperations C.KSP_DWORD, pdwAlgCount *C.KSP_DWORD, ppAlgList **C.KSP_ALGORITHM_NAME, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("EnumAlgorithms", enumAlgorithms(hProvider, dwAlgOperations, pdwAlgCount, ppAlgList, dwFlags), dwAlgOperations, dwFlags)
}

func enumAlgorithms(hProvider C.KSP_HANDLE, dwAlgOperations C.KSP_DWORD, pdwAlgCount *C.KSP_DWORD, ppAlgList **C.KSP_ALGORITHM_NAME, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil {
		return status(nteInvalidHandle)
	}
	if pdwAlgCount == nil || ppAlgList == nil {
		return status(nteInvalidParameter)
	}
	names := []string{"RSA", "ECDSA_P256"}
	if dwAlgOperations != 0 && dwAlgOperations&ncryptSignatureOperation == 0 {
		names = nil
	}
	// One allocation holds the array and its strings, so one FreeBuffer
	// frees it.
	entry := C.size_t(unsafe.Sizeof(C.KSP_ALGORITHM_NAME{}))
	size := entry * C.size_t(len(names))
	for _, n := range names {
		size += C.size_t(len(wide(n)))
	}
	block := C.malloc(size + 1)
	if block == nil {
		return status(nteNoMemory)
	}
	list := unsafe.Slice((*C.KSP_ALGORITHM_NAME)(block), len(names))
	text := unsafe.Add(block, int(entry)*len(names))
	for i, n := range names {
		cWide(text, n)
		list[i].pszName = (*C.KSP_WCHAR)(text)
		list[i].dwClass = bcryptSignatureInterface
		list[i].dwAlgOperations = ncryptSignatureOperation
		list[i].dwFlags = 0
		text = unsafe.Add(text, len(wide(n)))
	}
	*pdwAlgCount = C.KSP_DWORD(len(names))
	*ppAlgList = (*C.KSP_ALGORITHM_NAME)(block)
	return 0
}

//export kspEnumKeys
func kspEnumKeys(hProvider C.KSP_HANDLE, pszScope C.KSP_LPCWSTR, ppKeyName **C.KSP_KEY_NAME, ppEnumState *unsafe.Pointer, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("EnumKeys", enumKeys(hProvider, pszScope, ppKeyName, ppEnumState, dwFlags), pszScope, dwFlags)
}

func enumKeys(hProvider C.KSP_HANDLE, pszScope C.KSP_LPCWSTR, ppKeyName **C.KSP_KEY_NAME, ppEnumState *unsafe.Pointer, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	p := open.provider(hProvider)
	if p == nil {
		return status(nteInvalidHandle)
	}
	if ppKeyName == nil || ppEnumState == nil {
		return status(nteInvalidParameter)
	}
	// The enumeration state is the index of the next key, in C memory the
	// caller frees with FreeBuffer.
	if *ppEnumState == nil {
		state := C.malloc(C.size_t(unsafe.Sizeof(C.KSP_DWORD(0))))
		if state == nil {
			return status(nteNoMemory)
		}
		*(*C.KSP_DWORD)(state) = 0
		*ppEnumState = state
	}
	index := (*C.KSP_DWORD)(*ppEnumState)
	for int(*index) < len(p.keyIDs) {
		id := p.keyIDs[*index]
		*index++
		k, rv := p.loadKey(id)
		if rv != 0 {
			continue
		}
		entry := C.size_t(unsafe.Sizeof(C.KSP_KEY_NAME{}))
		name, alg := wide(k.id), wide(k.alg)
		block := C.malloc(entry + C.size_t(len(name)+len(alg)))
		if block == nil {
			return status(nteNoMemory)
		}
		out := (*C.KSP_KEY_NAME)(block)
		nameAt := unsafe.Add(block, int(entry))
		algAt := unsafe.Add(nameAt, len(name))
		cWide(nameAt, k.id)
		cWide(algAt, k.alg)
		out.pszName = (*C.KSP_WCHAR)(nameAt)
		out.pszAlgid = (*C.KSP_WCHAR)(algAt)
		out.dwLegacyKeySpec = 0
		out.dwFlags = 0
		*ppKeyName = out
		return 0
	}
	return status(nteNoMoreItems)
}

//export kspImportKey
func kspImportKey(hProvider C.KSP_HANDLE, hImportKey C.KSP_HANDLE, pszBlobType C.KSP_LPCWSTR, pParameterList unsafe.Pointer, phKey *C.KSP_HANDLE, pbData *C.KSP_BYTE, cbData C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("ImportKey", importKey(hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbData, cbData, dwFlags), pszBlobType, dwFlags)
}

func importKey(hProvider C.KSP_HANDLE, hImportKey C.KSP_HANDLE, pszBlobType C.KSP_LPCWSTR, pParameterList unsafe.Pointer, phKey *C.KSP_HANDLE, pbData *C.KSP_BYTE, cbData C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

// publicBlob is the key's public key as a BCRYPT_RSAPUBLIC_BLOB or
// BCRYPT_ECCPUBLIC_BLOB.
func (k *signingKey) publicBlob(blobType string) ([]byte, bool) {
	switch pk := k.public.(type) {
	case *rsa.PublicKey:
		if blobType != "PUBLICBLOB" && blobType != "RSAPUBLICBLOB" {
			return nil, false
		}
		exponent := big.NewInt(int64(pk.E)).Bytes()
		modulus := pk.N.Bytes()
		out := make([]byte, 0, 24+len(exponent)+len(modulus))
		for _, v := range []uint32{bcryptRSAPublicMagic, uint32(pk.N.BitLen()), uint32(len(exponent)), uint32(len(modulus)), 0, 0} { // #nosec G115 -- RSA sizes fit 32 bits
			out = append(out, dword(v)...)
		}
		return append(append(out, exponent...), modulus...), true
	case *ecdsa.PublicKey:
		if blobType != "PUBLICBLOB" && blobType != "ECCPUBLICBLOB" {
			return nil, false
		}
		out := append(dword(bcryptECDSAP256PubMagi), dword(32)...)
		x, y := make([]byte, 32), make([]byte, 32)
		pk.X.FillBytes(x)
		pk.Y.FillBytes(y)
		return append(append(out, x...), y...), true
	}
	return nil, false
}

//export kspExportKey
func kspExportKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, hExportKey C.KSP_HANDLE, pszBlobType C.KSP_LPCWSTR, pParameterList unsafe.Pointer, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("ExportKey", exportKey(hProvider, hKey, hExportKey, pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags), pszBlobType, dwFlags)
}

func exportKey(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, hExportKey C.KSP_HANDLE, pszBlobType C.KSP_LPCWSTR, pParameterList unsafe.Pointer, pbOutput *C.KSP_BYTE, cbOutput C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil {
		return status(nteInvalidHandle)
	}
	k := open.key(hKey)
	if k == nil {
		return status(nteInvalidHandle)
	}
	if hExportKey != 0 {
		return status(nteNotSupported)
	}
	// Only the public key: the private key is not here to export.
	blob, ok := k.publicBlob(goString(pszBlobType))
	if !ok {
		return status(nteNotSupported)
	}
	return output(blob, pbOutput, cbOutput, pcbResult)
}

// signatureLength is the size of the key's CNG signature.
func (k *signingKey) signatureLength() int {
	if k.group == "ECDSA" {
		return 64
	}
	return (k.bits + 7) / 8
}

// checkPadding accepts PKCS #1 v1.5 with SHA-256 for RSA, and none for ECDSA;
// both sign a 32-byte SHA-256 hash.
func (k *signingKey) checkPadding(pPaddingInfo unsafe.Pointer, cbHash C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if cbHash != 32 {
		return status(nteNotSupported)
	}
	if k.group == "ECDSA" {
		if dwFlags&(bcryptPadPKCS1|bcryptPadPSS) != 0 {
			return status(nteBadFlags)
		}
		return 0
	}
	if dwFlags&bcryptPadPSS != 0 || dwFlags&bcryptPadPKCS1 == 0 || pPaddingInfo == nil {
		return status(nteNotSupported)
	}
	if goString((*C.KSP_PKCS1_PADDING_INFO)(pPaddingInfo).pszAlgId) != "SHA256" {
		return status(nteNotSupported)
	}
	return 0
}

//export kspSignHash
func kspSignHash(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pPaddingInfo unsafe.Pointer, pbHashValue *C.KSP_BYTE, cbHashValue C.KSP_DWORD, pbSignature *C.KSP_BYTE, cbSignature C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("SignHash", signHash(hProvider, hKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, pcbResult, dwFlags), dwFlags)
}

func signHash(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pPaddingInfo unsafe.Pointer, pbHashValue *C.KSP_BYTE, cbHashValue C.KSP_DWORD, pbSignature *C.KSP_BYTE, cbSignature C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	p := open.provider(hProvider)
	if p == nil {
		return status(nteInvalidHandle)
	}
	k := open.key(hKey)
	if k == nil {
		return status(nteInvalidHandle)
	}
	if pbHashValue == nil || pcbResult == nil {
		return status(nteInvalidParameter)
	}
	if rv := k.checkPadding(pPaddingInfo, cbHashValue, dwFlags); rv != 0 {
		return rv
	}
	length := k.signatureLength()
	*pcbResult = C.KSP_DWORD(length) // #nosec G115 -- a signature length fits 32 bits
	if pbSignature == nil {
		return 0
	}
	if int(cbSignature) < length {
		return status(nteBufferTooSmall)
	}
	hash := C.GoBytes(unsafe.Pointer(pbHashValue), C.int(cbHashValue))
	ctx, cancel := context.WithTimeout(context.Background(), p.client.ApprovalWait+2*time.Minute)
	defer cancel()
	artifact := "ksp:RSA_PKCS1_SHA256"
	if k.group == "ECDSA" {
		artifact = "ksp:ECDSA_P256_SHA256"
	}
	signed, err := p.client.SignDigest(ctx, k.id, artifact, hash)
	if err != nil {
		var refused *trstctlsign.APIError
		if errors.As(err, &refused) {
			logf("trstctl refused the signature: %v", err)
			return status(ntePerm)
		}
		logf("sign with %s: %v", k.id, err)
		return status(nteFail)
	}
	sig, err := k.finish(hash, signed.Signature)
	if err != nil {
		logf("%v", err)
		return status(nteFail)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(pbSignature)), len(sig)), sig)
	return 0
}

// finish checks trstctl's signature against the key's certificate and
// returns it in CNG's form: r||s for ECDSA, as-is for RSA.
func (k *signingKey) finish(hash, signature []byte) ([]byte, error) {
	switch pub := k.public.(type) {
	case *ecdsa.PublicKey:
		var sig struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(signature, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
			return nil, errors.New("trstctl returned a signature that is not an ASN.1 ECDSA signature")
		}
		if !ecdsa.Verify(pub, hash, sig.R, sig.S) {
			return nil, errors.New("trstctl's signature does not verify against the key's certificate")
		}
		out := make([]byte, 64)
		sig.R.FillBytes(out[:32])
		sig.S.FillBytes(out[32:])
		return out, nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, signature); err != nil {
			return nil, errors.New("trstctl's signature does not verify against the key's certificate")
		}
		return signature, nil
	}
	return nil, errors.New("unsupported key type")
}

//export kspVerifySignature
func kspVerifySignature(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pPaddingInfo unsafe.Pointer, pbHashValue *C.KSP_BYTE, cbHashValue C.KSP_DWORD, pbSignature *C.KSP_BYTE, cbSignature C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("VerifySignature", verifySignature(hProvider, hKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags), dwFlags)
}

func verifySignature(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pPaddingInfo unsafe.Pointer, pbHashValue *C.KSP_BYTE, cbHashValue C.KSP_DWORD, pbSignature *C.KSP_BYTE, cbSignature C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	if open.provider(hProvider) == nil {
		return status(nteInvalidHandle)
	}
	k := open.key(hKey)
	if k == nil {
		return status(nteInvalidHandle)
	}
	if pbHashValue == nil || pbSignature == nil {
		return status(nteInvalidParameter)
	}
	if rv := k.checkPadding(pPaddingInfo, cbHashValue, dwFlags); rv != 0 {
		return rv
	}
	hash := C.GoBytes(unsafe.Pointer(pbHashValue), C.int(cbHashValue))
	sig := C.GoBytes(unsafe.Pointer(pbSignature), C.int(cbSignature))
	switch pub := k.public.(type) {
	case *ecdsa.PublicKey:
		if len(sig) == 64 && ecdsa.Verify(pub, hash, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return 0
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, sig) == nil {
			return 0
		}
	}
	return status(0x80090006) // NTE_BAD_SIGNATURE
}

//export kspPromptUser
func kspPromptUser(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pszOperation C.KSP_LPCWSTR, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("PromptUser", promptUser(hProvider, hKey, pszOperation, dwFlags), pszOperation, dwFlags)
}

func promptUser(hProvider C.KSP_HANDLE, hKey C.KSP_HANDLE, pszOperation C.KSP_LPCWSTR, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspNotifyChangeKey
func kspNotifyChangeKey(hProvider C.KSP_HANDLE, phEvent *unsafe.Pointer, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("NotifyChangeKey", notifyChangeKey(hProvider, phEvent, dwFlags), dwFlags)
}

func notifyChangeKey(hProvider C.KSP_HANDLE, phEvent *unsafe.Pointer, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspSecretAgreement
func kspSecretAgreement(hProvider C.KSP_HANDLE, hPrivKey C.KSP_HANDLE, hPubKey C.KSP_HANDLE, phAgreedSecret *C.KSP_HANDLE, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("SecretAgreement", secretAgreement(hProvider, hPrivKey, hPubKey, phAgreedSecret, dwFlags), dwFlags)
}

func secretAgreement(hProvider C.KSP_HANDLE, hPrivKey C.KSP_HANDLE, hPubKey C.KSP_HANDLE, phAgreedSecret *C.KSP_HANDLE, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspDeriveKey
func kspDeriveKey(hProvider C.KSP_HANDLE, hSharedSecret C.KSP_HANDLE, pwszKDF C.KSP_LPCWSTR, pParameterList unsafe.Pointer, pbDerivedKey *C.KSP_BYTE, cbDerivedKey C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return traced("DeriveKey", deriveKey(hProvider, hSharedSecret, pwszKDF, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags), pwszKDF, dwFlags)
}

func deriveKey(hProvider C.KSP_HANDLE, hSharedSecret C.KSP_HANDLE, pwszKDF C.KSP_LPCWSTR, pParameterList unsafe.Pointer, pbDerivedKey *C.KSP_BYTE, cbDerivedKey C.KSP_DWORD, pcbResult *C.KSP_DWORD, dwFlags C.KSP_DWORD) C.KSP_STATUS {
	return status(nteNotSupported)
}

//export kspFreeSecret
func kspFreeSecret(hProvider C.KSP_HANDLE, hSharedSecret C.KSP_HANDLE) C.KSP_STATUS {
	return traced("FreeSecret", freeSecret(hProvider, hSharedSecret))
}

func freeSecret(hProvider C.KSP_HANDLE, hSharedSecret C.KSP_HANDLE) C.KSP_STATUS {
	return status(nteNotSupported)
}
