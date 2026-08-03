// SPDX-License-Identifier: MPL-2.0

//go:build windows

package discovery

import (
	"context"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The real crypt32 read path (epic C1).
//
// This is the only file in the tree that touches the Windows certificate API,
// and it is deliberately small: open a store read-only, walk its contexts, copy
// each certificate's DER blob out, close. Nothing here exports, imports,
// deletes, or asks about a private key. A Windows certificate's key may live in
// a TPM or a smart card and be non-exportable by policy — this code does not
// care, because it never asks.
//
// CERT_STORE_READONLY_FLAG is not decoration. Opening the machine store
// writable would require privileges the agent should not hold and would make a
// bug in this file capable of damaging an estate's trust configuration. Read
// intent is declared to the platform, not just to the reader.

// platformWindowsCertReader returns the crypt32-backed reader on Windows.
func platformWindowsCertReader() windowsCertReader { return crypt32Reader{} }

type crypt32Reader struct{}

// storeLocationFlag maps a location to the crypt32 flag selecting its hierarchy.
func storeLocationFlag(location WindowsStoreLocation) (uint32, error) {
	switch location {
	case WindowsLocationLocalMachine:
		return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, nil
	case WindowsLocationCurrentUser:
		return windows.CERT_SYSTEM_STORE_CURRENT_USER, nil
	default:
		return 0, fmt.Errorf("discovery: unknown Windows store location %q", location)
	}
}

// readStore walks one system store and returns each certificate's DER blob.
//
// The label is the SHA-1 thumbprint the platform itself uses to identify a
// context, falling back to an index when a context has none. That makes the
// finding's location stable across passes — an operator diffing two inventories
// sees real change, not reordering — and unique within the store.
func (crypt32Reader) readStore(ctx context.Context, location WindowsStoreLocation, store string) (map[string][]byte, error) {
	flag, err := storeLocationFlag(location)
	if err != nil {
		return nil, err
	}
	storeName, err := windows.UTF16PtrFromString(store)
	if err != nil {
		return nil, fmt.Errorf("discovery: encode store name %q: %w", store, err)
	}
	handle, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		flag|windows.CERT_STORE_READONLY_FLAG|certStoreOpenExistingFlag,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		// An unopenable store is a source failure, never an empty inventory:
		// "we could not look" and "there is nothing there" must not read the
		// same to an operator.
		return nil, fmt.Errorf("discovery: open Windows store %s/%s: %w", location, store, err)
	}
	defer func() { _ = windows.CertCloseStore(handle, 0) }()

	out := map[string][]byte{}
	var certCtx *windows.CertContext
	index := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		certCtx, err = windows.CertEnumCertificatesInStore(handle, certCtx)
		if err != nil {
			if err == syscall.Errno(windows.CRYPT_E_NOT_FOUND) || err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("discovery: enumerate Windows store %s/%s: %w", location, store, err)
		}
		if certCtx == nil {
			break
		}
		// Copy the blob out of the context's memory: the context is freed by
		// the next enumeration step, and a retained slice would alias memory
		// the platform has reclaimed.
		encoded := unsafe.Slice(certCtx.EncodedCert, certCtx.Length)
		blob := make([]byte, len(encoded))
		copy(blob, encoded)

		// Label by enumeration index. The SOURCE relabels each finding by the
		// certificate's own fingerprint once it is parsed, which is stable
		// across passes and unique within the store — so there is no reason to
		// ask crypt32 for a thumbprint property, and no reason for this file to
		// compute a digest (AN-3 keeps hashing behind internal/crypto).
		out[strconv.Itoa(index)] = blob
		index++
	}
	return out, nil
}

// certStoreOpenExistingFlag refuses to CREATE a store that does not exist.
// Without it, asking for a misspelled store name silently succeeds against a
// brand-new empty store — the exact false-clean result this source must never
// produce.
const certStoreOpenExistingFlag uint32 = 0x00004000 // CERT_STORE_OPEN_EXISTING_FLAG
