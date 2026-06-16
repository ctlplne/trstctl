//go:build windows

package certstore

import (
	"encoding/pem"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/crypto/pfx"
)

// Windows is a CryptoAPI/CNG-backed certificate store. It installs certificates
// into a Windows system store (for example LocalMachine\MY) and, when a key is
// supplied, imports the certificate together with its private key via
// PFXImportCertStore — the idiomatic mechanism that persists the key (in a CNG
// container) and links it to the certificate. The key is imported
// non-exportable.
//
// This file compiles only for GOOS=windows; the Windows CI job builds it,
// exercises it against the per-user store, and the platform-neutral contract is
// also covered on every platform by the in-process Memory store. Keys and
// certificates are PEM bytes handed to the crypto boundary (internal/crypto/pfx)
// and to the OS; this file imports no crypto/* itself (AN-3).
type Windows struct{}

// NewWindows returns a CryptoAPI-backed certificate store.
func NewWindows() *Windows { return &Windows{} }

var _ destination.CertStore = (*Windows)(nil)

const (
	x509AndPKCS7Encoding   = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING
	certFriendlyNamePropID = 11
	certKeyProvInfoPropID  = 2
	certFindAny            = 0
	cryptUserKeyset        = 0x00001000 // CRYPT_USER_KEYSET
	cryptMachineKeyset     = 0x00000020 // CRYPT_MACHINE_KEYSET
)

var (
	modcrypt32                            = windows.NewLazySystemDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore  = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertAddCertificateContextToStore  = modcrypt32.NewProc("CertAddCertificateContextToStore")
	procCertSetCertificateContextProperty = modcrypt32.NewProc("CertSetCertificateContextProperty")
	procCertGetCertificateContextProperty = modcrypt32.NewProc("CertGetCertificateContextProperty")
	procCertDeleteCertificateFromStore    = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertFreeCertificateContext        = modcrypt32.NewProc("CertFreeCertificateContext")
	procPFXImportCertStore                = modcrypt32.NewProc("PFXImportCertStore")
)

// cryptDataBlob mirrors CRYPT_DATA_BLOB (used for the in-memory PFX and for
// property values).
type cryptDataBlob struct {
	cbData uint32
	pbData *byte
}

func locationFlag(loc destination.StoreLocation) uint32 {
	if loc == destination.CurrentUser {
		return windows.CERT_SYSTEM_STORE_CURRENT_USER
	}
	return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
}

func openSystemStore(ref destination.StoreRef) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(ref.Name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		locationFlag(ref.Location),
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		return 0, fmt.Errorf("certstore: open %s: %w", ref, err)
	}
	return h, nil
}

func setFriendlyName(ctx *windows.CertContext, name string) error {
	w, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	blob := cryptDataBlob{cbData: uint32(len(w) * 2), pbData: (*byte)(unsafe.Pointer(&w[0]))}
	r, _, e := procCertSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		uintptr(certFriendlyNamePropID),
		0,
		uintptr(unsafe.Pointer(&blob)),
	)
	if r == 0 {
		return fmt.Errorf("certstore: set friendly name: %w", e)
	}
	return nil
}

// AddCertificate adds a certificate to the store with no associated key.
func (w *Windows) AddCertificate(ref destination.StoreRef, friendlyName string, certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("certstore: no PEM certificate block")
	}
	store, err := openSystemStore(ref)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	var ctx *windows.CertContext
	r, _, e := procCertAddEncodedCertificateToStore.Call(
		uintptr(store),
		uintptr(x509AndPKCS7Encoding),
		uintptr(unsafe.Pointer(&block.Bytes[0])),
		uintptr(len(block.Bytes)),
		uintptr(windows.CERT_STORE_ADD_REPLACE_EXISTING),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r == 0 {
		return fmt.Errorf("certstore: CertAddEncodedCertificateToStore: %w", e)
	}
	defer procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
	return setFriendlyName(ctx, friendlyName)
}

// ImportWithKey installs the certificate together with its private key. It
// encodes a transient PFX (via the crypto boundary), imports it with
// PFXImportCertStore so the key is persisted non-exportable in a CNG container
// and linked to the certificate, then copies the key-bearing certificate into
// the destination system store.
func (w *Windows) ImportWithKey(ref destination.StoreRef, friendlyName string, certPEM, keyPEM []byte) error {
	pfxDER, password, err := pfx.EncodeTransient(keyPEM, certPEM)
	if err != nil {
		return fmt.Errorf("certstore: build PFX: %w", err)
	}
	pw, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	blob := cryptDataBlob{cbData: uint32(len(pfxDER)), pbData: &pfxDER[0]}

	keyset := uintptr(cryptUserKeyset)
	if ref.Location == destination.LocalMachine {
		keyset = cryptMachineKeyset
	}
	r, _, e := procPFXImportCertStore.Call(
		uintptr(unsafe.Pointer(&blob)),
		uintptr(unsafe.Pointer(pw)),
		keyset, // no CRYPT_EXPORTABLE: the key cannot be exported
	)
	if r == 0 {
		return fmt.Errorf("certstore: PFXImportCertStore: %w", e)
	}
	tempStore := windows.Handle(r)
	defer windows.CertCloseStore(tempStore, 0)

	// The PFX yields the leaf (with its linked key) and any CA certs; install
	// the key-bearing one.
	src := keyBearingCert(tempStore)
	if src == nil {
		return fmt.Errorf("certstore: imported PFX has no key-bearing certificate")
	}
	dest, err := openSystemStore(ref)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(dest, 0)

	var added *windows.CertContext
	if r2, _, e2 := procCertAddCertificateContextToStore.Call(
		uintptr(dest),
		uintptr(unsafe.Pointer(src)),
		uintptr(windows.CERT_STORE_ADD_REPLACE_EXISTING),
		uintptr(unsafe.Pointer(&added)),
	); r2 == 0 {
		return fmt.Errorf("certstore: CertAddCertificateContextToStore: %w", e2)
	}
	defer procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(added)))
	return setFriendlyName(added, friendlyName)
}

// keyBearingCert returns the certificate in store that has an associated
// private key (CERT_KEY_PROV_INFO), or nil. The returned context is owned by
// the store and freed when the store closes.
func keyBearingCert(store windows.Handle) *windows.CertContext {
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertFindCertificateInStore(store, x509AndPKCS7Encoding, 0, certFindAny, nil, prev)
		if err != nil || ctx == nil {
			return nil
		}
		prev = ctx
		if propPresent(ctx, certKeyProvInfoPropID) {
			return ctx
		}
	}
}

// Find returns the certificate stored under (ref, friendlyName) by enumerating
// the store and matching the friendly-name property.
func (w *Windows) Find(ref destination.StoreRef, friendlyName string) (destination.Entry, bool, error) {
	store, err := openSystemStore(ref)
	if err != nil {
		return destination.Entry{}, false, err
	}
	defer windows.CertCloseStore(store, 0)

	var prev *windows.CertContext
	for {
		ctx, err := windows.CertFindCertificateInStore(store, x509AndPKCS7Encoding, 0, certFindAny, nil, prev)
		if err != nil || ctx == nil {
			return destination.Entry{}, false, nil
		}
		prev = ctx
		if friendlyNameOf(ctx) != friendlyName {
			continue
		}
		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
		return destination.Entry{
			CertPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			HasPrivateKey: propPresent(ctx, certKeyProvInfoPropID),
			Exportable:    false,
			Ref:           ref,
		}, true, nil
	}
}

// Delete removes the certificate stored under (ref, friendlyName). It is a no-op
// if no such certificate exists. Used to uninstall a credential and to clean up
// after tests.
func (w *Windows) Delete(ref destination.StoreRef, friendlyName string) error {
	store, err := openSystemStore(ref)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	var prev *windows.CertContext
	for {
		ctx, err := windows.CertFindCertificateInStore(store, x509AndPKCS7Encoding, 0, certFindAny, nil, prev)
		if err != nil || ctx == nil {
			return nil
		}
		prev = ctx
		if friendlyNameOf(ctx) != friendlyName {
			continue
		}
		// CertDeleteCertificateFromStore frees ctx and ends the enumeration.
		if r, _, e := procCertDeleteCertificateFromStore.Call(uintptr(unsafe.Pointer(ctx))); r == 0 {
			return fmt.Errorf("certstore: delete %s\\%s: %w", ref, friendlyName, e)
		}
		return nil
	}
}

func getProp(ctx *windows.CertContext, propID uint32) ([]byte, bool) {
	var n uint32
	if r, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(propID), 0, uintptr(unsafe.Pointer(&n)),
	); r == 0 || n == 0 {
		return nil, false
	}
	buf := make([]byte, n)
	if r, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(propID), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
	); r == 0 {
		return nil, false
	}
	return buf[:n], true
}

func friendlyNameOf(ctx *windows.CertContext) string {
	b, ok := getProp(ctx, certFriendlyNamePropID)
	if !ok || len(b) < 2 {
		return ""
	}
	// The property is a little-endian UTF-16 string; decode it pair-by-pair
	// rather than reinterpreting the byte slice (which go vet flags).
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return windows.UTF16ToString(u16)
}

func propPresent(ctx *windows.CertContext, propID uint32) bool {
	_, ok := getProp(ctx, propID)
	return ok
}
