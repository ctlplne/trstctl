// SPDX-License-Identifier: BUSL-1.1

package destination

import (
	"context"
	"errors"
)

// StoreLocation is a Windows certificate-store location: per-machine
// (LocalMachine) or per-user (CurrentUser).
type StoreLocation string

const (
	// LocalMachine is the machine-wide store (HKLM); keys imported here are
	// non-exportable by default and require administrative rights.
	LocalMachine StoreLocation = "LocalMachine"
	// CurrentUser is the per-user store (HKCU).
	CurrentUser StoreLocation = "CurrentUser"
)

// StoreRef identifies a Windows certificate store by location and name, for
// example {LocalMachine, "MY"} for the machine Personal store.
type StoreRef struct {
	Location StoreLocation
	Name     string
}

// String renders the store as "Location\Name" (for example "LocalMachine\MY").
func (r StoreRef) String() string { return string(r.Location) + `\` + r.Name }

// Entry is a certificate found in a Windows store, with the custody facts that
// matter for verification: whether it has an associated private key and whether
// that key can be exported.
type Entry struct {
	CertPEM       []byte
	HasPrivateKey bool
	Exportable    bool
	Ref           StoreRef
}

// CertStore is the subset of the Windows certificate store the WindowsCertStore
// destination drives. The production implementation wraps CryptoAPI/CNG via
// golang.org/x/sys/windows (build-tagged for Windows); tests and non-Windows
// builds use the in-process store in the certstore subpackage.
type CertStore interface {
	// AddCertificate adds a PEM certificate to (ref) under friendlyName, with
	// no associated private key.
	AddCertificate(ref StoreRef, friendlyName string, certPEM []byte) error
	// ImportWithKey adds a PEM certificate and associates its PEM private key,
	// stored non-exportable (the machine-store default).
	ImportWithKey(ref StoreRef, friendlyName string, certPEM, keyPEM []byte) error
	// Find returns the certificate stored under (ref, friendlyName).
	Find(ref StoreRef, friendlyName string) (Entry, bool, error)
}

// WindowsCertStore installs a credential into a Windows certificate store: the
// certificate as a store entry and, when the credential carries one, its key
// associated to that entry under hardware/OS custody (non-exportable).
type WindowsCertStore struct {
	store        CertStore
	ref          StoreRef
	friendlyName string
}

var _ Destination = (*WindowsCertStore)(nil)

// NewWindowsCertStore returns a destination that installs into store at ref,
// labeling the entry with friendlyName (how a workload locates its cert).
func NewWindowsCertStore(store CertStore, ref StoreRef, friendlyName string) *WindowsCertStore {
	return &WindowsCertStore{store: store, ref: ref, friendlyName: friendlyName}
}

// Install adds the certificate to the store, associating the key when present.
func (w *WindowsCertStore) Install(_ context.Context, cred Credential) error {
	if len(cred.CertPEM) == 0 {
		return errors.New("destination: nothing to install (empty certificate)")
	}
	if cred.HasKey() {
		return w.store.ImportWithKey(w.ref, w.friendlyName, cred.CertPEM, cred.KeyPEM)
	}
	return w.store.AddCertificate(w.ref, w.friendlyName, cred.CertPEM)
}

// Describe returns a short identifier for the destination.
func (w *WindowsCertStore) Describe() string {
	return "windows-cert-store(" + w.ref.String() + `\` + w.friendlyName + ")"
}
