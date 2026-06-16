// Package certstore provides Windows certificate-store backends for the
// WindowsCertStore destination: an in-process software store (Memory) used by
// tests and non-Windows builds, and a CryptoAPI-backed store (capi_windows.go)
// for real Windows agents.
//
// The software store models the store identity (location + name) and the
// custody facts the destination cares about — whether an entry has an
// associated private key and whether that key is exportable — and enforces the
// machine-store invariant that an imported key is non-exportable. Certificates
// are opaque PEM bytes, copied in and out, so this file holds no crypto/*
// imports (AN-3).
package certstore

import (
	"context"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/agent/destination"
)

type entry struct {
	cert       []byte
	hasKey     bool
	exportable bool
}

// Memory is an in-process software certificate store. The zero value is not
// usable; call NewMemory.
type Memory struct {
	mu sync.RWMutex
	// entries keyed by store ref, then friendly name.
	entries map[string]map[string]entry
}

var _ destination.CertStore = (*Memory)(nil)

// NewMemory returns an empty software certificate store.
func NewMemory() *Memory {
	return &Memory{entries: make(map[string]map[string]entry)}
}

func (m *Memory) put(ref destination.StoreRef, name string, e entry) {
	key := ref.String()
	if m.entries[key] == nil {
		m.entries[key] = make(map[string]entry)
	}
	m.entries[key][name] = e
}

// AddCertificate stores a certificate with no associated key.
func (m *Memory) AddCertificate(ref destination.StoreRef, friendlyName string, certPEM []byte) error {
	if len(certPEM) == 0 {
		return fmt.Errorf("certstore: empty certificate for %s\\%s", ref, friendlyName)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.put(ref, friendlyName, entry{cert: clone(certPEM)})
	return nil
}

// ImportWithKey stores a certificate and associates its key, non-exportable —
// the default for a key imported into a machine store.
func (m *Memory) ImportWithKey(ref destination.StoreRef, friendlyName string, certPEM, keyPEM []byte) error {
	if len(certPEM) == 0 {
		return fmt.Errorf("certstore: empty certificate for %s\\%s", ref, friendlyName)
	}
	if len(keyPEM) == 0 {
		return fmt.Errorf("certstore: ImportWithKey with no key for %s\\%s", ref, friendlyName)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.put(ref, friendlyName, entry{cert: clone(certPEM), hasKey: true, exportable: false})
	return nil
}

// Find returns the certificate stored under (ref, friendlyName).
func (m *Memory) Find(ref destination.StoreRef, friendlyName string) (destination.Entry, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[ref.String()][friendlyName]
	if !ok {
		return destination.Entry{}, false, nil
	}
	return destination.Entry{
		CertPEM:       clone(e.cert),
		HasPrivateKey: e.hasKey,
		Exportable:    e.exportable,
		Ref:           ref,
	}, true, nil
}

// EnumerateCertificates returns every certificate in the store, keyed by its
// friendly name, as PEM — the read side used by agent discovery (S6.2). Entries
// across all store refs are flattened; the real CryptoAPI store enumerates a
// single named store.
func (m *Memory) EnumerateCertificates(_ context.Context) (map[string][]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]byte)
	for _, byName := range m.entries {
		for name, e := range byName {
			out[name] = clone(e.cert)
		}
	}
	return out, nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
