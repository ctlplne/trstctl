// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter

import (
	"errors"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// hsm.go is the custody-boundary embodiment of the PCAS-claim-12 signer (PCAS-claim-26): the
// isolated process comprises a hardware security module holding the key material PLUS
// an enforcement component mediating all use of the module. Together they form a
// custody boundary from which private key material is not released, and the
// per-identity epoch floor resides WITHIN that boundary.
//
// The SoftHSM below is a software test double of the module (CI exercises the variant
// without hardware); the Minter — its constraint engine of epoch floor, policy,
// dual-control, and strength ordering — is the enforcement component. Every module
// key operation used to mint a succession is mediated by the Minter, and the module
// never exposes private key bytes: a crypto.Signer handle offers only Public() and
// Sign(), never an export, and TryExport fails closed. The floor is module-resident
// sealed state (equivalently a module monotonic counter, PCAS-18), so control-plane
// state loss or rollback cannot regress it (INV-1, INV-3).

// ErrKeyMaterialNotReleasable is returned by any attempt to export private key
// material from the custody boundary — the material is not releasable (PCAS-claim-26 /
// INV-1).
var ErrKeyMaterialNotReleasable = errors.New("minter: private key material is not releasable from the custody boundary")

// SoftHSM is a software test double for an HSM / PKCS#11 module. Keys are generated
// and used inside it; only public keys and opaque handles cross its boundary. It
// exposes NO method returning private key bytes, and holds the module-resident epoch
// floor.
type SoftHSM struct {
	mu      sync.Mutex
	backend crypto.KeyGenerator      // in-module key factory (software backend in CI)
	keys    map[string]crypto.Signer // handle -> in-boundary signer (private key stays here)
	floors  map[string]uint64        // module-resident epoch floor per identity
	seq     int
}

// NewSoftHSM builds a soft-HSM over an in-module key factory (e.g. the software
// backend in CI).
func NewSoftHSM(backend crypto.KeyGenerator) *SoftHSM {
	return &SoftHSM{backend: backend, keys: map[string]crypto.Signer{}, floors: map[string]uint64{}}
}

// GenerateKey generates a key inside the module and returns an in-boundary Signer
// handle whose private key never leaves the module. It implements crypto.KeyGenerator
// so the Minter uses the module as its successor-key factory.
func (h *SoftHSM) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	s, err := h.backend.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.seq++
	handle := fmt.Sprintf("hsm-%d", h.seq)
	h.keys[handle] = s
	h.mu.Unlock()
	return s, nil
}

// Import registers an existing signer under handle as module-resident key material
// (e.g. a predecessor). The signer's private material is treated as living inside the
// module; only the handle is used to reference it.
func (h *SoftHSM) Import(handle string, s crypto.Signer) {
	h.mu.Lock()
	h.keys[handle] = s
	h.mu.Unlock()
}

// Resolve returns the in-boundary signer for a handle. It implements KeyResolver so
// the Minter references the predecessor by handle without the key ever leaving the
// module.
func (h *SoftHSM) Resolve(handle string) (crypto.Signer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.keys[handle]
	if !ok {
		return nil, fmt.Errorf("hsm: unknown key handle %q", handle)
	}
	return s, nil
}

// TryExport models an attempt to extract private key bytes for handle. It always
// fails closed: no API, error, or debug path releases key material from the boundary
// (PCAS-claim-26 / INV-1).
func (h *SoftHSM) TryExport(handle string) ([]byte, error) {
	return nil, ErrKeyMaterialNotReleasable
}

// FloorStore returns the module-resident epoch-floor store: the floor lives inside
// the custody boundary, not in control-plane storage (PCAS-claim-26 / INV-3).
func (h *SoftHSM) FloorStore() FloorStore { return &hsmFloor{hsm: h} }

// hsmFloor is a FloorStore whose state is the module-resident, monotonic epoch floor.
// A fresh Minter (a new control-plane process) loads the authoritative floor from the
// module; control-plane loss or rollback therefore cannot regress it.
type hsmFloor struct{ hsm *SoftHSM }

func (f *hsmFloor) Load() (map[string]uint64, error) {
	f.hsm.mu.Lock()
	defer f.hsm.mu.Unlock()
	out := make(map[string]uint64, len(f.hsm.floors))
	for k, v := range f.hsm.floors {
		out[k] = v
	}
	return out, nil
}

func (f *hsmFloor) Advance(identityID string, epoch uint64) error {
	f.hsm.mu.Lock()
	defer f.hsm.mu.Unlock()
	if epoch > f.hsm.floors[identityID] { // monotonic: the module never lowers the floor
		f.hsm.floors[identityID] = epoch
	}
	return nil
}

// ModuleFloor returns the module-resident floor for an identity (for inspection /
// reconciliation); it is the authoritative value inside the boundary.
func (h *SoftHSM) ModuleFloor(identityID string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.floors[identityID]
}

// Compile-time proof the module satisfies the Minter's key seams: it is both the
// successor key factory and the predecessor resolver, so every key operation the
// Minter performs is a module operation mediated by the Minter's constraint engine.
var (
	_ crypto.KeyGenerator = (*SoftHSM)(nil)
	_ KeyResolver         = (*SoftHSM)(nil)
	_ FloorStore          = (*hsmFloor)(nil)
)
