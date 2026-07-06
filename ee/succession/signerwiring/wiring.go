// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"errors"
	"sync"

	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// Config configures the production succession minter attached to the isolated
// signer (INT-02). All fields are optional; the zero value yields a working minter
// with interim in-memory defaults that later cards harden (durable floor at INT-05,
// PKCS#11/KMS key backend at INT-07, mandatory attestation at INT-11).
type Config struct {
	// SignerID identifies this signer; bound into signer attestations when an
	// AttestSigner is set.
	SignerID string
	// Keygen generates successor keys INSIDE the signer. Default: software backend.
	// INT-07 replaces this with a module-resident (PKCS#11/KMS) backend.
	Keygen crypto.KeyGenerator
	// Floors is the per-identity epoch floor. Default: interim in-memory (or durable
	// when FloorDir is set, INT-05).
	Floors minter.FloorStore
	// FloorDir, when set and Floors is nil, selects a DURABLE, restart-surviving
	// file-backed epoch floor under this directory within the signer custody boundary
	// (INT-05, claim 21). Empty (and Floors nil) => interim in-memory floor.
	FloorDir string
	// AttestSigner, when set, countersigns every minted record with the signer's
	// attestation key. INT-11 makes attestation mandatory with a frozen vector.
	AttestSigner crypto.Signer
}

// NewProductionMinter builds a fully-gated succession minter for attachment to the
// isolated signer via signing.WithSuccessionMinter. Strength-ordered downgrade
// refusal is on by default. The minter's predecessor resolver is intentionally
// left unbound: the signer injects its own key custody at attach time
// (UsePredecessorResolver), so a minter that is never attached fails closed rather
// than resolving predecessors from any control-plane-supplied source.
func NewProductionMinter(cfg Config) (*ProductionMinter, error) {
	keygen := cfg.Keygen
	if keygen == nil {
		keygen = crypto.NewSoftwareBackend()
	}
	floors := cfg.Floors
	if floors == nil {
		if cfg.FloorDir != "" {
			df, err := minter.NewDurableFloorStore(cfg.FloorDir)
			if err != nil {
				return nil, err
			}
			floors = df
		} else {
			floors = newInterimFloorStore()
		}
	}
	opts := []minter.Option{
		// Downgrade refusal on by default (claim 17): a weaker-class successor is
		// refused unless a break-glass token is presented (none configured here).
		minter.WithStrengthOrdering(nil),
	}
	if cfg.AttestSigner != nil {
		opts = append(opts, minter.WithAttestation(cfg.AttestSigner, cfg.SignerID))
	}
	m, err := minter.New(unboundResolver{}, keygen, floors, opts...)
	if err != nil {
		return nil, err
	}
	return &ProductionMinter{Minter: m}, nil
}

// ProductionMinter is a succession minter for attachment to the isolated signer. It
// embeds the base minter (so it satisfies signing.SuccessionMinter) and additionally
// accepts the signer's own key custody as its predecessor resolver at attach time,
// via the signer's resolver-injection seam (INT-02). A bare minter.Minter is not
// resolver-aware and keeps whatever resolver it was built with.
type ProductionMinter struct{ *minter.Minter }

// UseSignerCustody binds the signer's key custody into this minter: predecessor
// handles resolve against keys the signer holds, and successor keys are generated
// and PERSISTED in the signer keystore under their per-epoch handle (INT-03). The
// signer calls it once at construction, before serving.
func (p *ProductionMinter) UseSignerCustody(c signing.SignerCustody) {
	p.Minter.SetPredecessorResolver(predecessorResolverAdapter{r: c})
	p.Minter.SetSuccessorKeyStore(c)
}

// predecessorResolverAdapter adapts the signer's PredecessorResolver to the minter's
// KeyResolver — both resolve a handle to a message Signer.
type predecessorResolverAdapter struct{ r signing.PredecessorResolver }

func (a predecessorResolverAdapter) Resolve(handle string) (crypto.Signer, error) {
	return a.r.ResolvePredecessor(handle)
}

// unboundResolver fails closed until the signer injects its custody via
// UsePredecessorResolver (INT-02).
type unboundResolver struct{}

func (unboundResolver) Resolve(string) (crypto.Signer, error) {
	return nil, errors.New("signerwiring: predecessor resolver not bound by the signer")
}

// interimFloorStore is an in-memory epoch floor used until INT-05 provides a
// durable, restart-surviving floor within the signer custody boundary. It is NOT
// durable: a signer restart resets it, so INT-05 is a hard prerequisite for the
// DELIVERED status of INT-02/INT-03.
type interimFloorStore struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newInterimFloorStore() *interimFloorStore { return &interimFloorStore{m: map[string]uint64{}} }

func (f *interimFloorStore) Load() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]uint64, len(f.m))
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}

func (f *interimFloorStore) Advance(id string, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = epoch
	return nil
}
