// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	keyRecordVersion = 2
	maxKeyProbeBytes = 4 << 10
	keyProbeValue    = "trstctl:independent-event-key-probe:v1"
	keyProbeDomain   = "trstctl.independent-event-key-probe.v1"
)

// KeyCreationEvidence contains only public identity and ciphertext of a fixed
// public value. It contains neither the tenant key nor a wrapped copy of it.
// Activation must retain this evidence in the immutable source before writes
// begin, so an accidental replacement directory cannot redefine the same key.
type KeyCreationEvidence struct {
	Version   int       `json:"version"`
	Ref       KeyRef    `json:"ref"`
	CreatedAt time.Time `json:"created_at"`
	Probe     []byte    `json:"probe"`
}

func (e KeyCreationEvidence) Digest() string {
	if validateCreationEvidence(e) != nil {
		return ""
	}
	wire, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return crypto.SHA256Hex(append([]byte("trstctl.event-key-creation.v1\x00"), wire...))
}

func validateCreationEvidence(e KeyCreationEvidence) error {
	ref, err := normalizedKeyRef(e.Ref)
	if err != nil || ref != e.Ref || e.Version != keyRecordVersion || e.CreatedAt.IsZero() || len(e.Probe) == 0 || len(e.Probe) > maxKeyProbeBytes {
		return ErrKey
	}
	return nil
}

func creationEvidenceFor(record fileKeyRecord) KeyCreationEvidence {
	return KeyCreationEvidence{Version: record.Version, Ref: record.Ref, CreatedAt: record.CreatedAt, Probe: bytes.Clone(record.Probe)}
}

func keyProbeBindings(record fileKeyRecord) ([]byte, error) {
	return json.Marshal(struct {
		Format    string    `json:"format"`
		Version   int       `json:"version"`
		Ref       KeyRef    `json:"ref"`
		CreatedAt time.Time `json:"created_at"`
	}{keyProbeDomain, record.Version, record.Ref, record.CreatedAt.UTC()})
}

func makeKeyProbe(key seal.KeyWrapper, record fileKeyRecord) ([]byte, error) {
	aad, err := keyProbeBindings(record)
	if err != nil {
		return nil, ErrKey
	}
	probe, err := seal.SealDomain(key, []byte(keyProbeValue), aad, []byte(keyProbeDomain))
	if err != nil || len(probe) == 0 || len(probe) > maxKeyProbeBytes {
		return nil, ErrKey
	}
	return probe, nil
}

func verifyKeyProbe(key seal.KeyWrapper, record fileKeyRecord) error {
	if validateCreationEvidence(creationEvidenceFor(record)) != nil {
		return ErrKey
	}
	aad, err := keyProbeBindings(record)
	if err != nil {
		return ErrKey
	}
	opened, err := seal.OpenDomain(key, record.Probe, aad, []byte(keyProbeDomain))
	defer secret.Wipe(opened)
	if err != nil || !bytes.Equal(opened, []byte(keyProbeValue)) {
		return ErrKey
	}
	return nil
}

// CreationEvidence independently checks the active material before returning
// the public receipt which an activation event must retain. A destroyed key may
// return its original public evidence only after its destruction is verified.
func (a *FileAuthority) CreationEvidence(ctx context.Context, ref KeyRef) (KeyCreationEvidence, error) {
	var evidence KeyCreationEvidence
	err := a.withLock(ctx, ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		if err != nil || !found {
			return ErrKey
		}
		if record.Phase == "destroyed" {
			if !errors.Is(a.destroyedState(record), ErrDestroyed) {
				return ErrKey
			}
		} else {
			if record.Phase != "active" {
				return ErrKey
			}
			key, err := a.loadKey(ref, record)
			if err != nil {
				return err
			}
			key.Destroy()
		}
		evidence = creationEvidenceFor(record)
		return nil
	})
	return evidence, err
}

// WithVerifiedKey checks the exact public creation evidence retained by the
// activation source under the same lock as key use. Comparing only the local
// record would not detect replacement of both its probe and key material.
func (a *FileAuthority) WithVerifiedKey(ctx context.Context, expected KeyCreationEvidence, fn func(seal.KeyWrapper) error) error {
	if fn == nil || validateCreationEvidence(expected) != nil {
		return ErrContext
	}
	return a.withLock(ctx, expected.Ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		if err != nil || !found || creationEvidenceFor(record).Digest() != expected.Digest() {
			return ErrKey
		}
		if record.Phase == "destroyed" {
			return a.destroyedState(record)
		}
		if record.Phase != "active" {
			return ErrKey
		}
		key, err := a.loadKey(ref, record)
		if err != nil {
			return err
		}
		defer key.Destroy()
		return fn(key)
	})
}
