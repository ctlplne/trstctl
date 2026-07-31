// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	resultCodecRawV0                = "raw-v0"
	resultCodecSealedRowV1          = "sealed-row-v1"
	resultCodecSealedDynamicLeaseV1 = "sealed-dynamic-lease-v1"
)

// ResultProtector adapts tenant cryptographic Access to the orchestrator's
// opaque idempotency-result seam. The row identity is authenticated as AAD, so
// moving a ciphertext across tenant, key, or request-binding columns fails.
//
// raw-v0 and sealed-dynamic-lease-v1 remain read-only rolling-upgrade codecs.
// They still pass through Access.WithTenant so a sealed or corrupt tenant never
// receives legacy plaintext merely because its row has not migrated yet.
type ResultProtector struct {
	access Access
}

// NewResultProtector returns a tenant-bound idempotency result protector.
func NewResultProtector(access Access) (*ResultProtector, error) {
	if access == nil {
		return nil, errors.New("tenantseal: result protector requires tenant access")
	}
	return &ResultProtector{access: access}, nil
}

// Protect always emits the one writable protected result codec.
func (p *ResultProtector) Protect(
	ctx context.Context,
	tenantID, key, binding string,
	plaintext []byte,
) (string, []byte, error) {
	aad, err := idempotencyResultAAD(tenantID, key, binding)
	if err != nil {
		return "", nil, err
	}
	var protected []byte
	err = p.access.WithTenant(ctx, tenantID, func(cipher Cipher) error {
		var err error
		protected, err = cipher.Seal(plaintext, aad)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return resultCodecSealedRowV1, protected, nil
}

// Open authenticates sealed-row-v1 and permits the two historical codecs only
// while the tenant's current access state allows cryptographic reads.
func (p *ResultProtector) Open(
	ctx context.Context,
	tenantID, key, binding, codec string,
	protected []byte,
) ([]byte, error) {
	aad, err := idempotencyResultAAD(tenantID, key, binding)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	err = p.access.WithTenant(ctx, tenantID, func(cipher Cipher) error {
		switch codec {
		case resultCodecSealedRowV1:
			var err error
			plaintext, err = cipher.Open(protected, aad)
			return err
		case resultCodecRawV0, resultCodecSealedDynamicLeaseV1:
			plaintext = append([]byte(nil), protected...)
			return nil
		default:
			return fmt.Errorf("tenantseal: unsupported idempotency result codec %q", codec)
		}
	})
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func idempotencyResultAAD(tenantID, key, binding string) ([]byte, error) {
	if tenantID == "" || key == "" {
		return nil, errors.New("tenantseal: idempotency result requires tenant and key")
	}
	fields := [...]string{tenantID, key, binding}
	total := len("trstctl.idempotency.result.v1")
	for _, field := range fields {
		total += 4 + len(field)
	}
	aad := make([]byte, 0, total)
	aad = append(aad, "trstctl.idempotency.result.v1"...)
	var length [4]byte
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return nil, errors.New("tenantseal: idempotency result identity is too large")
		}
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		aad = append(aad, length[:]...)
		aad = append(aad, field...)
	}
	return aad, nil
}
