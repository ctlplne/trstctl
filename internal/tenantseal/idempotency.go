// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

const resultCodecSealedRowV1 = "sealed-row-v1"

// ResultProtector adapts tenant cryptographic Access to the orchestrator's
// opaque idempotency-result seam. The row identity is authenticated as AAD, so
// moving a ciphertext across tenant, key, or request-binding columns fails.
//
// raw-v0 and sealed-dynamic-lease-v1 are handled only by the pre-readiness
// migrator. This runtime reader rejects them: after readiness there is no
// plaintext compatibility path to bypass a sealed or corrupt tenant.
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

// Open authenticates sealed-row-v1 and rejects every pre-readiness codec.
func (p *ResultProtector) Open(
	ctx context.Context,
	tenantID, key, binding, codec string,
	protected []byte,
) ([]byte, error) {
	if codec != resultCodecSealedRowV1 {
		return nil, fmt.Errorf("tenantseal: idempotency result codec %q is retired after readiness", codec)
	}
	aad, err := idempotencyResultAAD(tenantID, key, binding)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	err = p.access.WithTenant(ctx, tenantID, func(cipher Cipher) error {
		var err error
		plaintext, err = cipher.Open(protected, aad)
		return err
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
		binary.BigEndian.PutUint32(length[:], uint32(len(field))) // #nosec G115 -- length framing of short bounded fields (CWE-190)
		aad = append(aad, length[:]...)
		aad = append(aad, field...)
	}
	return aad, nil
}
