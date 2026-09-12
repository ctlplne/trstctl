// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A durable lifecycle delivery owns one signing operation. Keep its original
// outbox key, including on redelivery; an attempt number is never an operation ID.
type leafCommand struct {
	tenantID string
	key      string
	idem     *orchestrator.Idempotency
	slot     string
}

type leafCommandContextKey struct{}

func withLeafCommand(ctx context.Context, idem *orchestrator.Idempotency, tenantID, key string) context.Context {
	return context.WithValue(ctx, leafCommandContextKey{}, leafCommand{tenantID: tenantID, key: key, idem: idem})
}

func withLeafSlot(ctx context.Context, slot string) context.Context {
	command, ok := ctx.Value(leafCommandContextKey{}).(leafCommand)
	if !ok {
		return ctx
	}
	command.slot = slot
	return context.WithValue(ctx, leafCommandContextKey{}, command)
}

// The fixed-width public slot digest separates each predecessor in a bulk
// renewal. The remaining suffix is the original outbox key for retention.
func (c leafCommand) preparationKey(prefix string) string {
	return prefix + crypto.SHA256Hex([]byte(c.slot)) + ":" + c.key
}

type journaledLeafSigner interface {
	crypto.DigestSigner
	SignDigestForOperation(string, []byte, crypto.SignOptions) ([]byte, error)
}

type leafOperationSigner struct {
	journaledLeafSigner
	operationID string
}

func (s leafOperationSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.SignDigestForOperation(s.operationID, digest, opts)
}

// Retain the public template before crossing the signer boundary. A lost reply
// or a failed certificate.recorded append then asks the persistent signer for
// precisely the same digest and receives precisely the same signature. These
// are receiver bookkeeping records, not a replacement for certificate events.
func signLifecycleLeaf(ctx context.Context, caDER []byte, signer crypto.DigestSigner, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
	command, durable := ctx.Value(leafCommandContextKey{}).(leafCommand)
	if !durable {
		return crypto.SignLeafFromCSRWithValidity(caDER, signer, csr, ttl, profile)
	}
	journal, ok := signer.(journaledLeafSigner)
	if !ok || command.idem == nil || command.tenantID == "" || command.key == "" {
		return crypto.IssuedLeaf{}, errors.New("server: lifecycle issuance requires a durable signing operation")
	}
	binding, err := json.Marshal(struct {
		Issuer  []byte
		CSR     []byte
		TTL     time.Duration
		Profile crypto.LeafProfile
	}{caDER, csr, ttl, profile})
	if err != nil {
		return crypto.IssuedLeaf{}, err
	}
	preparedJSON, err := command.idem.DoBound(ctx, command.tenantID, command.preparationKey("leaf-template:v1:"), crypto.SHA256Hex(binding), func(context.Context) ([]byte, error) {
		prepared, err := crypto.NewLeafPreparation()
		if err != nil {
			return nil, err
		}
		return json.Marshal(prepared)
	})
	defer secret.Wipe(preparedJSON)
	if err != nil {
		return crypto.IssuedLeaf{}, err
	}
	var prepared crypto.LeafPreparation
	if err := json.Unmarshal(preparedJSON, &prepared); err != nil {
		return crypto.IssuedLeaf{}, errors.New("server: retained leaf template is invalid")
	}
	operation, err := json.Marshal([]string{"lifecycle-leaf-v1", command.tenantID, command.key, command.slot})
	if err != nil {
		return crypto.IssuedLeaf{}, err
	}
	return crypto.SignLeafFromCSRWithPreparation(caDER, leafOperationSigner{journal, crypto.SHA256Hex(operation)}, csr, ttl, profile, prepared)
}
