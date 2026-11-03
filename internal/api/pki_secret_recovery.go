// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// MaxPKISecretLeafPEMBytes bounds the public certificate a recovery reads.
const MaxPKISecretLeafPEMBytes = 64 << 10

var (
	// ErrPKISecretLeafNotRecoverable: the certificate is not a historical
	// PKI-secret leaf this control plane minted.
	ErrPKISecretLeafNotRecoverable = errors.New("api: not a recoverable PKI secret leaf")
	// ErrManagedCALeafNotRecoverable: the certificate is not a leaf one of the
	// tenant's managed CAs minted and recorded by serial only.
	ErrManagedCALeafNotRecoverable = errors.New("api: not a recoverable managed CA leaf")
	// ErrPKISecretLeafInInventory: the leaf already has an inventory row.
	ErrPKISecretLeafInInventory = errors.New("api: the leaf is already in inventory")
)

// PKISecretLeafRecoveryService gives a historical PKI-secret leaf, minted by
// a v1 event that kept only its serial, the inventory row a v3 mint would
// have had, from the public certificate an operator supplies (A111). It also
// gives an inventory row that holds no certificate bytes the bytes of its
// certificate, from the tenant's CA mint or the endpoint it records (A215).
type PKISecretLeafRecoveryService interface {
	RecoverPKISecretLeaf(ctx context.Context, tenantID string, certificatePEM []byte) (PKISecretLeafRecovery, error)
	RecoverCertificateDER(ctx context.Context, tenantID, certificateID string, req CertificateDERRecoveryRequest) (CertificateDERRecovery, error)
}

// WithPKISecretLeafRecovery wires historical PKI-secret leaf recovery.
func WithPKISecretLeafRecovery(svc PKISecretLeafRecoveryService) Option {
	return func(c *config) { c.pkiSecretLeafRecovery = svc }
}

// ManagedCALeafRecoveryService gives a managed CA leaf that a v1
// ca.endentity.issued mint recorded by serial only its inventory row, from the
// public certificate an operator supplies (A209).
type ManagedCALeafRecoveryService interface {
	RecoverManagedCALeaf(ctx context.Context, tenantID string, certificatePEM []byte) (PKISecretLeafRecovery, error)
}

// WithManagedCALeafRecovery wires managed CA leaf recovery (A209).
func WithManagedCALeafRecovery(svc ManagedCALeafRecoveryService) Option {
	return func(c *config) { c.managedCALeafRecovery = svc }
}

// PKISecretLeafRecovery reports the inventory row a historical leaf now has.
type PKISecretLeafRecovery struct {
	CertificateID    string `json:"certificate_id"`
	Serial           string `json:"serial"`
	Fingerprint      string `json:"fingerprint"`
	OriginalEventID  string `json:"original_event_id"`
	Evidence         string `json:"evidence"`
	AlreadyRecovered bool   `json:"already_recovered"`
}

// recoverPKISecretLeaf reads one PEM certificate as the request body.
//
//trstctl:mutation
func (a *API) recoverPKISecretLeaf(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pkiSecretLeafRecovery == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PKI secret leaf recovery is not available on this control plane")
		}
		pemBytes, err := readLeafPEM(r)
		if err != nil {
			return 0, nil, err
		}
		out, err := a.pkiSecretLeafRecovery.RecoverPKISecretLeaf(ctx, tenantID, pemBytes)
		switch {
		case errors.Is(err, ErrPKISecretLeafNotRecoverable):
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
		case errors.Is(err, ErrPKISecretLeafInInventory):
			return 0, nil, errWithStatus(http.StatusConflict, err)
		case err != nil:
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

// recoverManagedCALeaf reads one PEM certificate as the request body (A209).
//
//trstctl:mutation
func (a *API) recoverManagedCALeaf(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.managedCALeafRecovery == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "managed CA leaf recovery is not available on this control plane")
		}
		pemBytes, err := readLeafPEM(r)
		if err != nil {
			return 0, nil, err
		}
		out, err := a.managedCALeafRecovery.RecoverManagedCALeaf(ctx, tenantID, pemBytes)
		switch {
		case errors.Is(err, ErrManagedCALeafNotRecoverable):
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
		case errors.Is(err, ErrPKISecretLeafInInventory):
			return 0, nil, errWithStatus(http.StatusConflict, err)
		case err != nil:
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	})
}

// readLeafPEM reads the one PEM certificate both recoveries take as the body.
func readLeafPEM(r *http.Request) ([]byte, error) {
	pemBytes, err := io.ReadAll(io.LimitReader(r.Body, MaxPKISecretLeafPEMBytes+1))
	if err != nil {
		return nil, errStatus(http.StatusBadRequest, "cannot read the certificate")
	}
	if len(pemBytes) == 0 {
		return nil, errStatus(http.StatusBadRequest, "send the leaf's PEM certificate as the request body")
	}
	if len(pemBytes) > MaxPKISecretLeafPEMBytes {
		return nil, errStatus(http.StatusRequestEntityTooLarge, "the certificate is larger than 64 KiB")
	}
	return pemBytes, nil
}
