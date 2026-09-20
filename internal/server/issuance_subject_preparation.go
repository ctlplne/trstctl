// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type preparedLeafSubject struct {
	CSRDER []byte `json:"csr_der"`
	KeyPEM []byte `json:"key_pem"`
}

func generateLeafSubject(commonName string, dnsNames []string) (preparedLeafSubject, error) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return preparedLeafSubject{}, err
	}
	defer key.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, key)
	if err != nil {
		return preparedLeafSubject{}, err
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		return preparedLeafSubject{}, err
	}
	return preparedLeafSubject{CSRDER: csr, KeyPEM: keyPEM}, nil
}

// Legacy connector delivery needs the same subject key after a crash. Retain
// only a tenant-bound sealed envelope, before any CA call. Even a test recorder
// without an outer result protector must never write plaintext key bytes.
func (d *issuanceDispatcher) prepareLeafSubject(ctx context.Context, tenantID, ownerID, commonName string, dnsNames []string, selection endpointAuthoritySelection) (preparedLeafSubject, bool, error) {
	return d.leafSubjectPreparation(ctx, tenantID, ownerID, commonName, dnsNames, selection, true)
}

// Recovery may open an existing preparation, but must never create a replacement
// key for an already recorded certificate. A missing or changed binding requires
// reconciliation, not a new signing attempt.
func (d *issuanceDispatcher) leafSubjectPreparation(ctx context.Context, tenantID, ownerID, commonName string, dnsNames []string, selection endpointAuthoritySelection, create bool) (preparedLeafSubject, bool, error) {
	command, durable := ctx.Value(leafCommandContextKey{}).(leafCommand)
	if !durable {
		if !create {
			return preparedLeafSubject{}, false, errors.New("server: certificate deployment recovery requires its original issuance command")
		}
		subject, err := generateLeafSubject(commonName, dnsNames)
		return subject, false, err
	}
	if command.idem == nil || command.tenantID != tenantID || command.key == "" || d.connectorPayloadKey == nil {
		return preparedLeafSubject{}, false, errors.New("server: durable subject preparation requires tenant-bound credential sealing")
	}
	binding, err := json.Marshal(struct {
		Tenant, Owner, CommonName string
		DNSNames                  []string
		Authority                 endpointAuthoritySelection
	}{tenantID, ownerID, commonName, dnsNames, selection})
	if err != nil {
		return preparedLeafSubject{}, false, err
	}
	key := command.preparationKey("leaf-subject:v1:")
	aad, err := json.Marshal([]string{"lifecycle-leaf-subject-v1", tenantID, key, crypto.SHA256Hex(binding)})
	if err != nil {
		return preparedLeafSubject{}, false, err
	}
	var sealed []byte
	if !create {
		var found bool
		sealed, found, err = command.idem.LookupBound(ctx, tenantID, key, crypto.SHA256Hex(binding))
		if err == nil && !found {
			err = errors.New("server: original subject preparation is missing or its issuance binding changed; reconcile the recorded certificate before deployment")
		}
	} else {
		sealed, err = command.idem.DoBound(ctx, tenantID, key, crypto.SHA256Hex(binding), func(ctx context.Context) ([]byte, error) {
			generated, err := generateLeafSubject(commonName, dnsNames)
			if err != nil {
				return nil, err
			}
			defer secret.Wipe(generated.KeyPEM)
			plain, err := json.Marshal(generated)
			defer secret.Wipe(plain)
			if err != nil {
				return nil, err
			}
			return sealTenantValue(ctx, d.tenantCrypto, d.connectorPayloadKey, tenantID, plain, aad)
		})
	}
	defer secret.Wipe(sealed)
	if err != nil {
		return preparedLeafSubject{}, false, err
	}
	plain, err := openTenantValue(ctx, d.tenantCrypto, d.connectorPayloadKey, tenantID, sealed, aad)
	defer secret.Wipe(plain)
	if err != nil {
		return preparedLeafSubject{}, false, err
	}
	var subject preparedLeafSubject
	if err := json.Unmarshal(plain, &subject); err != nil || len(subject.CSRDER) == 0 || len(subject.KeyPEM) == 0 {
		secret.Wipe(subject.KeyPEM)
		return preparedLeafSubject{}, false, errors.New("server: retained subject preparation is invalid")
	}
	return subject, true, nil
}
