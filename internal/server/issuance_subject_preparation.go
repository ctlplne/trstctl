// SPDX-License-Identifier: MPL-2.0

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
	command, durable := ctx.Value(leafCommandContextKey{}).(leafCommand)
	if !durable {
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
	sealed, err := command.idem.DoBound(ctx, tenantID, key, crypto.SHA256Hex(binding), func(ctx context.Context) ([]byte, error) {
		subject, err := generateLeafSubject(commonName, dnsNames)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(subject.KeyPEM)
		plain, err := json.Marshal(subject)
		defer secret.Wipe(plain)
		if err != nil {
			return nil, err
		}
		return sealTenantValue(ctx, d.tenantCrypto, d.connectorPayloadKey, tenantID, plain, aad)
	})
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
