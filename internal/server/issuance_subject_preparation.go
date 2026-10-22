// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type preparedLeafSubject struct {
	CSRDER []byte `json:"csr_der"`
	KeyPEM []byte `json:"key_pem"`
}

// generateLeafSubjectFromTemplate generates the subject key and request for a
// control-plane issued leaf, with every identifier kind the template carries
// (A33 appliance successors add IP addresses, rfc822Names and URIs).
func generateLeafSubjectFromTemplate(tmpl crypto.CertificateRequestTemplate) (preparedLeafSubject, error) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return preparedLeafSubject{}, err
	}
	defer key.Destroy()
	csr, err := crypto.CreateCertificateRequest(tmpl, key)
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
// prepareLeafSubjectFromTemplate opens or creates the retained subject key
// for a control-plane mint. The retained binding adds the extra identifier
// kinds only when present, so a DNS-only preparation keeps its exact retained
// key across the A33 change.
func (d *issuanceDispatcher) prepareLeafSubjectFromTemplate(ctx context.Context, tenantID, ownerID string, tmpl crypto.CertificateRequestTemplate, selection endpointAuthoritySelection) (preparedLeafSubject, bool, error) {
	return d.leafSubjectPreparationFromTemplate(ctx, tenantID, ownerID, tmpl, selection, true)
}

// Recovery may open an existing preparation, but must never create a replacement
// key for an already recorded certificate. A missing or changed binding requires
// reconciliation, not a new signing attempt.
func (d *issuanceDispatcher) leafSubjectPreparation(ctx context.Context, tenantID, ownerID, commonName string, dnsNames []string, selection endpointAuthoritySelection, create bool) (preparedLeafSubject, bool, error) {
	return d.leafSubjectPreparationFromTemplate(ctx, tenantID, ownerID,
		crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, selection, create)
}

func (d *issuanceDispatcher) leafSubjectPreparationFromTemplate(ctx context.Context, tenantID, ownerID string, tmpl crypto.CertificateRequestTemplate, selection endpointAuthoritySelection, create bool) (preparedLeafSubject, bool, error) {
	command, durable := ctx.Value(leafCommandContextKey{}).(leafCommand)
	if !durable {
		if !create {
			return preparedLeafSubject{}, false, errors.New("server: certificate deployment recovery requires its original issuance command")
		}
		subject, err := generateLeafSubjectFromTemplate(tmpl)
		return subject, false, err
	}
	if command.idem == nil || command.tenantID != tenantID || command.key == "" || d.connectorPayloadKey == nil {
		return preparedLeafSubject{}, false, errors.New("server: durable subject preparation requires tenant-bound credential sealing")
	}
	// The extra identifier kinds are omitted when empty, so a DNS-only
	// preparation keeps the exact binding digest it had before A33.
	binding, err := json.Marshal(struct {
		Tenant, Owner, CommonName string
		DNSNames                  []string
		IPAddresses               []net.IP `json:",omitempty"`
		EmailAddresses            []string `json:",omitempty"`
		URIs                      []string `json:",omitempty"`
		Authority                 endpointAuthoritySelection
	}{tenantID, ownerID, tmpl.CommonName, tmpl.DNSNames, tmpl.IPAddresses, tmpl.EmailAddresses, tmpl.URIs, selection})
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
			generated, err := generateLeafSubjectFromTemplate(tmpl)
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
