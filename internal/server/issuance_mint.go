// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/store"
)

// The control-plane keygen mint, split from issuance.go to keep that served
// file within its size budget.

func (d *issuanceDispatcher) mintServedLeafMaterialForSelection(
	ctx context.Context,
	tenantID, ownerID, commonName string,
	dnsNames []string,
	selection endpointAuthoritySelection,
	issueKey string,
	issuance ...*store.OperationApprovalIssuanceBinding,
) (issuedLeafMaterial, error) {
	if len(dnsNames) == 0 {
		dnsNames = []string{commonName}
	}
	return d.mintServedLeafMaterialFromTemplate(ctx, tenantID, ownerID,
		crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, selection, issueKey, issuance...)
}

// mintServedLeafMaterialFromTemplate is the control-plane keygen mint for a
// subject with every identifier kind (A33): an appliance successor asserts the
// DNS names, IP addresses, rfc822Names and URIs its predecessor carried, and
// nothing else. The profile gate and the authority seam are the same ones the
// DNS-only path uses.
func (d *issuanceDispatcher) mintServedLeafMaterialFromTemplate(
	ctx context.Context,
	tenantID, ownerID string,
	tmpl crypto.CertificateRequestTemplate,
	selection endpointAuthoritySelection,
	issueKey string,
	issuance ...*store.OperationApprovalIssuanceBinding,
) (issuedLeafMaterial, error) {
	commonName, dnsNames := tmpl.CommonName, tmpl.DNSNames
	if len(dnsNames) == 0 {
		dnsNames = []string{commonName}
	}
	subject, retained, err := d.prepareLeafSubjectFromTemplate(ctx, tenantID, ownerID, tmpl, selection)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	keyBuffer, err := secret.NewFrom(subject.KeyPEM)
	secret.Wipe(subject.KeyPEM)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	keyPEM, csrDER := keyBuffer.Bytes(), subject.CSRDER
	keepKeyPEM := false
	defer func() {
		if !keepKeyPEM {
			keyBuffer.Destroy()
		}
	}()
	// Enforce the certificate-profile model on the served mint (PKIGOV-002):
	// when a default profile is configured and resolves for the tenant, validate
	// this request against it BEFORE signing and emit the allow/deny decision as
	// an issuance.profile_evaluated event. A violation rejects (fail closed) so an
	// out-of-profile certificate is never minted on the served path.
	ttl, binding, err := approvedIssuanceTTL(issuance)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafProfile, err := d.enforceProfile(ctx, tenantID, csrDER, dnsNames, ttl, binding)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafPEM, chainPEM, caID, source, anchor, err := d.issueEndpointCSR(ctx, tenantID, selection, issueKey, csrDER, dnsNames, ttl, leafProfile, custody.OriginControlPlane)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	blk, _ := pem.Decode(leafPEM)
	if blk == nil {
		return issuedLeafMaterial{}, errors.New("server: issued certificate is not PEM")
	}
	info, err := certinfo.Inspect(blk.Bytes)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	var ownerPtr *string
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		owner := ownerID
		ownerPtr = &owner
	}
	nb, na := info.NotBefore, info.NotAfter
	storage := custody.StorageLockedMemory
	if retained {
		storage = custody.StorageSealedStore
	}
	keepKeyPEM = true
	return issuedLeafMaterial{
		Certificate: store.Certificate{
			CAID: caID, OwnerID: ownerPtr, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
			ValidityAnchor: anchor,
			Source:         source, CertificateDER: append([]byte(nil), blk.Bytes...),
			// B5: the deprecated path. The key was held in locked memory and
			// wiped, but it existed outside the requester, and a credential on
			// this path is one an operator should plan to replace. They cannot
			// plan for what is not written down, so it is written down here
			// rather than only in a deprecation event nobody queries.
			KeyOrigin:     string(custody.OriginControlPlane),
			KeyStorage:    string(storage),
			KeyExportable: string(custody.Exportable),
		},
		CertPEM:   append([]byte(nil), leafPEM...),
		ChainPEM:  append([]byte(nil), chainPEM...),
		KeyPEM:    keyPEM,
		keyBuffer: keyBuffer,
	}, nil
}
