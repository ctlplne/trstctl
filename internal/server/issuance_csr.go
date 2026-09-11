// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// CSR-first issuance (epic B1).
//
// The direct identity API had no CSR input at all: transitioning an identity to
// issued made the control plane generate the subject key, sign for it, and hand
// the key onward. That is a custody claim nobody wants to defend — "your private
// key was created in our process" — and it is the reason the served surface could
// not say private keys never reach the control plane.
//
// A caller who supplies their own PKCS#10 request gets the other shape: we sign
// what they made and never see a key. Both paths still enforce the same profile
// gate before signing, because whose key it is does not change what the
// certificate is allowed to say.

// mintServedLeafForTrigger signs the caller's CSR when the transition carries
// one, and otherwise falls back to generating the subject key. The fallback
// records a deprecation event each time it is used, so an operator can see which
// of their flows still hand key generation to the control plane before the path
// is removed.
func (d *issuanceDispatcher) mintServedLeafForTrigger(ctx context.Context, tenantID string, ident store.Identity, p transitionTrigger, issueKey string) (issuedLeafMaterial, error) {
	binding, err := issuanceBindingForTrigger(p)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	selection, err := endpointIssuingAuthority(ident.Attributes)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	// A CSR on the transition wins: it is the most specific statement of intent
	// for this particular issuance.
	if csr := strings.TrimSpace(p.SubjectCSRPEM); csr != "" {
		return d.mintServedLeafFromCSRForSelection(ctx, tenantID, ident, selection, issueKey, []byte(csr), binding)
	}
	// Otherwise the request's own CSR, recorded when the identity was created.
	// The CSR belongs to the requester, not to whoever approves them: an approver
	// pressing "approve" should not have to re-supply key material they never had.
	if csr := subjectCSRFromIdentity(ident); csr != "" {
		return d.mintServedLeafFromCSRForSelection(ctx, tenantID, ident, selection, issueKey, []byte(csr), binding)
	}
	d.recordServerSideKeygenDeprecation(ctx, tenantID, ident)
	return d.mintServedLeafMaterialForSelection(ctx, tenantID, ident.OwnerID, ident.Name, []string{ident.Name}, selection, issueKey, binding)
}

// mintServedLeafForRenewal preserves the predecessor's proven key custody.
// Requester renewal requires the exact retained lifecycle CSR and a matching
// predecessor public key and identifiers; mutable identity attributes never
// authorize a new key. Unknown/external custody must renew through its own
// protocol/agent flow. Only an explicitly recorded legacy control-plane key
// can use the existing announced control-plane generation path.
func (d *issuanceDispatcher) mintServedLeafForRenewal(
	ctx context.Context, tenantID string, ident store.Identity, predecessor store.Certificate, commonName string, dnsNames []string, issueKey string,
) (issuedLeafMaterial, error) {
	selection, err := endpointIssuingAuthority(ident.Attributes)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	if predecessor.KeyOrigin == string(custody.OriginRequester) {
		csr, err := d.store.IdentityRenewalCSR(ctx, tenantID, ident.ID, predecessor.ID)
		if err != nil {
			return issuedLeafMaterial{}, fmt.Errorf("server: requester renewal requires retained authorized CSR: %w", err)
		}
		if err := validateRequesterRenewalCSR([]byte(csr), predecessor); err != nil {
			return issuedLeafMaterial{}, err
		}
		// The current renewal admission/profile/authority checks still apply.
		// Retaining public CSR custody does not reuse an old approval vote.
		return d.mintServedLeafFromCSRForSelection(ctx, tenantID, ident, selection, issueKey, []byte(csr))
	}
	if predecessor.KeyOrigin != string(custody.OriginControlPlane) || subjectCSRFromIdentity(ident) != "" {
		return issuedLeafMaterial{}, errors.New("server: renewal key custody is unknown or requires its original requester/agent protocol")
	}
	d.recordServerSideKeygenDeprecation(ctx, tenantID, ident)
	return d.mintServedLeafMaterialForSelection(ctx, tenantID, ident.OwnerID, commonName, dnsNames, selection, issueKey)
}

// Existing crypto-boundary parsers supply both verified request attributes and
// SPKI bytes. The opaque parser is used only for public-key extraction AFTER
// InspectCSR checks proof of possession; it is never signature authorization.
func validateRequesterRenewalCSR(publicCSR []byte, predecessor store.Certificate) error {
	der, info, err := crypto.ParsePublicCSRPEM(publicCSR)
	if err != nil {
		return err
	}
	parsed, err := crypto.InspectOpaqueCSR(der)
	if err != nil {
		return err
	}
	old, err := certinfo.Inspect(predecessor.CertificateDER)
	if err != nil {
		return err
	}
	if old.SHA256Fingerprint != predecessor.Fingerprint || crypto.SHA256Hex(parsed.RawSubjectPublicKeyInfo) != old.SPKISHA256 {
		return errors.New("server: authorized renewal CSR public key differs from predecessor")
	}
	if info.CommonName != old.CommonName || !sameRenewalIdentifiers(info.DNSNames, old.DNSNames) || !sameRenewalIdentifiers(info.IPAddresses, old.IPAddresses) ||
		!sameRenewalIdentifiers(info.EmailAddresses, old.EmailAddresses) || !sameRenewalIdentifiers(info.URIs, old.URIs) {
		return errors.New("server: authorized renewal CSR identifiers differ from predecessor")
	}
	return nil
}
func sameRenewalIdentifiers(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := map[string]int{}
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		if counts[value] == 0 {
			return false
		}
		counts[value]--
	}
	return true
}

// subjectCSRFromIdentity reads the CSR a requester attached when they created the
// request. Attributes are free-form, so read defensively: a malformed attribute
// block means no CSR, not a failed issuance.
func subjectCSRFromIdentity(ident store.Identity) string {
	if len(ident.Attributes) == 0 {
		return ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(ident.Attributes, &attrs); err != nil {
		return ""
	}
	csr, _ := attrs["subject_csr_pem"].(string)
	return strings.TrimSpace(csr)
}

// mintServedLeafFromCSRForSelection signs a caller-supplied request with the
// identity's exact authority selection. It returns no KeyPEM,
// because there is no key here to return — which is the point. The connector
// deploy path degrades to certificate-only for this identity, since the material
// it would need is on the caller's side; host-executed renewal (epic B2) is what
// closes that loop properly.
func (d *issuanceDispatcher) mintServedLeafFromCSRForSelection(
	ctx context.Context,
	tenantID string,
	ident store.Identity,
	selection endpointAuthoritySelection,
	issueKey string,
	csrPEM []byte,
	issuance ...*store.OperationApprovalIssuanceBinding,
) (issuedLeafMaterial, error) {
	csrDER, dnsNames, err := decodeSubjectCSR(csrPEM)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	if len(dnsNames) == 0 {
		dnsNames = []string{ident.Name}
	}
	// Same profile gate as the server-keygen path: the origin of the key does not
	// change what the certificate may assert, and skipping it here would make
	// "bring your own CSR" a way around policy.
	ttl, binding, err := approvedIssuanceTTL(issuance)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafProfile, err := d.enforceProfile(ctx, tenantID, csrDER, dnsNames, ttl, binding)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafPEM, chainPEM, caID, source, anchor, err := d.issueEndpointCSR(ctx, tenantID, selection, issueKey, csrDER, dnsNames, ttl, leafProfile)
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
	if ownerID := strings.TrimSpace(ident.OwnerID); ownerID != "" {
		owner := ownerID
		ownerPtr = &owner
	}
	nb, na := info.NotBefore, info.NotAfter
	return issuedLeafMaterial{
		Certificate: store.Certificate{
			CAID: caID, OwnerID: ownerPtr, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
			ValidityAnchor: anchor,
			Source:         source, CertificateDER: append([]byte(nil), blk.Bytes...),
			// B5: the requester generated this key and the control plane never
			// held it. That is a fact about THIS certificate, recorded from what
			// the code did rather than from what the documentation says the
			// system does — which is the difference an auditor is asking about.
			KeyOrigin: string(custody.OriginRequester),
		},
		CertPEM:  append([]byte(nil), leafPEM...),
		ChainPEM: append([]byte(nil), chainPEM...),
		// The material field is left zero on purpose: the subject key was never
		// here, so there is nothing to return, wipe, or leak.
	}, nil
}

// recordServerSideKeygenDeprecation appends an audit event naming the identity
// that used the legacy path. It is deliberately best-effort: failing to record
// the deprecation must not fail the issuance an operator is relying on today.
func (d *issuanceDispatcher) recordServerSideKeygenDeprecation(ctx context.Context, tenantID string, ident store.Identity) {
	if d.log == nil {
		return
	}
	body, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		Name       string `json:"name"`
		Detail     string `json:"detail"`
		Successor  string `json:"successor"`
	}{
		IdentityID: ident.ID, Name: ident.Name,
		Detail:    "the control plane generated this identity's subject key because the issuance carried no CSR; this path is deprecated",
		Successor: "supply subject_csr_pem on the transition to issued so the key is generated where it will be used",
	})
	if err != nil {
		return
	}
	_, _ = d.log.Append(ctx, events.Event{Type: "issuance.server_side_keygen", TenantID: tenantID, Data: body})
}

// decodeSubjectCSR turns a caller-supplied PKCS#10 request into DER plus the
// names it asks for, verifying the request's self-signature through the crypto
// boundary (AN-3) before anything downstream trusts it.
//
// Rejecting here rather than at the signer is deliberate: a malformed or
// unsigned CSR is a caller mistake, and it should come back as one instead of
// surfacing as an opaque signing failure later in the outbox.
func decodeSubjectCSR(csrPEM []byte) (der []byte, dnsNames []string, err error) {
	der, info, err := crypto.ParsePublicCSRPEM(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("server: subject CSR is not one valid, self-signed PKCS#10 request: %w", err)
	}
	names := append([]string(nil), info.DNSNames...)
	if len(names) == 0 && strings.TrimSpace(info.CommonName) != "" {
		names = []string{info.CommonName}
	}
	return der, names, nil
}
