// SPDX-License-Identifier: BUSL-1.1

package paloalto

import (
	"context"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// PEM types an export of a certificate object carries: the pending request
// until a certificate is imported for it, then the certificate.
const (
	pemCertificate        = "CERTIFICATE"
	pemCertificateRequest = "CERTIFICATE REQUEST"
)

var _ connector.ApplianceKeyGenerator = (*Connector)(nil)

// GenerateApplianceKey asks the firewall to generate an ECDSA P-256 key and a
// CSR, signed by an external authority, into a certificate object named for
// the job, and returns the CSR (A122). A pending CSR the firewall already holds
// under that name is returned as it is, so a reclaimed job continues with the
// key its earlier attempt made. PAN-OS replaces the pending CSR with the
// certificate imported for it, so an object that already holds a certificate
// was installed by an earlier attempt and has no CSR left to sign; the request
// stops with ErrApplianceKeyAlreadyInstalled rather than generating a second
// key. The key is never exported.
func (c *Connector) GenerateApplianceKey(ctx context.Context, sb connector.Sandbox, req connector.ApplianceKeyRequest) (connector.ApplianceKey, error) {
	if err := c.applianceKeyConfigured(); err != nil {
		return connector.ApplianceKey{}, err
	}
	object := strings.TrimSpace(req.ObjectName)
	if !connector.IsApplianceKeyObjectName(object) {
		return connector.ApplianceKey{}, errors.New("paloalto: an appliance key needs the object name assigned to its job")
	}
	commonName := applianceCommonName(req)
	if commonName == "" {
		return connector.ApplianceKey{}, errors.New("paloalto: an appliance key request names nothing to certify")
	}
	present, err := c.certificateEntryExists(ctx, sb, object)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("paloalto: look up certificate object %q: %w", object, err)
	}
	if !present {
		q := url.Values{}
		q.Set("type", "op")
		q.Set("cmd", generateCommand(object, commonName, req))
		body, err := c.api(ctx, sb, q)
		if err != nil {
			return connector.ApplianceKey{}, fmt.Errorf("paloalto: generate key and CSR %q: %w", object, err)
		}
		secret.Wipe(body)
	}
	exported, blockType, err := c.exportPublic(ctx, sb, object)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("paloalto: export the CSR of %q: %w", object, err)
	}
	switch blockType {
	case pemCertificateRequest:
		return connector.ApplianceKey{ObjectName: object, CSRPEM: exported}, nil
	case pemCertificate:
		return connector.ApplianceKey{}, fmt.Errorf("paloalto: certificate object %q: %w", object, connector.ErrApplianceKeyAlreadyInstalled)
	}
	return connector.ApplianceKey{}, fmt.Errorf("paloalto: the firewall exported no CSR for %q", object)
}

// InstallWithApplianceKey imports the signed certificate into the job-named
// object, where the firewall pairs it with the key it generated, then points
// the SSL/TLS service profile at that object and commits. No key is imported.
// The object keeps its job name: PAN-OS holds a certificate and its key in one
// object, so a rollback binds a predecessor's object back as it is, and a
// readback fingerprints the bound certificate instead of reading the name.
func (c *Connector) InstallWithApplianceKey(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, key connector.ApplianceKey) error {
	if err := c.applianceKeyConfigured(); err != nil {
		return err
	}
	object := strings.TrimSpace(key.ObjectName)
	if !connector.IsApplianceKeyObjectName(object) {
		return errors.New("paloalto: an appliance-key install needs the key's object name")
	}
	if len(dep.KeyPEM) != 0 {
		return errors.New("paloalto: an appliance-key install must not carry a private key")
	}
	if len(dep.CertPEM) == 0 {
		return errors.New("paloalto: an appliance-key install needs a certificate")
	}
	if err := c.importPart(ctx, sb, categoryCertificate, object, dep.CertPEM); err != nil {
		return fmt.Errorf("paloalto: import certificate into %q: %w", object, err)
	}
	if err := c.bindAndCommit(ctx, sb, object); err != nil {
		return fmt.Errorf("paloalto: bind SSL/TLS service profile %q to %q: %w", c.sslTLSProfile, object, err)
	}
	return nil
}

// rollbackToApplianceKey binds the SSL/TLS service profile back to the
// job-named object the predecessor's key was generated into, which holds the
// predecessor certificate beside that key, and commits (A122). The object must
// still exist and hold that certificate; the key is not exported.
func (c *Connector) rollbackToApplianceKey(ctx context.Context, sb connector.Sandbox, object, fingerprint string) error {
	if !connector.IsApplianceKeyObjectName(object) {
		return fmt.Errorf("paloalto: %q is not the name of an object a job's key was generated into", object)
	}
	present, err := c.certificateEntryExists(ctx, sb, object)
	if err != nil {
		return fmt.Errorf("paloalto: predecessor appliance key %q: %w", object, err)
	}
	if !present {
		return fmt.Errorf("paloalto: predecessor appliance key %q: %w", object, connector.ErrNoPredecessorInstalled)
	}
	certPEM, blockType, err := c.exportPublic(ctx, sb, object)
	if err != nil {
		return fmt.Errorf("paloalto: predecessor appliance key %q: %w", object, err)
	}
	if blockType != pemCertificate || !sameFingerprint(connector.CertificateFingerprint(certPEM), fingerprint) {
		return fmt.Errorf("paloalto: predecessor appliance key %q does not hold the predecessor certificate: %w",
			object, connector.ErrNoPredecessorInstalled)
	}
	if err := c.bindAndCommit(ctx, sb, object); err != nil {
		return fmt.Errorf("paloalto: re-bind SSL/TLS service profile %q to predecessor %q: %w", c.sslTLSProfile, object, err)
	}
	return nil
}

// applianceKeyConfigured refuses a key generated on the firewall for a target
// without an SSL/TLS service profile: the job-named object is installed by
// binding the profile to it, and the in-place import has nothing to bind.
func (c *Connector) applianceKeyConfigured() error {
	if c.sslTLSProfile == "" {
		return errors.New("paloalto: a key generated on the firewall needs ssl_tls_profile, the SSL/TLS service profile its certificate object is bound to")
	}
	return c.bindingConfigured()
}

// exportPublic exports a certificate object's public half as PEM, the pending
// CSR or the certificate imported for it, and names its PEM type. The private
// key is never requested, and anything else the export carries is refused.
func (c *Connector) exportPublic(ctx context.Context, sb connector.Sandbox, name string) ([]byte, string, error) {
	q := url.Values{}
	q.Set("type", "export")
	q.Set("category", categoryCertificate)
	q.Set("certificate-name", name)
	q.Set("format", "pem")
	q.Set("include-key", "no")
	body, err := c.api(ctx, sb, q)
	if err != nil {
		return nil, "", err
	}
	defer secret.Wipe(body)
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, "", errors.New("the export carried no PEM")
	}
	switch block.Type {
	case pemCertificate, pemCertificateRequest:
		return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), block.Type, nil
	}
	secret.Wipe(block.Bytes)
	return nil, "", errors.New("the export carried neither a certificate nor a certificate request")
}

// generateCommand is the op command that has the firewall generate an ECDSA
// P-256 key and a CSR for an external authority under the object name. Names
// come from the identity rather than this connector, so they are XML-escaped.
func generateCommand(object, commonName string, req connector.ApplianceKeyRequest) string {
	var b strings.Builder
	b.WriteString("<request><certificate><generate>")
	writeXMLElement(&b, "certificate-name", object)
	writeXMLElement(&b, "name", commonName)
	b.WriteString("<algorithm><ECDSA><ecdsa-nbits>256</ecdsa-nbits></ECDSA></algorithm>")
	writeXMLElement(&b, "digest", "sha256")
	writeXMLElement(&b, "signed-by", "external")
	writeXMLMembers(&b, "hostname", req.DNSNames)
	writeXMLMembers(&b, "ip", req.IPAddresses)
	b.WriteString("</generate></certificate></request>")
	return b.String()
}

func writeXMLElement(b *strings.Builder, name, value string) {
	b.WriteString("<" + name + ">")
	_ = xml.EscapeText(b, []byte(value))
	b.WriteString("</" + name + ">")
}

func writeXMLMembers(b *strings.Builder, name string, values []string) {
	open := false
	for _, value := range values {
		if value = strings.TrimSpace(value); value == "" {
			continue
		}
		if !open {
			b.WriteString("<" + name + ">")
			open = true
		}
		writeXMLElement(b, "member", value)
	}
	if open {
		b.WriteString("</" + name + ">")
	}
}

// applianceCommonName is the common name the firewall's request carries,
// which PAN-OS requires: the identity's, else its first DNS name or address.
func applianceCommonName(req connector.ApplianceKeyRequest) string {
	if name := strings.TrimSpace(req.CommonName); name != "" {
		return name
	}
	for _, names := range [][]string{req.DNSNames, req.IPAddresses} {
		for _, name := range names {
			if name = strings.TrimSpace(name); name != "" {
				return name
			}
		}
	}
	return ""
}

// sameFingerprint compares two certificate fingerprints in the forms the
// deploy path accepts: optional sha256: prefix, colons, either case.
func sameFingerprint(a, b string) bool {
	norm := func(fp string) string {
		fp = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(fp), "sha256:"))
		return strings.ReplaceAll(fp, ":", "")
	}
	return norm(a) != "" && norm(a) == norm(b)
}
