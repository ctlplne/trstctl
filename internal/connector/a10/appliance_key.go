// SPDX-License-Identifier: BUSL-1.1

package a10

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var _ connector.ApplianceKeyGenerator = (*Connector)(nil)

// GenerateApplianceKey asks the A10 to generate an ECDSA P-256 key file
// <object>.key and a CSR file <object>.csr for the request, and returns the CSR
// (A122). A CSR the A10 already holds for this object is returned as it is, so
// a reclaimed job continues with the key its earlier attempt made; a key file
// left by an attempt that stopped before its CSR is reused. The key file is
// never read.
func (c *Connector) GenerateApplianceKey(ctx context.Context, sb connector.Sandbox, req connector.ApplianceKeyRequest) (connector.ApplianceKey, error) {
	object := strings.TrimSpace(req.ObjectName)
	if object == "" {
		return connector.ApplianceKey{}, errors.New("a10: an appliance key needs an object name")
	}
	if strings.TrimSpace(req.CommonName) == "" && len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		return connector.ApplianceKey{}, errors.New("a10: an appliance key request names nothing to certify")
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("a10: %w", err)
	}
	defer secret.Wipe(token)

	keyFile, csrFile := object+".key", object+".csr"
	if csrPEM, found, err := c.readCSR(ctx, sb, token, csrFile); err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("a10: read CSR %q: %w", csrFile, err)
	} else if found {
		return connector.ApplianceKey{ObjectName: object, CSRPEM: csrPEM}, nil
	}
	data, err := c.call(ctx, sb, http.MethodPost, "/axapi/v3/pki/create", token, map[string]any{
		"create": map[string]any{
			"key-file": keyFile, "csr-file": csrFile, "csr-generate": 1, "ec-curve": "prime256v1",
			"common-name": strings.TrimSpace(req.CommonName), "subject-alternate-name": a10SubjectAltNames(req),
		},
	})
	secret.Wipe(data)
	// An existing key file is an earlier attempt's key, reused.
	var se *statusError
	if err != nil && (!errors.As(err, &se) || se.code != http.StatusConflict) {
		return connector.ApplianceKey{}, fmt.Errorf("a10: generate key %q: %w", keyFile, err)
	}
	csrPEM, found, err := c.readCSR(ctx, sb, token, csrFile)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("a10: read CSR %q: %w", csrFile, err)
	}
	if !found || len(csrPEM) == 0 {
		return connector.ApplianceKey{}, fmt.Errorf("a10: the appliance wrote no CSR to %q", csrFile)
	}
	return connector.ApplianceKey{ObjectName: object, CSRPEM: csrPEM}, nil
}

// InstallWithApplianceKey uploads the signed certificate under its
// fingerprint-derived file name, as Deploy does, and points the client-SSL
// template named by dep.Target at it and at the key the A10 generated. No key
// is uploaded.
func (c *Connector) InstallWithApplianceKey(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, key connector.ApplianceKey) error {
	object := strings.TrimSpace(key.ObjectName)
	if object == "" {
		return errors.New("a10: an appliance-key install needs the key's object name")
	}
	if len(dep.KeyPEM) != 0 {
		return errors.New("a10: an appliance-key install must not carry a private key")
	}
	if strings.TrimSpace(dep.Target) == "" || len(dep.CertPEM) == 0 {
		return errors.New("a10: an appliance-key install needs a client-ssl template and a certificate")
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("a10: %w", err)
	}
	defer secret.Wipe(token)
	certFile := connector.DeployedObjectName(dep.Target, dep.Fingerprint) + ".crt"
	if err := c.upload(ctx, sb, token, "ssl-cert", certFile, dep.CertPEM); err != nil {
		return fmt.Errorf("a10: upload certificate: %w", err)
	}
	if err := c.bind(ctx, sb, token, dep.Target, certFile, object+".key"); err != nil {
		return fmt.Errorf("a10: bind client-ssl template %q to the appliance key: %w", dep.Target, err)
	}
	return nil
}

// readCSR reads a CSR file the A10 holds. found is false when it has none.
func (c *Connector) readCSR(ctx context.Context, sb connector.Sandbox, token []byte, name string) ([]byte, bool, error) {
	data, err := c.call(ctx, sb, http.MethodGet, "/axapi/v3/file/csr/"+url.PathEscape(name), token, nil)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	var out struct {
		CSR struct {
			FileContent string `json:"file-content"`
		} `json:"csr"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, false, errors.New("decode CSR response failed")
	}
	content, err := base64.StdEncoding.DecodeString(out.CSR.FileContent)
	if err != nil || len(content) == 0 {
		return nil, false, errors.New("the CSR response carried no content")
	}
	return content, true, nil
}

// a10SubjectAltNames renders the request's names as aXAPI subject alternate
// name entries.
func a10SubjectAltNames(req connector.ApplianceKeyRequest) []map[string]string {
	out := make([]map[string]string, 0, len(req.DNSNames)+len(req.IPAddresses))
	for _, name := range req.DNSNames {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, map[string]string{"type": "dns", "value": name})
		}
	}
	for _, ip := range req.IPAddresses {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, map[string]string{"type": "ip", "value": ip})
		}
	}
	return out
}
