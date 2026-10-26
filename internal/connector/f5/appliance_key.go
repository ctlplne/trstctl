// SPDX-License-Identifier: BUSL-1.1

package f5

import (
	"bytes"
	"context"
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

// GenerateApplianceKey asks the BIG-IP to generate an ECDSA P-256 key into
// the crypto object <object>.key together with a CSR named <object>, and
// returns the CSR (A122). A CSR the BIG-IP already holds for this object is
// returned as it is, so a reclaimed job continues with the key its earlier
// attempt made. The key is never read back.
func (c *Connector) GenerateApplianceKey(ctx context.Context, sb connector.Sandbox, req connector.ApplianceKeyRequest) (connector.ApplianceKey, error) {
	object := strings.TrimSpace(req.ObjectName)
	if object == "" {
		return connector.ApplianceKey{}, errors.New("f5: an appliance key needs an object name")
	}
	if strings.TrimSpace(req.CommonName) == "" && len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		return connector.ApplianceKey{}, errors.New("f5: an appliance key request names nothing to certify")
	}
	csrPEM, found, err := c.readCSR(ctx, sb, object)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("f5: read CSR %q: %w", object, err)
	}
	if found {
		return connector.ApplianceKey{ObjectName: object, CSRPEM: csrPEM}, nil
	}
	status, err := c.callStatus(ctx, sb, http.MethodPost, "/mgmt/tm/sys/crypto/key", map[string]any{
		"name": object + ".key", "keyType": "ec-private", "curveName": "prime256v1",
		"commonName": strings.TrimSpace(req.CommonName), "subjectAlternativeName": f5SubjectAltName(req),
		"options": []map[string]string{{"gen-csr": object}},
	})
	// 409: an earlier attempt's key, whose CSR is read below.
	if err != nil && status != http.StatusConflict {
		return connector.ApplianceKey{}, fmt.Errorf("f5: generate key %q: %w", object, err)
	}
	csrPEM, found, err = c.readCSR(ctx, sb, object)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("f5: read CSR %q: %w", object, err)
	}
	if !found || len(csrPEM) == 0 {
		return connector.ApplianceKey{}, fmt.Errorf("f5: the BIG-IP holds no CSR %q", object)
	}
	return connector.ApplianceKey{ObjectName: object, CSRPEM: csrPEM}, nil
}

// InstallWithApplianceKey uploads and installs the signed certificate under
// its fingerprint-derived object name, as Deploy does, and binds the Client SSL
// profile to it and to the key the BIG-IP generated. No key is uploaded.
func (c *Connector) InstallWithApplianceKey(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, key connector.ApplianceKey) error {
	object := strings.TrimSpace(key.ObjectName)
	if object == "" {
		return errors.New("f5: an appliance-key install needs the key's object name")
	}
	if len(dep.KeyPEM) != 0 {
		return errors.New("f5: an appliance-key install must not carry a private key")
	}
	if len(dep.CertPEM) == 0 {
		return errors.New("f5: an appliance-key install needs a certificate")
	}
	base := connector.DeployedObjectName(c.name, dep.Fingerprint)
	certName := base + ".crt"
	if err := c.call(ctx, sb, http.MethodPost, "/mgmt/shared/file-transfer/uploads/"+certName, "application/octet-stream", dep.CertPEM); err != nil {
		return fmt.Errorf("f5: upload certificate: %w", err)
	}
	if err := c.callJSON(ctx, sb, http.MethodPost, "/mgmt/tm/sys/crypto/cert", map[string]string{
		"command": "install", "name": certName, "from-local-file": "/var/config/rest/downloads/" + certName,
	}); err != nil {
		return fmt.Errorf("f5: install certificate: %w", err)
	}
	if err := c.bindProfile(ctx, sb, base, certName, object+".key"); err != nil {
		return fmt.Errorf("f5: bind to profile %q with the appliance key: %w", c.profile, err)
	}
	return nil
}

// readCSR reads the CSR the BIG-IP holds under name. found is false when it
// has none.
func (c *Connector) readCSR(ctx context.Context, sb connector.Sandbox, name string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/mgmt/tm/sys/crypto/csr/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", c.basicAuth())
	resp, err := sb.Request(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, false, nil
	}
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, false, fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
	}
	data, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, false, errors.New("read CSR response failed")
	}
	var out struct {
		CSRPem string `json:"csrPem"`
	}
	if err := json.Unmarshal(data, &out); err != nil || strings.TrimSpace(out.CSRPem) == "" {
		return nil, false, errors.New("the CSR response carried no PEM")
	}
	return []byte(out.CSRPem), true, nil
}

// callStatus is callJSON that also reports the HTTP status of a refusal.
func (c *Connector) callStatus(ctx context.Context, sb connector.Sandbox, method, path string, payload any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("encode request: %w", err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.basicAuth())
	resp, err := sb.Request(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_ = secret.DrainBounded(resp.Body, 1<<20)
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// f5SubjectAltName renders the request's names in tmsh's
// subject-alternative-name form.
func f5SubjectAltName(req connector.ApplianceKeyRequest) string {
	parts := make([]string, 0, len(req.DNSNames)+len(req.IPAddresses))
	for _, name := range req.DNSNames {
		if name = strings.TrimSpace(name); name != "" {
			parts = append(parts, "DNS:"+name)
		}
	}
	for _, ip := range req.IPAddresses {
		if ip = strings.TrimSpace(ip); ip != "" {
			parts = append(parts, "IP Address:"+ip)
		}
	}
	return strings.Join(parts, ", ")
}
