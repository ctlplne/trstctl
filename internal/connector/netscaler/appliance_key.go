// SPDX-License-Identifier: BUSL-1.1

package netscaler

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

// GenerateApplianceKey asks the NetScaler to generate an ECDSA P-256 key into
// <object>.key and a CSR for the request into <object>.csr, and returns the
// CSR (A122). A CSR already on the appliance for this object is returned as it
// is, so a reclaimed job continues with the key its earlier attempt made; a key
// file left by an attempt that stopped before its CSR is reused. The key file
// is never read: only the CSR leaves the appliance.
func (c *Connector) GenerateApplianceKey(ctx context.Context, sb connector.Sandbox, req connector.ApplianceKeyRequest) (connector.ApplianceKey, error) {
	object := strings.TrimSpace(req.ObjectName)
	if object == "" {
		return connector.ApplianceKey{}, errors.New("netscaler: an appliance key needs an object name")
	}
	if strings.TrimSpace(req.CommonName) == "" && len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		return connector.ApplianceKey{}, errors.New("netscaler: an appliance key request names nothing to certify")
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("netscaler: %w", err)
	}
	defer secret.Wipe(token)
	defer func() { _ = c.logout(ctx, sb, token) }()

	keyFile, csrFile := object+".key", object+".csr"
	csrPEM, found, err := c.readPublicFile(ctx, sb, token, csrFile)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("netscaler: read CSR %q: %w", csrFile, err)
	}
	if found {
		return connector.ApplianceKey{ObjectName: object, CSRPEM: csrPEM}, nil
	}
	data, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/sslecdsakey?action=create", token, sslecdsakeyReq{
		Sslecdsakey: sslecdsakey{Keyfile: keyFile, Curve: "P_256", Keyform: "PEM"},
	})
	secret.Wipe(data)
	var se *statusError
	// An existing key file is an earlier attempt's key, reused.
	if err != nil && (!errors.As(err, &se) || se.code != http.StatusConflict) {
		return connector.ApplianceKey{}, fmt.Errorf("netscaler: generate key %q: %w", keyFile, err)
	}
	data, err = c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/sslcertreq?action=create", token, sslcertreqReq{
		Sslcertreq: sslcertreq{
			Reqfile: csrFile, Keyfile: keyFile, Keyform: "PEM",
			Commonname: strings.TrimSpace(req.CommonName), Subjectaltname: subjectAltName(req),
		},
	})
	secret.Wipe(data)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("netscaler: create CSR %q: %w", csrFile, err)
	}
	csrPEM, found, err = c.readPublicFile(ctx, sb, token, csrFile)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("netscaler: read CSR %q: %w", csrFile, err)
	}
	if !found || len(csrPEM) == 0 {
		return connector.ApplianceKey{}, fmt.Errorf("netscaler: the appliance wrote no CSR to %q", csrFile)
	}
	return connector.ApplianceKey{ObjectName: object, CSRPEM: csrPEM}, nil
}

// InstallWithApplianceKey uploads the signed certificate under its
// fingerprint-derived file name, as Deploy does, and re-points the certkey
// named by dep.Target at it and at the key the appliance generated. No key is
// uploaded.
func (c *Connector) InstallWithApplianceKey(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, key connector.ApplianceKey) error {
	object := strings.TrimSpace(key.ObjectName)
	if object == "" {
		return errors.New("netscaler: an appliance-key install needs the key's object name")
	}
	if len(dep.KeyPEM) != 0 {
		return errors.New("netscaler: an appliance-key install must not carry a private key")
	}
	if strings.TrimSpace(dep.Target) == "" || len(dep.CertPEM) == 0 {
		return errors.New("netscaler: an appliance-key install needs a certkey and a certificate")
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("netscaler: %w", err)
	}
	defer secret.Wipe(token)
	defer func() { _ = c.logout(ctx, sb, token) }()

	certFile := connector.DeployedObjectName(dep.Target, dep.Fingerprint) + ".crt"
	if err := c.upload(ctx, sb, token, certFile, dep.CertPEM); err != nil {
		return fmt.Errorf("netscaler: upload certificate: %w", err)
	}
	if err := c.rebind(ctx, sb, token, dep.Target, certFile, object+".key"); err != nil {
		return fmt.Errorf("netscaler: rebind certkey %q to the appliance key: %w", dep.Target, err)
	}
	return nil
}

// readPublicFile reads a system file this connector may read: a CSR or a
// certificate, never a key. found is false when the file does not exist.
func (c *Connector) readPublicFile(ctx context.Context, sb connector.Sandbox, token []byte, filename string) ([]byte, bool, error) {
	if strings.HasSuffix(filename, ".key") {
		return nil, false, errors.New("a key file is not read back")
	}
	path := "/nitro/v1/config/systemfile?args=filename:" + url.PathEscape(filename) +
		",filelocation:" + url.PathEscape(c.fileLocation)
	data, err := c.call(ctx, sb, http.MethodGet, path, token, nil)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	var out struct {
		Systemfile []struct {
			Filecontent string `json:"filecontent"`
		} `json:"systemfile"`
	}
	if err := json.Unmarshal(data, &out); err != nil || len(out.Systemfile) == 0 {
		return nil, false, errors.New("decode system file response failed")
	}
	content, err := base64.StdEncoding.DecodeString(out.Systemfile[0].Filecontent)
	if err != nil {
		return nil, false, errors.New("system file content is not base64")
	}
	return content, true, nil
}

// subjectAltName renders the request's names in NITRO's subjectaltname form.
func subjectAltName(req connector.ApplianceKeyRequest) string {
	parts := make([]string, 0, len(req.DNSNames)+len(req.IPAddresses))
	for _, name := range req.DNSNames {
		if name = strings.TrimSpace(name); name != "" {
			parts = append(parts, "DNS:"+name)
		}
	}
	for _, ip := range req.IPAddresses {
		if ip = strings.TrimSpace(ip); ip != "" {
			parts = append(parts, "IP:"+ip)
		}
	}
	return strings.Join(parts, " ")
}

type sslecdsakeyReq struct {
	Sslecdsakey sslecdsakey `json:"sslecdsakey"`
}

type sslecdsakey struct {
	Keyfile string `json:"keyfile"`
	Curve   string `json:"curve"`
	Keyform string `json:"keyform"`
}

type sslcertreqReq struct {
	Sslcertreq sslcertreq `json:"sslcertreq"`
}

type sslcertreq struct {
	Reqfile        string `json:"reqfile"`
	Keyfile        string `json:"keyfile"`
	Keyform        string `json:"keyform"`
	Commonname     string `json:"commonname,omitempty"`
	Subjectaltname string `json:"subjectaltname,omitempty"`
}
