// SPDX-License-Identifier: BUSL-1.1

package cisco

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// Appliance-generated keys on Cisco ISE (A122, owner decision 2026-10-26).
//
// ISE generates the key and a CSR on the node and names the request with an
// ID of its own, so a renewal cannot find its request by a name the relay
// picks. The ID travels back in ApplianceKey.Reference; the relay keeps it for
// the job on the control plane and hands it back to every later attempt, which
// reuses the request instead of leaving an orphan. Binding the signed
// certificate to the request turns it into a system certificate holding the
// key ISE generated, named for the certificate fingerprint and bound to the
// target's roles, so readback and rollback work as they do for an import.

const (
	isePathCSR       = "/api/v1/certs/certificate-signing-request"
	isePathCSRExport = "/api/v1/certs/certificate-signing-request/export/"
	isePathBind      = "/api/v1/certs/signed-certificate/bind"
)

var _ connector.ApplianceKeyGenerator = (*Connector)(nil)

type iseCSRRequest struct {
	Hostnames         []string `json:"hostnames"`
	SubjectCommonName string   `json:"subjectCommonName"`
	SANDNS            []string `json:"sanDNS,omitempty"`
	SANIP             []string `json:"sanIP,omitempty"`
	KeyType           string   `json:"keyType"`
	KeyLength         string   `json:"keyLength"`
	DigestType        string   `json:"digestType"`
	UsedFor           string   `json:"usedFor"`
}

type iseBindRequest struct {
	HostName string                 `json:"hostName"`
	ID       string                 `json:"id"`
	Data     secretjson.StringBytes `json:"data"`
	Name     string                 `json:"name"`
	iseRoleFlags
}

// GenerateApplianceKey returns the CSR for the job's key on the ISE node: the
// request an earlier attempt recorded (req.Reference) when ISE still holds it,
// otherwise a new ECDSA P-256 request ISE generates. ISE turns a request into
// its system certificate when a certificate is bound to it, so a recorded
// request that is gone was installed by an earlier attempt or removed; that
// stops with ErrApplianceKeyAlreadyInstalled rather than making a second key.
func (c *Connector) GenerateApplianceKey(ctx context.Context, sb connector.Sandbox, req connector.ApplianceKeyRequest) (connector.ApplianceKey, error) {
	if err := c.iseConfigured(); err != nil {
		return connector.ApplianceKey{}, err
	}
	commonName := strings.TrimSpace(req.CommonName)
	for _, names := range [][]string{req.DNSNames, req.IPAddresses} {
		for _, name := range names {
			if commonName == "" {
				commonName = strings.TrimSpace(name)
			}
		}
	}
	if commonName == "" {
		return connector.ApplianceKey{}, errors.New("cisco: an appliance key request names nothing to certify")
	}
	if ref := strings.TrimSpace(req.Reference); ref != "" {
		csrPEM, found, err := c.exportCSR(ctx, sb, ref)
		if err != nil {
			return connector.ApplianceKey{}, fmt.Errorf("cisco: export CSR %q from %s: %w", ref, c.node, err)
		}
		if !found {
			return connector.ApplianceKey{}, fmt.Errorf("cisco: CSR %q on %s: %w", ref, c.node, connector.ErrApplianceKeyAlreadyInstalled)
		}
		return connector.ApplianceKey{ObjectName: req.ObjectName, CSRPEM: csrPEM, Reference: ref}, nil
	}
	body, err := json.Marshal(iseCSRRequest{
		Hostnames: []string{c.node}, SubjectCommonName: commonName,
		SANDNS: nonEmpty(req.DNSNames), SANIP: nonEmpty(req.IPAddresses),
		KeyType: "ECDSA", KeyLength: "256", DigestType: "SHA-256", UsedFor: "MULTI-USE",
	})
	if err != nil {
		return connector.ApplianceKey{}, err
	}
	raw, err := c.iseCall(ctx, sb, http.MethodPost, isePathCSR, body)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("cisco: generate a CSR on %s: %w", c.node, err)
	}
	var created struct {
		Response []struct {
			ID string `json:"id"`
		} `json:"response"`
	}
	err = json.Unmarshal(raw, &created)
	secret.Wipe(raw)
	if err != nil || len(created.Response) != 1 || strings.TrimSpace(created.Response[0].ID) == "" {
		return connector.ApplianceKey{}, fmt.Errorf("cisco: %s answered the CSR request without one request ID", c.node)
	}
	ref := strings.TrimSpace(created.Response[0].ID)
	csrPEM, found, err := c.exportCSR(ctx, sb, ref)
	if err != nil {
		return connector.ApplianceKey{}, fmt.Errorf("cisco: export the new CSR %q from %s: %w", ref, c.node, err)
	}
	if !found {
		return connector.ApplianceKey{}, fmt.Errorf("cisco: %s does not hold the CSR %q it just generated", c.node, ref)
	}
	return connector.ApplianceKey{ObjectName: req.ObjectName, CSRPEM: csrPEM, Reference: ref}, nil
}

// InstallWithApplianceKey binds the signed certificate to the ISE request the
// key was generated for, under its fingerprint name and with the target's
// roles. Only the leaf is sent; ISE must already trust the issuing CA.
func (c *Connector) InstallWithApplianceKey(ctx context.Context, sb connector.Sandbox, dep connector.Deployment, key connector.ApplianceKey) error {
	if err := c.iseConfigured(); err != nil {
		return err
	}
	ref := strings.TrimSpace(key.Reference)
	if ref == "" {
		return errors.New("cisco: an appliance-key install needs the ISE request ID")
	}
	if len(dep.KeyPEM) != 0 {
		return errors.New("cisco: an appliance-key install must not carry a private key")
	}
	if strings.TrimSpace(dep.Fingerprint) == "" {
		return errors.New("cisco: an appliance-key install needs the certificate fingerprint to name the system certificate")
	}
	leaf, _ := pem.Decode(dep.CertPEM)
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return errors.New("cisco: an appliance-key install needs a PEM certificate")
	}
	name := connector.DeployedObjectName(certBase(dep.Target), dep.Fingerprint)
	body, err := json.Marshal(iseBindRequest{
		HostName: c.node, ID: ref, Data: secretjson.StringBytes(pem.EncodeToMemory(leaf)), Name: name,
		iseRoleFlags: c.roleFlags(),
	})
	if err != nil {
		return err
	}
	if _, err := c.iseCall(ctx, sb, http.MethodPost, isePathBind, body); err != nil {
		return fmt.Errorf("cisco: bind the signed certificate to CSR %q on %s: %w", ref, c.node, err)
	}
	return nil
}

// exportCSR reads a pending request's CSR; found is false when ISE no longer
// holds the request.
func (c *Connector) exportCSR(ctx context.Context, sb connector.Sandbox, ref string) ([]byte, bool, error) {
	raw, err := c.iseCall(ctx, sb, http.MethodGet, isePathCSRExport+url.PathEscape(c.node)+"/"+url.PathEscape(ref), nil)
	var status iseStatusError
	if errors.As(err, &status) && status.code == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	block, _ := pem.Decode(raw)
	secret.Wipe(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, false, errors.New("the export carried no PEM certificate request")
	}
	return pem.EncodeToMemory(block), true, nil
}

func nonEmpty(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
