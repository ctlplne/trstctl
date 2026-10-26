// SPDX-License-Identifier: BUSL-1.1

package cisco

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

var (
	_ connector.Rollbacker = (*Connector)(nil)
	_ connector.Readbacker = (*Connector)(nil)
)

// ISE mode (A122, owner decision 2026-10-26).
//
// A target that names the ISE node (node_hostname) and the roles its
// certificate serves (certificate_roles) deploys through ISE's OpenAPI
// system-certificate calls instead of the legacy import. Each certificate is
// imported under a fingerprint-derived friendly name and bound to those roles
// on that node, so the predecessor stays in the node's system store; moving the
// roles back to it is the rollback, and the certificate holding the roles is
// what readback reports. A target without a node keeps the legacy import and
// reports rollback and readback as not configured.

const (
	isePathImport    = "/api/v1/certs/system-certificate/import"
	isePathSystem    = "/api/v1/certs/system-certificate/"
	isePortalGroup   = "Default Portal Certificate Group"
	isePageSize      = 100
	iseMaxPages      = 50
	iseResponseLimit = 1 << 20
)

// iseRoleUsage maps the role a target names to the usage name ISE reports in
// a system certificate's usedBy.
var iseRoleUsage = map[string]string{
	"admin":  "Admin",
	"eap":    "EAP Authentication",
	"radius": "RADIUS DTLS",
	"pxgrid": "pxGrid",
	"portal": "Portal",
	"saml":   "SAML",
	"ims":    "ISE Messaging Service",
}

// ISERoles lists the certificate roles a target may name, sorted.
func ISERoles() []string {
	out := make([]string, 0, len(iseRoleUsage))
	for role := range iseRoleUsage {
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}

// ValidateISETarget checks a target's ISE node and roles: both or neither, at
// least one role, only roles ISE assigns, none twice.
func ValidateISETarget(node string, roles []string) error {
	node = strings.TrimSpace(node)
	if node == "" && len(roles) == 0 {
		return nil
	}
	if node == "" || len(roles) == 0 {
		return errors.New("cisco: node_hostname and certificate_roles go together: name the ISE node and the roles its certificate serves")
	}
	seen := map[string]bool{}
	for _, role := range roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if _, known := iseRoleUsage[role]; !known {
			return fmt.Errorf("cisco: certificate role %q is not one ISE assigns (%s)", role, strings.Join(ISERoles(), ", "))
		}
		if seen[role] {
			return fmt.Errorf("cisco: certificate role %q is named twice", role)
		}
		seen[role] = true
	}
	return nil
}

// WithISENode makes deploys ISE system-certificate imports on node, named for
// the certificate fingerprint and bound to roles, which is what makes the
// target rollback- and readback-capable.
func WithISENode(node string, roles []string) Option {
	return func(c *Connector) {
		c.node = strings.TrimSpace(node)
		c.roles = nil
		for _, role := range roles {
			if role = strings.ToLower(strings.TrimSpace(role)); role != "" {
				c.roles = append(c.roles, role)
			}
		}
		sort.Strings(c.roles)
	}
}

func (c *Connector) iseConfigured() error {
	if c.node == "" {
		return errors.New("cisco: this target names no node_hostname and certificate_roles")
	}
	return ValidateISETarget(c.node, c.roles)
}

// iseRoleFlags are the role switches ISE's import, bind and update calls take.
type iseRoleFlags struct {
	Admin                          bool   `json:"admin"`
	EAP                            bool   `json:"eap"`
	RADIUS                         bool   `json:"radius"`
	PxGrid                         bool   `json:"pxgrid"`
	Portal                         bool   `json:"portal"`
	SAML                           bool   `json:"saml"`
	IMS                            bool   `json:"ims"`
	PortalGroupTag                 string `json:"portalGroupTag,omitempty"`
	AllowReplacementOfCertificates bool   `json:"allowReplacementOfCertificates"`
}

func (c *Connector) roleFlags() iseRoleFlags {
	has := func(role string) bool {
		for _, r := range c.roles {
			if r == role {
				return true
			}
		}
		return false
	}
	flags := iseRoleFlags{
		Admin: has("admin"), EAP: has("eap"), RADIUS: has("radius"), PxGrid: has("pxgrid"),
		Portal: has("portal"), SAML: has("saml"), IMS: has("ims"),
		AllowReplacementOfCertificates: true,
	}
	if flags.Portal {
		flags.PortalGroupTag = isePortalGroup
	}
	return flags
}

type iseImportRequest struct {
	Name           string                 `json:"name"`
	Data           secretjson.StringBytes `json:"data"`
	PrivateKeyData secretjson.StringBytes `json:"privateKeyData"`
	iseRoleFlags
}

type iseUpdateRequest struct {
	Name string `json:"name"`
	iseRoleFlags
}

type iseSystemCertificate struct {
	ID           string `json:"id"`
	FriendlyName string `json:"friendlyName"`
	UsedBy       string `json:"usedBy"`
}

// serves reports whether the certificate holds role.
func (sc iseSystemCertificate) serves(role string) bool {
	usage := iseRoleUsage[role]
	for _, part := range strings.Split(sc.UsedBy, ",") {
		if strings.EqualFold(strings.TrimSpace(part), usage) {
			return true
		}
	}
	return false
}

// deployISE imports the pair under its fingerprint name, bound to the roles.
func (c *Connector) deployISE(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := c.iseConfigured(); err != nil {
		return err
	}
	if strings.TrimSpace(dep.Fingerprint) == "" {
		return errors.New("cisco: an ISE deploy needs the certificate fingerprint to name the system certificate")
	}
	name := connector.DeployedObjectName(certBase(dep.Target), dep.Fingerprint)
	body, err := json.Marshal(iseImportRequest{
		Name: name, Data: secretjson.StringBytes(dep.CertPEM), PrivateKeyData: secretjson.StringBytes(dep.KeyPEM),
		iseRoleFlags: c.roleFlags(),
	})
	if err != nil {
		return fmt.Errorf("cisco: encode ISE import: %w", err)
	}
	// The body carries the private key; it is the transient edge copy (AN-8).
	defer secret.Wipe(body)
	if _, err := c.iseCall(ctx, sb, http.MethodPost, isePathImport, body); err != nil {
		return fmt.Errorf("cisco: import system certificate %q on %s: %w", name, c.node, err)
	}
	return nil
}

// Rollback moves the target's roles back to the predecessor's system
// certificate, which a fingerprint-named deploy left in the node's store.
// Nothing is uploaded.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if c.node == "" {
		return connector.ErrRollbackNotConfigured
	}
	if err := c.iseConfigured(); err != nil {
		return err
	}
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	name := connector.RollbackObjectName(certBase(rb.Target), rb.PredecessorFingerprint)
	certs, err := c.listSystemCertificates(ctx, sb)
	if err != nil {
		return fmt.Errorf("cisco: list system certificates on %s: %w", c.node, err)
	}
	for _, sc := range certs {
		if sc.FriendlyName != name {
			continue
		}
		body, err := json.Marshal(iseUpdateRequest{Name: sc.FriendlyName, iseRoleFlags: c.roleFlags()})
		if err != nil {
			return err
		}
		path := isePathSystem + url.PathEscape(c.node) + "/" + url.PathEscape(sc.ID)
		if _, err := c.iseCall(ctx, sb, http.MethodPut, path, body); err != nil {
			return fmt.Errorf("cisco: move roles back to %q on %s: %w", name, c.node, err)
		}
		return nil
	}
	return fmt.Errorf("cisco: predecessor system certificate %q on %s: %w", name, c.node, connector.ErrNoPredecessorInstalled)
}

// Readback reports the system certificate serving the target's roles on the
// node, as ISE's system store states it.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, _ string) (connector.Installed, error) {
	if c.node == "" {
		return connector.Installed{}, connector.ErrReadbackNotConfigured
	}
	if err := c.iseConfigured(); err != nil {
		return connector.Installed{}, err
	}
	certs, err := c.listSystemCertificates(ctx, sb)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("cisco: list system certificates on %s: %w", c.node, err)
	}
	for _, sc := range certs {
		if !sc.serves(c.roles[0]) {
			continue
		}
		bound := true
		for _, role := range c.roles[1:] {
			bound = bound && sc.serves(role)
		}
		return connector.Installed{
			Fingerprint: connector.FingerprintFromObjectName(sc.FriendlyName), ObjectName: sc.FriendlyName, Bound: bound,
		}, nil
	}
	return connector.Installed{}, nil
}

// listSystemCertificates reads the node's whole system store, a page at a time.
func (c *Connector) listSystemCertificates(ctx context.Context, sb connector.Sandbox) ([]iseSystemCertificate, error) {
	var out []iseSystemCertificate
	for page := 1; page <= iseMaxPages; page++ {
		path := isePathSystem + url.PathEscape(c.node) + "?page=" + strconv.Itoa(page) + "&size=" + strconv.Itoa(isePageSize)
		raw, err := c.iseCall(ctx, sb, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var body struct {
			Response []iseSystemCertificate `json:"response"`
		}
		err = json.Unmarshal(raw, &body)
		secret.Wipe(raw)
		if err != nil {
			return nil, errors.New("the system certificate list did not decode")
		}
		out = append(out, body.Response...)
		if len(body.Response) < isePageSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("the node lists more than %d system certificates", isePageSize*iseMaxPages)
}

// iseStatusError is a non-2xx answer from ISE. The body is not kept: an error
// body can echo the request, and the request may carry a key.
type iseStatusError struct{ code int }

func (e iseStatusError) Error() string {
	return fmt.Sprintf("status %d (response body redacted)", e.code)
}

// iseCall makes one ISE OpenAPI request and returns the bounded body of a 2xx
// answer.
func (c *Connector) iseCall(ctx context.Context, sb connector.Sandbox, method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.basicAuth())
	resp, err := sb.Request(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, iseStatusError{code: resp.StatusCode}
	}
	out, err := secret.ReadBounded(resp.Body, iseResponseLimit)
	if err != nil {
		return nil, errors.New("read response (details redacted)")
	}
	return out, nil
}

// certBase is the object base a deploy names certificates from: the target,
// or the connector's default name.
func certBase(target string) string {
	if strings.TrimSpace(target) == "" {
		return defaultName
	}
	return target
}
