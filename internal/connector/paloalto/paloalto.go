// Package paloalto is the Palo Alto Networks (PAN-OS) deployment connector
// (S10.10), built from the connector SDK (S5.5). A PAN-OS firewall (and Panorama)
// is driven over the XML API, so — like the F5 BIG-IP, Citrix ADC, FortiGate, and
// AWS ACM connectors — it routes every privileged operation through the
// capability-gated Sandbox (sb.Request) and is conformance-tested and
// outbox-delivered.
//
// Renewal is the PAN-OS certificate *import*: the renewed material is POSTed to
// the import endpoint, which replaces the named certificate object in place and
// reloads it. PAN-OS imports the certificate and the private key as two separate
// objects under the same certificate-name (category=certificate, then
// category=private-key), so the connector makes one import call per part. Each is
// the same shape: the import parameters travel in the query string
// (type=import&category=…&certificate-name=…&format=pem) and the PEM travels as
// the request body; format=pem means PAN-OS reads the body verbatim. A PAN-OS
// import is idempotent — re-importing the same name overwrites the object with
// identical material — so a redeploy converges to the same firewall state.
//
// Authentication is the PAN-OS API key, presented in the X-PAN-KEY header. It
// crosses the wire on every call and is never logged, never placed in an error,
// and is carried in a field, not in the deployment payload. So this connector
// imports no crypto/* (AN-3): the key is opaque and there is no signing. The
// PAN-OS XML API also signals failure *inside* a 200 response — an HTTP 200 with
// <response status="error"> is a failed import — so a 2xx is necessary but not
// sufficient: the import is accepted only when the status is 2xx and the parsed
// XML envelope reports status="success" (equivalently, does not report a non-
// success status). The parse is a tiny status read, not a certificate parse.
// Least privilege is net.dial to the appliance host alone; no filesystem, no
// exec. Key material is carried as []byte (AN-8) and the PEM is opaque (no
// certificate parse).
package paloalto

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trustctl.io/trustctl/internal/connector"
	"trustctl.io/trustctl/internal/pluginhost"
)

// defaultName is the certificate object name used when the deployment target does
// not name one.
const defaultName = "trustctl"

// PAN-OS import categories: the certificate and the private key are imported as
// two distinct objects sharing one certificate-name.
const (
	categoryCertificate = "certificate"
	categoryPrivateKey  = "private-key"
)

// Connector deploys certificates to a Palo Alto Networks (PAN-OS) firewall or
// Panorama over the XML API.
type Connector struct {
	baseURL string // PAN-OS management base, e.g. https://fw.example (no trailing slash)
	host    string // host of baseURL, for the net.dial grant
	apiKey  string // PAN-OS API key (AN-8-adjacent: never logged)
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector. (None are required today — baseURL is the
// endpoint and the host is derived from it — but the variadic keeps the
// constructor forward-compatible with the other connectors.)
type Option func(*Connector)

// New returns a PAN-OS connector for the appliance at baseURL, authenticating
// with the PAN-OS API key. baseURL is the endpoint; the net.dial grant host is
// derived from it.
func New(baseURL string, apiKey string, opts ...Option) *Connector {
	c := &Connector{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
	}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "paloalto" }

// Capabilities declares the least privilege the connector needs: reach the
// appliance host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy imports the renewed certificate (and, when present, the private key)
// into the PAN-OS certificate object named by dep.Target (default "trustctl").
// The certificate and key are imported as two objects under the same name; the
// key import is skipped when no key is supplied (e.g. when the key already lives
// on the appliance in an HSM).
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	name := certName(dep.Target)

	if err := c.importPart(ctx, sb, categoryCertificate, name, dep.CertPEM); err != nil {
		return fmt.Errorf("paloalto: import certificate %q: %w", name, err)
	}
	if len(dep.KeyPEM) > 0 {
		if err := c.importPart(ctx, sb, categoryPrivateKey, name, dep.KeyPEM); err != nil {
			// Never include the key (or its bytes) in the error — only the name.
			return fmt.Errorf("paloalto: import private key for %q: %w", name, err)
		}
	}
	return nil
}

// importPart performs a single PAN-OS import: the parameters travel in the query
// string and the PEM travels as the request body. The call succeeds only when the
// HTTP status is 2xx and the PAN-OS XML envelope does not report a failure.
//
// PAN-OS signals an outcome two ways, and both must be honored: a non-2xx status,
// and — because the XML API answers some failures (auth, validation) with a 200
// carrying <response status="error"> — an error *inside* a 2xx. So a 2xx is
// necessary but not sufficient: the envelope's status is authoritative. A real
// PAN-OS import always returns <response status="success">; a body that carries
// no parseable envelope at all (no status to contradict success) is accepted, so
// a 2xx from a target that does not speak the XML envelope is not spuriously
// failed.
func (c *Connector) importPart(ctx context.Context, sb connector.Sandbox, category, name string, pem []byte) error {
	q := url.Values{}
	q.Set("type", "import")
	q.Set("category", category)
	q.Set("certificate-name", name)
	q.Set("format", "pem")
	endpoint := c.baseURL + "/api/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(pem))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-pem-file")
	// PAN-OS API key. Never logged, never placed in an error.
	req.Header.Set("X-PAN-KEY", c.apiKey)

	resp, err := sb.Request(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the read so a hostile/large body cannot blow up memory. PAN-OS error
	// bodies are small XML; the success body is too.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d: %s", resp.StatusCode, panMessage(body))
	}
	// PAN-OS reports failure inside a 200, so the XML status is authoritative.
	if panFailed(body) {
		return fmt.Errorf("PAN-OS reported failure: %s", panMessage(body))
	}
	return nil
}

// panResponse is the PAN-OS XML API envelope, parsed only far enough to read the
// outcome (the status attribute and any human-readable message). This is a status
// read, not a certificate parse — no crypto/*.
type panResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	// msg may be plain text (<msg>…</msg>) or a nested line list
	// (<msg><line>…</line></msg>); InnerXML captures either for diagnostics.
	Msg struct {
		Inner string `xml:",innerxml"`
	} `xml:"msg"`
}

// panFailed reports whether body is a PAN-OS XML response that explicitly signals
// a non-success outcome (status="error", or any status other than "success"). A
// body that does not parse as a PAN-OS envelope carries no status to contradict
// the 2xx, so it is not a failure — only an envelope present *and* not "success"
// is. This is the failure-in-200 case the PAN-OS XML API uses for auth and
// validation errors.
func panFailed(body []byte) bool {
	var r panResponse
	if err := xml.Unmarshal(body, &r); err != nil {
		return false // not a PAN-OS envelope; the 2xx stands
	}
	if r.XMLName.Local != "response" {
		return false // some other XML document; do not interpret its status
	}
	return r.Status != "success"
}

// panMessage extracts a short, key-free diagnostic from a PAN-OS response body
// for use in errors. PAN-OS does not echo the API key in its response, and the
// key never reaches this function, so the message is safe to surface.
func panMessage(body []byte) string {
	var r panResponse
	if err := xml.Unmarshal(body, &r); err == nil {
		if msg := strings.TrimSpace(r.Msg.Inner); msg != "" {
			return fmt.Sprintf("status=%q: %s", r.Status, msg)
		}
		if r.Status != "" {
			return fmt.Sprintf("status=%q", r.Status)
		}
	}
	return strings.TrimSpace(string(body))
}

// certName derives the certificate object name from the deployment target,
// falling back to the default when the target is empty.
func certName(target string) string {
	if target == "" {
		return defaultName
	}
	return target
}
