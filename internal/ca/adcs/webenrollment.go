// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const webEnrollmentMaxBody = 1 << 20

var requestIDPattern = regexp.MustCompile(`(?i)(?:ReqID=|Request\s*ID[^0-9]*)([0-9]+)`)

// WebEnrollmentConfig configures ADCS's real /certsrv Web Enrollment transport.
// ADCS deployments commonly front this endpoint with Windows authentication;
// Username/Password supports Basic authentication when IIS enables it over TLS.
// A reverse proxy may supply Kerberos/NTLM and inject an already-authenticated
// HTTPClient instead.
type WebEnrollmentConfig struct {
	BaseURL  string
	Username string
	Password []byte
	// Authenticator supplies domain-integrated authentication (F4). When set it
	// REPLACES Basic entirely: the relay is domain-joined, so it can answer a
	// Negotiate or NTLM challenge without this process ever holding a password.
	//
	// An interface rather than a Kerberos implementation because the credential
	// lives on the relay host, not here. Core stays free of a GSSAPI dependency
	// and, more importantly, of any code path that could serialise a domain
	// password.
	Authenticator Authenticator
	HTTPClient    *http.Client
	Timeout       time.Duration
}

// Authenticator answers an AD CS authentication challenge on behalf of a
// domain-joined host.
type Authenticator interface {
	// Authorize sets whatever credential header the scheme needs. It is given
	// the challenge the server sent, so a multi-leg scheme (NTLM's three-way,
	// SPNEGO's mutual auth) can drive its own state machine.
	//
	// It must never receive or return a password: the point of domain
	// integration is that the secret stays in the host's credential store.
	Authorize(req *http.Request, challenge string) error
	// Scheme names what it implements, for the WWW-Authenticate match and for
	// operator-facing diagnostics that have to say which auth was used.
	Scheme() string
}

// WebEnrollmentTransport implements the documented certsrv new-request and
// pending-retrieval endpoints. It is a production wire transport, not a registry
// test double.
type WebEnrollmentTransport struct {
	baseURL  string
	username string
	password []byte
	auth     Authenticator
	client   *http.Client
	timeout  time.Duration
}

var _ Transport = (*WebEnrollmentTransport)(nil)

func NewWebEnrollmentTransport(cfg WebEnrollmentConfig) (*WebEnrollmentTransport, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("adcs: Web Enrollment base URL is required")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("adcs: Web Enrollment base URL must be absolute")
	}
	// F4: configuring both a password and a domain authenticator is ambiguous,
	// and the ambiguity is dangerous. The authenticator wins, so the password
	// is dead config — but dead config in a credential field is exactly what
	// somebody later "fixes" by making it take effect. Refuse it instead.
	if cfg.Authenticator != nil && len(cfg.Password) > 0 {
		return nil, errors.New(
			"adcs: both a password and a domain authenticator are configured; the authenticator " +
				"is used and the password would never be sent. Remove the password rather than " +
				"leaving a live domain credential in configuration that nothing reads")
	}
	// F4: a password may not leave this process over plaintext.
	//
	// Basic sends base64, which is an encoding and not a protection — anyone on
	// the path reads the CA operator's domain credential and can then issue from
	// the enterprise CA directly. This is refused at CONSTRUCTION rather than at
	// send time so a misconfiguration fails when the operator sets it up, not
	// silently on the first issuance in production.
	if len(cfg.Password) > 0 && !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf(
			"adcs: refusing to send a password to %s over %s; Basic is base64, not encryption, and "+
				"anyone on the path would read a credential that can issue from your enterprise CA. "+
				"Use https, or a domain-integrated Authenticator that never sends the password at all",
			u.Host, u.Scheme)
	}
	// Accept both https://host and https://host/certsrv without duplicating the
	// conventional virtual directory.
	if !strings.HasSuffix(strings.ToLower(u.Path), "/certsrv") {
		base += "/certsrv"
	}
	client := cfg.HTTPClient
	if client == nil {
		if err := ca.ValidateExternalCAEndpoint("adcs", base, ca.HTTPClientConfig{}); err != nil {
			return nil, err
		}
		client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{})
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &WebEnrollmentTransport{
		baseURL: base, username: cfg.Username, password: secrettext.Clone(cfg.Password),
		auth:   cfg.Authenticator,
		client: client, timeout: timeout,
	}, nil
}

// Destroy erases the IIS credential and drops idle network connections.
func (t *WebEnrollmentTransport) Destroy() {
	secret.Wipe(t.password)
	if t.client != nil {
		t.client.CloseIdleConnections()
	}
}

func (t *WebEnrollmentTransport) Submit(ctx context.Context, caConfig, template string, csrDER []byte) (Submission, error) {
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	form := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {string(csr)},
		"CertAttrib":       {"CertificateTemplate:" + template},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
		"ThumbPrint":       {""},
	}
	if strings.TrimSpace(caConfig) != "" {
		form.Set("ConfigString", caConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+"/certfnsh.asp", strings.NewReader(form.Encode()))
	if err != nil {
		return Submission{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return t.roundTrip(req)
}

func (t *WebEnrollmentTransport) RetrievePending(ctx context.Context, _ string, requestID int) (Submission, error) {
	query := url.Values{"ReqID": {strconv.Itoa(requestID)}, "Enc": {"b64"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+"/certnew.cer?"+query.Encode(), nil)
	if err != nil {
		return Submission{}, err
	}
	sub, err := t.roundTrip(req)
	if sub.RequestID == 0 {
		sub.RequestID = requestID
	}
	return sub, err
}

func (t *WebEnrollmentTransport) roundTrip(req *http.Request) (Submission, error) {
	if t.auth != nil {
		// A failure here fails the request. Falling back would downgrade to the
		// scheme the operator deliberately moved away from — and construction
		// already refused the combination that would make a password available
		// to fall back TO.
		if err := t.auth.Authorize(req, ""); err != nil {
			return Submission{}, fmt.Errorf("adcs: %s authentication failed: %w", t.auth.Scheme(), err)
		}
	} else if t.username != "" {
		// net/http's SetBasicAuth takes a password string and builds additional
		// immutable copies. Assemble user:password and base64 in erasable buffers,
		// then cross the forced string boundary exactly once at Header.Set.
		raw := make([]byte, 0, len(t.username)+1+len(t.password))
		raw = append(raw, t.username...)
		raw = append(raw, ':')
		raw = append(raw, t.password...)
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(encoded, raw)
		secret.Wipe(raw)
		req.Header.Set("Authorization", secrettext.Prefixed("Basic ", encoded))
		secret.Wipe(encoded)
	}
	ctx := req.Context()
	if _, ok := ctx.Deadline(); !ok && t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Submission{}, err
		}
		return Submission{}, errors.New("adcs: Web Enrollment request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := secret.ReadBounded(resp.Body, webEnrollmentMaxBody)
	if err != nil {
		return Submission{}, errors.New("adcs: Web Enrollment response read failed")
	}
	defer secret.Wipe(body)
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted {
		return Submission{Disposition: DispUnderSubmission}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Submission{}, fmt.Errorf("adcs: Web Enrollment returned status %d", resp.StatusCode)
	}
	if chain := decodeWebEnrollmentCertificate(body, resp.Header.Get("Content-Type")); len(chain) != 0 {
		return Submission{Disposition: DispIssued, CertChainPEM: chain}, nil
	}
	requestID := parseRequestID(body)
	switch {
	case containsASCIIFold(body, []byte("denied")), containsASCIIFold(body, []byte("rejected")):
		return Submission{Disposition: DispDenied, RequestID: requestID, StatusMessage: "ADCS denied the request"}, nil
	case containsASCIIFold(body, []byte("revoked")):
		return Submission{Disposition: DispRevoked, RequestID: requestID, StatusMessage: "ADCS revoked the request"}, nil
	case requestID != 0:
		// certfnsh.asp returns an HTML link carrying ReqID both for an issued
		// request and for a manager-pending request. RetrievePending resolves it.
		return Submission{Disposition: DispUnderSubmission, RequestID: requestID, StatusMessage: "ADCS request is under submission"}, nil
	default:
		return Submission{Disposition: DispError, StatusMessage: "ADCS returned an unclassified response"}, nil
	}
}

func parseRequestID(body []byte) int {
	match := requestIDPattern.FindSubmatch(body)
	if len(match) != 2 {
		return 0
	}
	id, _ := strconv.Atoi(string(match[1]))
	return id
}

func decodeWebEnrollmentCertificate(body []byte, contentType string) []byte {
	trimmed := bytes.TrimSpace(body)
	if block, _ := pem.Decode(trimmed); block != nil && block.Type == "CERTIFICATE" {
		return append([]byte(nil), trimmed...)
	}
	lowerType := strings.ToLower(contentType)
	if strings.Contains(lowerType, "pkix-cert") || strings.Contains(lowerType, "x-x509") {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trimmed})
	}
	filtered := make([]byte, 0, len(trimmed))
	for _, value := range trimmed {
		if value != '\r' && value != '\n' && value != ' ' && value != '\t' {
			filtered = append(filtered, value)
		}
	}
	defer secret.Wipe(filtered)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(filtered)))
	defer secret.Wipe(decoded)
	n, err := base64.StdEncoding.Decode(decoded, filtered)
	if err == nil && n > 32 && !containsASCIIFold(trimmed, []byte("<html")) {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded[:n]})
	}
	return nil
}

func containsASCIIFold(body, needle []byte) bool {
	for index := 0; index+len(needle) <= len(body); index++ {
		if bytes.EqualFold(body[index:index+len(needle)], needle) {
			return true
		}
	}
	return false
}
