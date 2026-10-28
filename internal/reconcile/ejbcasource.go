// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
)

// EJBCA authority source (A218).
//
// The issuance ledger of an EJBCA CA, read with the REST API's v2 certificate
// search (EJBCA Community or Enterprise; "REST Certificate Management V2" must
// be enabled) and a client certificate the operator places in an EJBCA role
// that may view certificates. Identity and expiry come from each certificate's
// own DER, never from EJBCA's strings; a certificate is revoked when EJBCA
// reports it revoked or on hold.
//
// The search is frozen at the observation time: certificates issued before it
// and expiring after it, active or revoked. The count is read first and the
// pages must add up to it; a ledger that moved during the read fails the
// observation and the round retries, rather than reporting a partial ledger
// as drift.

const (
	ejbcaSourceTimeout     = 30 * time.Second
	ejbcaSourceMaxBody     = 32 << 20
	ejbcaDefaultMaxCerts   = 20000
	ejbcaDefaultPageSize   = 500
	ejbcaMaxPageSize       = 1000
	ejbcaStatusRevoked     = 40
	ejbcaDefaultRESTPrefix = "/ejbca/ejbca-rest-api"
)

// EJBCASourceConfig is the core-owned shape operator config maps onto.
type EJBCASourceConfig struct {
	AuthorityID string
	// Address is the EJBCA base URL (https://ejbca.example.org:8443); a URL
	// with a path is taken as the REST API base itself.
	Address        string
	ServerName     string
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
	// IssuerCertificatesFile names the CAs this authority speaks for.
	IssuerCertificatesFile string
	// CANames narrows the search to these EJBCA CA names (optional).
	CANames         []string
	MaxCertificates int
	PageSize        int
	AllowTLS12      bool
	// AllowLoopback permits a loopback address (TLS is still required);
	// PrivateEndpointCIDRs widens the SSRF-safe dialer to operator ranges.
	AllowLoopback        bool
	PrivateEndpointCIDRs []netip.Prefix
	// HTTPClient overrides the client entirely (tests).
	HTTPClient *http.Client
}

type ejbcaSource struct {
	cfg  EJBCASourceConfig
	base string
	now  func() time.Time
}

func newEJBCASource(cfg EJBCASourceConfig) (*ejbcaSource, error) {
	cfg.AuthorityID = strings.TrimSpace(cfg.AuthorityID)
	if cfg.AuthorityID == "" {
		return nil, fmt.Errorf("%w: ejbca authority id required", errCASourceConfig)
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.Address), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%w: ejbca address must be an https URL", errCASourceConfig)
	}
	if u.Path == "" {
		u.Path = ejbcaDefaultRESTPrefix
	}
	if cfg.HTTPClient == nil && (strings.TrimSpace(cfg.CAFile) == "" || strings.TrimSpace(cfg.ClientCertFile) == "" || strings.TrimSpace(cfg.ClientKeyFile) == "") {
		return nil, fmt.Errorf("%w: ejbca needs ca_file, client_cert_file and client_key_file", errCASourceConfig)
	}
	if strings.TrimSpace(cfg.IssuerCertificatesFile) == "" {
		return nil, fmt.Errorf("%w: ejbca needs issuer_certificates_file", errCASourceConfig)
	}
	if cfg.MaxCertificates <= 0 {
		cfg.MaxCertificates = ejbcaDefaultMaxCerts
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = ejbcaDefaultPageSize
	}
	if cfg.PageSize > ejbcaMaxPageSize {
		return nil, fmt.Errorf("%w: ejbca page_size is at most %d", errCASourceConfig, ejbcaMaxPageSize)
	}
	return &ejbcaSource{cfg: cfg, base: u.String(), now: time.Now}, nil
}

// ejbcaCriterion is one v2 search criterion; criteria of one property are
// OR'ed by EJBCA, different properties AND'ed.
type ejbcaCriterion struct {
	Property  string `json:"property"`
	Value     string `json:"value"`
	Operation string `json:"operation"`
}

type ejbcaSearchRequest struct {
	Pagination struct {
		PageSize    int `json:"page_size"`
		CurrentPage int `json:"current_page"`
	} `json:"pagination"`
	Sort *struct {
		Property  string `json:"property"`
		Operation string `json:"operation"`
	} `json:"sort,omitempty"`
	Criteria []ejbcaCriterion `json:"criteria"`
}

type ejbcaSearchResponse struct {
	Certificates []struct {
		Fingerprint      string `json:"fingerprint"`
		SerialNumber     string `json:"serialNumber"`
		Status           int    `json:"status"`
		RevocationReason int    `json:"revocationReason"`
		Base64Cert       string `json:"base64Cert"`
	} `json:"certificates"`
	PaginationSummary struct {
		TotalCerts int `json:"total_certs"`
	} `json:"pagination_summary"`
	ErrorMessage string `json:"error_message"`
}

// SelfSnapshot implements reducers.SelfInventorySource.
func (e *ejbcaSource) SelfSnapshot(ctx context.Context, _ string) (reducers.SelfSnapshot, error) {
	jurisdiction, err := loadCAJurisdiction(e.cfg.IssuerCertificatesFile)
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	sb := reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(e.cfg.AuthorityID), nil)
	if _, err := sb.List(ctx, e.cfg.AuthorityID+"/certificates"); err != nil {
		return reducers.SelfSnapshot{}, err
	}
	client, err := e.client()
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	now := e.now().UTC().Truncate(time.Second)
	criteria := e.criteria(now)
	counted, err := e.search(ctx, client, criteria, -1)
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	total := counted.PaginationSummary.TotalCerts
	if total > e.cfg.MaxCertificates {
		return reducers.SelfSnapshot{}, fmt.Errorf("xrec ejbca source %s: %d certificates exceed max_objects %d; the observation would be partial",
			e.cfg.AuthorityID, total, e.cfg.MaxCertificates)
	}
	snap := reducers.SelfSnapshot{Watermark: storeWatermark("ejbca:"+e.cfg.AuthorityID, now)}
	seen := make(map[string]bool, total)
	maxPages := total/e.cfg.PageSize + 2
	for page := 1; ; page++ {
		if page > maxPages {
			return reducers.SelfSnapshot{}, fmt.Errorf("xrec ejbca source %s: the search did not end after %d pages", e.cfg.AuthorityID, maxPages)
		}
		resp, err := e.search(ctx, client, criteria, page)
		if err != nil {
			return reducers.SelfSnapshot{}, err
		}
		for _, item := range resp.Certificates {
			der, err := ejbcaCertificateDER(item.Base64Cert)
			if err != nil {
				return reducers.SelfSnapshot{}, fmt.Errorf("xrec ejbca source %s: certificate %s is not base64 DER", e.cfg.AuthorityID, item.SerialNumber)
			}
			facts, err := crypto.CertificateFactsFromDER(der)
			if err != nil {
				return reducers.SelfSnapshot{}, fmt.Errorf("xrec ejbca source %s: certificate %s: %w", e.cfg.AuthorityID, item.SerialNumber, err)
			}
			if !sameSerialHex(item.SerialNumber, facts.SerialHex) {
				return reducers.SelfSnapshot{}, fmt.Errorf("xrec ejbca source %s: EJBCA lists serial %s for a certificate whose serial is %s",
					e.cfg.AuthorityID, item.SerialNumber, facts.SerialHex)
			}
			key := string(facts.IssuerNameDER) + "\x00" + facts.SerialHex
			if seen[key] {
				continue
			}
			seen[key] = true
			if _, ok := jurisdiction[string(facts.IssuerNameDER)]; !ok || facts.NotAfter.Before(now) {
				continue
			}
			status := canonStatusActive
			if item.Status == ejbcaStatusRevoked || item.RevocationReason >= 0 {
				status = canonStatusRevoked
			}
			snap.Certificates = append(snap.Certificates, reducers.SelfCertificate{
				IssuerNameDER: facts.IssuerNameDER,
				SerialHex:     facts.SerialHex,
				Status:        status,
				NativeID:      item.Fingerprint,
			})
		}
		if len(resp.Certificates) < e.cfg.PageSize {
			break
		}
	}
	if len(seen) != total {
		return reducers.SelfSnapshot{}, fmt.Errorf("xrec ejbca source %s: the ledger changed during the observation (%d of %d certificates read); the round retries",
			e.cfg.AuthorityID, len(seen), total)
	}
	return snap, nil
}

// criteria freezes the search at now: active or revoked certificates issued
// before it and expiring after it, of the named CAs when CANames is set.
func (e *ejbcaSource) criteria(now time.Time) []ejbcaCriterion {
	at := now.Format(time.RFC3339)
	criteria := []ejbcaCriterion{
		{Property: "STATUS", Value: "CERT_ACTIVE", Operation: "EQUAL"},
		{Property: "STATUS", Value: "CERT_REVOKED", Operation: "EQUAL"},
		{Property: "ISSUED_DATE", Value: at, Operation: "BEFORE"},
		{Property: "EXPIRE_DATE", Value: at, Operation: "AFTER"},
	}
	for _, name := range e.cfg.CANames {
		if name = strings.TrimSpace(name); name != "" {
			criteria = append(criteria, ejbcaCriterion{Property: "CA", Value: name, Operation: "EQUAL"})
		}
	}
	return criteria
}

// search runs one v2 certificate search; page -1 asks for the count only.
func (e *ejbcaSource) search(ctx context.Context, client *http.Client, criteria []ejbcaCriterion, page int) (ejbcaSearchResponse, error) {
	var req ejbcaSearchRequest
	req.Pagination.PageSize, req.Pagination.CurrentPage = e.cfg.PageSize, page
	if page > 0 {
		// Expiry does not change when a certificate is revoked, so the order
		// holds while the pages are read.
		req.Sort = &struct {
			Property  string `json:"property"`
			Operation string `json:"operation"`
		}{Property: "EXPIRE_DATE", Operation: "ASC"}
	}
	req.Criteria = criteria
	body, err := json.Marshal(req)
	if err != nil {
		return ejbcaSearchResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/v2/certificate/search", bytes.NewReader(body))
	if err != nil {
		return ejbcaSearchResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return ejbcaSearchResponse{}, fmt.Errorf("xrec ejbca source %s: search: %w", e.cfg.AuthorityID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, ejbcaSourceMaxBody+1))
	if err != nil {
		return ejbcaSearchResponse{}, fmt.Errorf("xrec ejbca source %s: read search response: %w", e.cfg.AuthorityID, err)
	}
	if len(raw) > ejbcaSourceMaxBody {
		return ejbcaSearchResponse{}, fmt.Errorf("xrec ejbca source %s: search response exceeds %d bytes", e.cfg.AuthorityID, ejbcaSourceMaxBody)
	}
	var out ejbcaSearchResponse
	decodeErr := json.Unmarshal(raw, &out)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ejbcaSearchResponse{}, fmt.Errorf("xrec ejbca source %s: EJBCA answered 404 to the v2 certificate search; enable the REST Certificate Management V2 protocol",
			e.cfg.AuthorityID)
	case resp.StatusCode != http.StatusOK:
		return ejbcaSearchResponse{}, fmt.Errorf("xrec ejbca source %s: search answered HTTP %d: %s", e.cfg.AuthorityID, resp.StatusCode, boundedEJBCAMessage(out.ErrorMessage))
	case decodeErr != nil:
		return ejbcaSearchResponse{}, fmt.Errorf("xrec ejbca source %s: decode search response: %w", e.cfg.AuthorityID, decodeErr)
	}
	return out, nil
}

// client builds the mutual-TLS client at each observation, so a rotated client
// certificate applies to the next round. Requests are bound to the configured
// origin and dialed through the SSRF-safe dialer.
func (e *ejbcaSource) client() (*http.Client, error) {
	if e.cfg.HTTPClient != nil {
		return e.cfg.HTTPClient, nil
	}
	var opts []mtls.RawClientOption
	if e.cfg.AllowTLS12 {
		opts = append(opts, mtls.AllowTLS12())
	}
	transport, err := mtls.MutualTLSHTTPTransportFromFiles(e.cfg.ClientCertFile, e.cfg.ClientKeyFile, e.cfg.CAFile, strings.TrimSpace(e.cfg.ServerName), opts...)
	if err != nil {
		return nil, fmt.Errorf("xrec ejbca source %s: %w", e.cfg.AuthorityID, err)
	}
	safeOpts := netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), e.cfg.PrivateEndpointCIDRs...)}
	if e.cfg.AllowLoopback {
		safeOpts.AllowPrivateCIDRs = append(safeOpts.AllowPrivateCIDRs, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
	}
	client := netsec.SafeClientWithOptions(ejbcaSourceTimeout, safeOpts)
	safe, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("xrec ejbca source %s: the SSRF-safe client has no reviewed transport", e.cfg.AuthorityID)
	}
	transport.DialContext = safe.DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = ejbcaSourceTimeout
	transport.DisableKeepAlives = safe.DisableKeepAlives
	trust.HardenTransport(transport)
	client.Transport, err = netsec.BindTransportToOrigin(e.base, transport)
	if err != nil {
		return nil, fmt.Errorf("xrec ejbca source %s: %w", e.cfg.AuthorityID, err)
	}
	return client, nil
}

// ejbcaCertificateDER decodes a search result's base64Cert. EJBCA 9.6 puts the
// base64 of the certificate's base64 text there (two layers); a value that
// decodes straight to DER (a SEQUENCE tag) is taken as it is.
func ejbcaCertificateDER(field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(field))
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 && raw[0] == 0x30 {
		return raw, nil
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
}

// sameSerialHex compares EJBCA's serial (hex, any case, maybe zero-padded)
// with the serial read from the certificate.
func sameSerialHex(listed, parsed string) bool {
	listed = strings.TrimLeft(strings.ToLower(strings.TrimSpace(listed)), "0")
	parsed = strings.TrimLeft(strings.ToLower(parsed), "0")
	return listed == parsed
}

func boundedEJBCAMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	if msg == "" {
		return "no error message"
	}
	return msg
}
