// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"io"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/trust"
)

// CertificateStatusClient bounds the MongoDB driver's certificate-status request
// and keeps its sockets inside the admitted database egress policy.
func (dialer DatabaseDialer) CertificateStatusClient() *http.Client {
	transport := trust.HardenTransport(&http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 * 1024})
	return &http.Client{Transport: boundedCertificateStatus{transport}, Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type boundedCertificateStatus struct{ next http.RoundTripper }

func (b boundedCertificateStatus) RoundTrip(req *http.Request) (*http.Response, error) {
	const maxSize = 64 * 1024
	if req.URL.User != nil || req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, dbdsn.ErrTrust
	}
	resp, err := b.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > maxSize {
		_ = resp.Body.Close()
		return nil, dbdsn.ErrTrust
	}
	resp.Body = limitedStatusBody{Reader: io.LimitReader(resp.Body, maxSize), Closer: resp.Body}
	return resp, nil
}

type limitedStatusBody struct {
	io.Reader
	io.Closer
}
