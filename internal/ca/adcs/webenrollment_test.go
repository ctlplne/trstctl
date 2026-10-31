// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestWebEnrollmentTransportSubmitsAndRetrieves(t *testing.T) {
	issued := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("certificate-der")})
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("Authorization") == "" {
			t.Fatal("missing HTTP authorization")
		}
		if req.Method == http.MethodPost {
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if req.Form.Get("Mode") != "newreq" || req.Form.Get("CertAttrib") != "CertificateTemplate:WebServer" || req.Form.Get("ConfigString") != `HOST\CA` {
				t.Fatalf("form = %v", req.Form)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(`<a href="certnew.cer?ReqID=42&Enc=b64">certificate</a>`))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/pem-certificate-chain"}}, Body: io.NopCloser(strings.NewReader(string(issued)))}, nil
	})}
	transport, err := NewWebEnrollmentTransport(WebEnrollmentConfig{BaseURL: "https://adcs.example/certsrv", Username: "operator", Password: []byte("password"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := transport.Submit(context.Background(), `HOST\CA`, "WebServer", []byte("csr-der"))
	if err != nil || sub.Disposition != DispUnderSubmission || sub.RequestID != 42 {
		t.Fatalf("Submit = %+v, %v", sub, err)
	}
	sub, err = transport.RetrievePending(context.Background(), `HOST\CA`, sub.RequestID)
	if err != nil || sub.Disposition != DispIssued || !bytes.Equal(bytes.TrimSpace(sub.CertChainPEM), bytes.TrimSpace(issued)) {
		t.Fatalf("RetrievePending = %+v, %v", sub, err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
	transport.Destroy()
	for _, value := range transport.password {
		if value != 0 {
			t.Fatal("Destroy left IIS password bytes in memory")
		}
	}
}

// A161: a denial page keeps only an allowlisted refusal code; anything else on
// the page (an IIS echo of a submitted credential, for example) never crosses.
func TestWebEnrollmentDenialCarriesOnlyAnAllowlistedCode(t *testing.T) {
	for name, tc := range map[string]struct {
		page, want string
	}{
		"template permissions": {"<P>Denied by Policy Module 0x80094012, The permissions on the certificate template do not allow the current user to enroll.</P>", "ADCS denied the request (0x80094012)"},
		"echoed secret":        {"<P>Your request was denied. Authorization: Basic c3ZjOmh1bnRlcjI=</P>", "ADCS denied the request"},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(tc.page))}, nil
		})}
		transport, err := NewWebEnrollmentTransport(WebEnrollmentConfig{BaseURL: "https://adcs.example/certsrv", HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		sub, err := transport.Submit(context.Background(), `HOST\CA`, "WebServer", []byte("csr-der"))
		if err != nil || sub.Disposition != DispDenied || sub.StatusMessage != tc.want {
			t.Errorf("%s: Submit = %+v, %v; want message %q", name, sub, err, tc.want)
		}
	}
}
