// SPDX-License-Identifier: BUSL-1.1

package awspca

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestHTTPAPISendsAWSJSONWithSigV4(t *testing.T) {
	var operations []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		operations = append(operations, req.Header.Get("X-Amz-Target"))
		if got := req.Header.Get("Authorization"); !strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(got, "/us-east-1/acm-pca/aws4_request") {
			t.Fatalf("Authorization = %q", got)
		}
		if req.Header.Get("X-Amz-Date") != "20240102T030405Z" {
			t.Fatalf("X-Amz-Date = %q", req.Header.Get("X-Amz-Date"))
		}
		var body string
		switch req.Header.Get("X-Amz-Target") {
		case "ACMPrivateCA.IssueCertificate":
			body = `{"CertificateArn":"arn:aws:acm-pca:us-east-1:123:certificate-authority/ca/certificate/cert"}`
		case "ACMPrivateCA.GetCertificate":
			body = `{"Certificate":"leaf","CertificateChain":"chain"}`
		default:
			t.Fatalf("unexpected target %q", req.Header.Get("X-Amz-Target"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	api, err := NewHTTPAPI(HTTPConfig{
		Endpoint: "https://acm-pca.us-east-1.amazonaws.com", Region: "us-east-1", AccessKeyID: "AKID",
		SecretAccessKey: []byte("SECRET"), SessionToken: []byte("SESSION"), HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	api.now = func() time.Time { return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC) }
	issued, err := api.IssueCertificate(context.Background(), IssueCertificateInput{
		CertificateAuthorityArn: "arn:ca", Csr: []byte("csr"), SigningAlgorithm: "SHA256WITHRSA",
		Validity: Validity{Value: 30, Type: "DAYS"}, IdempotencyToken: "stable-token",
	})
	if err != nil || issued.CertificateArn == "" {
		t.Fatalf("IssueCertificate = %+v, %v", issued, err)
	}
	got, err := api.GetCertificate(context.Background(), GetCertificateInput{CertificateAuthorityArn: "arn:ca", CertificateArn: issued.CertificateArn})
	if err != nil || got.Certificate != "leaf" || got.CertificateChain != "chain" {
		t.Fatalf("GetCertificate = %+v, %v", got, err)
	}
	if len(operations) != 2 {
		t.Fatalf("operations = %v", operations)
	}
	api.Destroy()
	for _, material := range [][]byte{api.secretKey, api.sessionToken} {
		for _, value := range material {
			if value != 0 {
				t.Fatal("Destroy left AWS credential bytes in memory")
			}
		}
	}
}

func TestHTTPAPIMapsRequestInProgress(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"__type":"RequestInProgressException"}`))}, nil
	})}
	api, err := NewHTTPAPI(HTTPConfig{Endpoint: "https://pca.example", Region: "us-east-1", AccessKeyID: "AK", SecretAccessKey: []byte("SK"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer api.Destroy()
	if _, err := api.GetCertificate(context.Background(), GetCertificateInput{}); err != ErrRequestInProgress {
		t.Fatalf("error = %v, want ErrRequestInProgress", err)
	}
}
