package k8s_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/k8s"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHTTPSignerRejectsMalformedSuccessResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "malformed-json", body: "{", want: "decode signer response"},
		{name: "empty-json", body: `{}`, want: "missing certificate"},
		{name: "empty-certificate", body: `{"certificate":"  \n"}`, want: "missing certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := k8s.NewHTTPSigner("https://trstctl.example/sign", httpClientReturning(http.StatusOK, tc.body))
			_, err := signer.Sign(context.Background(), []byte("csr-der"))
			if err == nil {
				t.Fatal("Sign succeeded on a malformed successful response")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestHTTPSignerPostsServedIssuanceCSRAndAcceptsCertificatePEM(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer trst-token" {
			t.Fatalf("Authorization = %q, want bearer token header", got)
		}
		if got := req.Header.Get("Idempotency-Key"); !strings.HasPrefix(got, "k8s-cert-manager-") {
			t.Fatalf("Idempotency-Key = %q, want stable cert-manager key", got)
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body["csr"] == "" {
			t.Fatal("request did not include legacy base64 csr")
		}
		if !strings.Contains(body["csr_pem"], "BEGIN CERTIFICATE REQUEST") {
			t.Fatalf("request csr_pem = %q, want a PEM CSR for served issuance routes", body["csr_pem"])
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(`{"certificate_pem":"-----BEGIN CERTIFICATE-----\nserved\n-----END CERTIFICATE-----\n"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	signer := k8s.NewHTTPSigner("https://trstctl.example/api/v1/ca/authorities/root/issue", httpClient, k8s.WithBearerToken([]byte("trst-token")))
	cert, err := signer.Sign(context.Background(), []byte("csr-der"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.Contains(string(cert), "BEGIN CERTIFICATE") {
		t.Fatalf("certificate = %q, want served certificate_pem response", cert)
	}
}

func TestHTTPSignerRejectsReadErrors(t *testing.T) {
	signer := k8s.NewHTTPSigner("https://trstctl.example/sign", &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       readErrorCloser{err: errors.New("body truncated")},
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	})
	_, err := signer.Sign(context.Background(), []byte("csr-der"))
	if err == nil {
		t.Fatal("Sign succeeded when reading the response body failed")
	}
	if !strings.Contains(err.Error(), "read signer response") || !strings.Contains(err.Error(), "body truncated") {
		t.Fatalf("error %q did not surface the read failure", err)
	}
}

func TestHTTPSignerNon2xxIncludesBoundedResponseContext(t *testing.T) {
	body := strings.Repeat("x", 600) + "tail"
	signer := k8s.NewHTTPSigner("https://trstctl.example/sign", httpClientReturning(http.StatusBadGateway, body))
	_, err := signer.Sign(context.Background(), []byte("csr-der"))
	if err == nil {
		t.Fatal("Sign succeeded on a non-2xx signer response")
	}
	if !strings.Contains(err.Error(), "status 502") || !strings.Contains(err.Error(), "(truncated)") {
		t.Fatalf("error %q should include status and bounded response context", err)
	}
	if strings.Contains(err.Error(), "tail") {
		t.Fatalf("error %q included unbounded response tail", err)
	}
}

func httpClientReturning(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
}

type readErrorCloser struct {
	err error
}

func (r readErrorCloser) Read([]byte) (int, error) { return 0, r.err }
func (r readErrorCloser) Close() error             { return nil }
