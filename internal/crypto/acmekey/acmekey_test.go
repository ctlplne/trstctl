// SPDX-License-Identifier: MPL-2.0

package acmekey

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	boundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestDriverUsesInjectedHTTPClientAndDestroysAccountKey(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != http.MethodGet || req.URL.String() != "https://acme.test/directory" {
			t.Fatalf("directory request = %s %s", req.Method, req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"newNonce":"https://acme.test/new-nonce",
				"newAccount":"https://acme.test/new-account",
				"newOrder":"https://acme.test/new-order",
				"revokeCert":"https://acme.test/revoke-cert",
				"keyChange":"https://acme.test/key-change"
			}`)),
			Request: req,
		}, nil
	})}
	driver, err := newLocalDriverWithHTTPClient("https://acme.test/directory", nil, client)
	if err != nil {
		t.Fatal(err)
	}
	if driver.client.HTTPClient != client {
		t.Fatal("ACME driver did not retain the policy-controlled HTTP client")
	}
	if _, err := driver.client.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if requests != 1 {
		t.Fatalf("injected transport requests = %d, want 1", requests)
	}

	key := driver.client.Key
	driver.Destroy()
	if driver.client != nil {
		t.Fatal("Destroy retained the ACME client")
	}
	if key == nil {
		t.Fatal("test did not capture generated account key")
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("generated ACME account key has type %T, want ECDSA", key)
	}
	if _, err := privateKey.Sign(rand.Reader, make([]byte, stdcrypto.SHA256.Size()), stdcrypto.SHA256); err == nil {
		t.Fatal("Destroy left the ACME account private key usable for signing")
	}
	// A destroyed driver must fail before any protocol request.
	if _, err := driver.IssueChain(context.Background(), []string{"example.test"}, []byte("csr")); err == nil {
		t.Fatal("destroyed ACME driver accepted an issuance")
	}
}

func TestDriverRejectsCrossOriginURLsDiscoveredFromDirectory(t *testing.T) {
	requests := 0
	underlying := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.String() != "https://acme.test/directory" {
			t.Fatalf("origin-escaped request reached transport: %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"newNonce":"https://steering.test/new-nonce",
				"newAccount":"https://steering.test/new-account",
				"newOrder":"https://steering.test/new-order"
			}`)),
			Request: req,
		}, nil
	})
	bound, err := netsec.BindTransportToOrigin("https://acme.test/directory", underlying)
	if err != nil {
		t.Fatal(err)
	}
	driver, err := newLocalDriverWithHTTPClient("https://acme.test/directory", nil, &http.Client{Transport: bound})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Destroy()
	if _, err := driver.IssueChain(context.Background(), []string{"svc.example.test"}, []byte("unused-csr")); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("ACME directory steering error = %v, want ErrSSRFBlocked", err)
	}
	if requests != 1 {
		t.Fatalf("underlying ACME transport requests = %d, want directory only", requests)
	}
}

type recordingDigestSigner struct {
	public  boundary.PublicKey
	digests [][]byte
	opts    []boundary.SignOptions
}

func (s *recordingDigestSigner) Public() boundary.PublicKey { return s.public }
func (s *recordingDigestSigner) Algorithm() boundary.Algorithm {
	return boundary.ECDSAP256
}
func (s *recordingDigestSigner) SignDigest(digest []byte, opts boundary.SignOptions) ([]byte, error) {
	s.digests = append(s.digests, append([]byte(nil), digest...))
	s.opts = append(s.opts, opts)
	return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil
}

func TestDriverUsesOnlyRemoteDigestSignerForAccountJWS(t *testing.T) {
	publicDER, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     elliptic.P256().Params().Gx,
		Y:     elliptic.P256().Params().Gy,
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := &recordingDigestSigner{public: boundary.PublicKey{Algorithm: boundary.ECDSAP256, DER: publicDER}}
	driver, err := NewDriverWithDigestSigner("https://acme.test/directory", nil, http.DefaultClient, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Destroy()
	if _, local := driver.client.Key.(*ecdsa.PrivateKey); local {
		t.Fatal("remote ACME account adapter retained an in-process ECDSA private key")
	}
	digest := make([]byte, stdcrypto.SHA256.Size())
	digest[0] = 0x42
	signature, err := driver.client.Key.Sign(nil, digest, stdcrypto.SHA256)
	if err != nil {
		t.Fatalf("remote account Sign: %v", err)
	}
	if len(signature) == 0 || len(remote.digests) != 1 || remote.digests[0][0] != 0x42 {
		t.Fatalf("remote account signer calls = %#v signature=%x", remote.digests, signature)
	}
	if remote.opts[0].Hash != boundary.SHA256 {
		t.Fatalf("remote account signer hash = %q, want SHA-256", remote.opts[0].Hash)
	}
	driver.Destroy()
	if len(remote.digests) != 1 {
		t.Fatal("destroying an ACME driver performed a private-key operation")
	}
}
