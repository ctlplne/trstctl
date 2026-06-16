// Package acmtest is a faithful in-process double of the AWS Certificate Manager
// ImportCertificate endpoint, for testing the acm connector on Linux CI without
// real AWS. It is an httptest.Server that speaks the AWS JSON 1.1 protocol and,
// crucially, verifies the request's Signature Version 4 the way the real ACM
// service does: it reconstructs the canonical request from the wire and the
// SignedHeaders the client declared, recomputes the signature under the test
// secret, and rejects a mismatch with SignatureDoesNotMatch. So a canonical/
// payload-hash/scope bug in the connector's signer is caught here, not papered
// over. It records each imported credential by ARN so a test can assert it
// landed. No crypto/* (AN-3): the keyed MAC routes through the crypto boundary,
// the same primitive the connector uses.
package acmtest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

const target = "CertificateManager.ImportCertificate"

// Imported is a credential the fake ACM received.
type Imported struct {
	Certificate []byte
	PrivateKey  []byte
	Chain       []byte
}

// Server is a fake ACM ImportCertificate endpoint.
type Server struct {
	srv             *httptest.Server
	accessKeyID     string
	secretAccessKey string

	mu      sync.Mutex
	imports map[string]Imported // ARN -> credential
	calls   int
	minted  int
}

// New starts a fake ACM that accepts SigV4 requests signed with the given
// credentials.
func New(accessKeyID, secretAccessKey string) *Server {
	s := &Server{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		imports:         map[string]Imported{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the endpoint base URL of the fake service.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake service.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Imported returns the credential imported under arn.
func (s *Server) Imported(arn string) (Imported, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.imports[arn]
	return v, ok
}

// Calls is the number of authenticated ImportCertificate calls served.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		s.fail(w, http.StatusNotFound, "UnknownOperation", "no such resource")
		return
	}
	if r.Header.Get("X-Amz-Target") != target {
		s.fail(w, http.StatusBadRequest, "UnknownOperationException", "unexpected X-Amz-Target")
		return
	}
	body, _ := io.ReadAll(r.Body)

	if !s.verifySigV4(r, body) {
		s.fail(w, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature does not match")
		return
	}

	var in struct {
		Certificate      string
		PrivateKey       string
		CertificateChain string
		CertificateArn   string
	}
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, http.StatusBadRequest, "SerializationException", err.Error())
		return
	}
	cert, err1 := base64.StdEncoding.DecodeString(in.Certificate)
	key, err2 := base64.StdEncoding.DecodeString(in.PrivateKey)
	if err1 != nil || err2 != nil || len(cert) == 0 || len(key) == 0 {
		s.fail(w, http.StatusBadRequest, "ValidationException", "Certificate and PrivateKey are required base64 blobs")
		return
	}
	var chain []byte
	if in.CertificateChain != "" {
		chain, _ = base64.StdEncoding.DecodeString(in.CertificateChain)
	}

	s.mu.Lock()
	s.calls++
	arn := in.CertificateArn
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:acm:us-east-1:000000000000:certificate/%08d", s.minted)
		s.minted++
	}
	s.imports[arn] = Imported{Certificate: cert, PrivateKey: key, Chain: chain}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"CertificateArn": arn})
}

// verifySigV4 reconstructs the canonical request from the received request and
// the client's declared SignedHeaders, recomputes the signature under the test
// secret, and compares it to the one presented — exactly the server side of
// SigV4. It returns false on any structural problem or mismatch.
func (s *Server) verifySigV4(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	const algo = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, algo) {
		return false
	}
	cred, signedHeaders, sig := "", "", ""
	for _, f := range strings.Split(auth[len(algo):], ",") {
		f = strings.TrimSpace(f)
		switch {
		case strings.HasPrefix(f, "Credential="):
			cred = strings.TrimPrefix(f, "Credential=")
		case strings.HasPrefix(f, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(f, "SignedHeaders=")
		case strings.HasPrefix(f, "Signature="):
			sig = strings.TrimPrefix(f, "Signature=")
		}
	}
	scope := strings.SplitN(cred, "/", 2)
	if len(scope) != 2 || signedHeaders == "" || sig == "" {
		return false
	}
	accessKeyID := scope[0]
	credScope := scope[1] // date/region/service/aws4_request
	cs := strings.Split(credScope, "/")
	if accessKeyID != s.accessKeyID || len(cs) != 4 || cs[3] != "aws4_request" {
		return false
	}
	date, region, svc := cs[0], cs[1], cs[2]

	var canonHeaders strings.Builder
	for _, h := range strings.Split(signedHeaders, ";") {
		v := strings.TrimSpace(r.Header.Get(h))
		if h == "host" {
			v = r.Host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	canonicalRequest := strings.Join([]string{
		r.Method,
		r.URL.EscapedPath(),
		"",
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		r.Header.Get("X-Amz-Date"),
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := crypto.HMACSHA256([]byte("AWS4"+s.secretAccessKey), []byte(date))
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	kService := crypto.HMACSHA256(kRegion, []byte(svc))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	want := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	return want == sig
}

func (s *Server) fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": msg})
}
