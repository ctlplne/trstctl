// SPDX-License-Identifier: BUSL-1.1

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

const (
	target        = "CertificateManager.ImportCertificate"
	previewTarget = "CertificateManager.ListCertificates"
	tagsTarget    = "CertificateManager.ListTagsForCertificate"
	getTarget     = "CertificateManager.GetCertificate"
)

// Imported is a credential the fake ACM received.
type Imported struct {
	Certificate []byte
	PrivateKey  []byte
	Chain       []byte
	// Tags are the tags the first import applied (A166-L2); ACM refuses tags
	// on a re-import.
	Tags map[string]string
}

// Server is a fake ACM ImportCertificate endpoint.
type Server struct {
	srv             *httptest.Server
	accessKeyID     string
	secretAccessKey string

	mu      sync.Mutex
	imports map[string]Imported // ARN -> credential
	order   []string            // ARNs in the order they were minted
	calls   int
	preview int
	minted  int
}

// ARNs returns every certificate ARN in the account, in the order minted.
func (s *Server) ARNs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
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

// PreviewCalls is the number of authenticated read-only list operations.
func (s *Server) PreviewCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preview
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		s.fail(w, http.StatusNotFound, "UnknownOperation", "no such resource")
		return
	}
	operation := r.Header.Get("X-Amz-Target")
	if operation != target && operation != previewTarget && operation != tagsTarget && operation != getTarget {
		s.fail(w, http.StatusBadRequest, "UnknownOperationException", "unexpected X-Amz-Target")
		return
	}
	body, _ := io.ReadAll(r.Body)

	if !verifySigV4(r, body, s.accessKeyID, s.secretAccessKey, "acm") {
		s.fail(w, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature does not match")
		return
	}
	switch operation {
	case previewTarget:
		s.listCertificates(w, body)
		return
	case tagsTarget, getTarget:
		s.readCertificate(w, operation, body)
		return
	}

	var in struct {
		CertificateValue      string `json:"Certificate"`
		PrivateKeyValue       string `json:"PrivateKey"`
		CertificateChainValue string `json:"CertificateChain"`
		CertificateArn        string `json:"CertificateArn"`
		Tags                  []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		s.fail(w, http.StatusBadRequest, "SerializationException", err.Error())
		return
	}
	if in.CertificateArn != "" && len(in.Tags) > 0 {
		s.fail(w, http.StatusBadRequest, "ValidationException", "tags cannot be applied when re-importing a certificate")
		return
	}
	cert, err1 := base64.StdEncoding.DecodeString(in.CertificateValue)
	key, err2 := base64.StdEncoding.DecodeString(in.PrivateKeyValue)
	if err1 != nil || err2 != nil || len(cert) == 0 || len(key) == 0 {
		s.fail(w, http.StatusBadRequest, "ValidationException", "Certificate and PrivateKey are required base64 blobs")
		return
	}
	var chain []byte
	if in.CertificateChainValue != "" {
		chain, _ = base64.StdEncoding.DecodeString(in.CertificateChainValue)
	}

	s.mu.Lock()
	s.calls++
	arn := in.CertificateArn
	tags := map[string]string{}
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:acm:us-east-1:000000000000:certificate/%08d", s.minted)
		s.minted++
		s.order = append(s.order, arn)
		for _, tag := range in.Tags {
			tags[tag.Key] = tag.Value
		}
	} else {
		if _, known := s.imports[arn]; !known {
			s.order = append(s.order, arn)
		}
		tags = s.imports[arn].Tags
	}
	s.imports[arn] = Imported{Certificate: cert, PrivateKey: key, Chain: chain, Tags: tags}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"CertificateArn": arn})
}

// listCertificates answers ListCertificates two ARNs a page, so a client must
// follow NextToken (the real page size is larger; the protocol is the same).
func (s *Server) listCertificates(w http.ResponseWriter, body []byte) {
	var in struct {
		NextToken string `json:"NextToken"`
	}
	_ = json.Unmarshal(body, &in)
	s.mu.Lock()
	s.preview++
	start := 0
	if in.NextToken != "" {
		_, _ = fmt.Sscanf(in.NextToken, "page-%d", &start)
	}
	end := min(start+2, len(s.order))
	if start > end {
		start = end
	}
	items := make([]map[string]string, 0, end-start)
	for _, arn := range s.order[start:end] {
		items = append(items, map[string]string{"CertificateArn": arn})
	}
	out := map[string]any{"CertificateSummaryList": items}
	if end < len(s.order) {
		out["NextToken"] = fmt.Sprintf("page-%d", end)
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

// readCertificate answers ListTagsForCertificate and GetCertificate.
func (s *Server) readCertificate(w http.ResponseWriter, operation string, body []byte) {
	var in struct {
		CertificateArn string `json:"CertificateArn"`
	}
	_ = json.Unmarshal(body, &in)
	s.mu.Lock()
	imported, ok := s.imports[in.CertificateArn]
	s.mu.Unlock()
	if !ok {
		s.fail(w, http.StatusBadRequest, "ResourceNotFoundException", "no certificate with that ARN")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if operation == getTarget {
		_ = json.NewEncoder(w).Encode(map[string]string{"Certificate": string(imported.Certificate), "CertificateChain": string(imported.Chain)})
		return
	}
	tags := []map[string]string{}
	for k, v := range imported.Tags {
		tags = append(tags, map[string]string{"Key": k, "Value": v})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"Tags": tags})
}

// SetTag changes one tag on a certificate, as anyone with tag rights in the
// account could (a test of a rollback that must not trust a tag alone).
func (s *Server) SetTag(arn, key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	imported := s.imports[arn]
	if imported.Tags == nil {
		imported.Tags = map[string]string{}
	}
	imported.Tags[key] = value
	s.imports[arn] = imported
}

// verifySigV4 reconstructs the canonical request from the received request and
// the client's declared SignedHeaders, recomputes the signature under the test
// secret, and compares it to the one presented — exactly the server side of
// SigV4, for the named service. It returns false on any structural problem or
// mismatch.
func verifySigV4(r *http.Request, body []byte, wantAccessKeyID, secretAccessKey, wantService string) bool {
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
	if accessKeyID != wantAccessKeyID || len(cs) != 4 || cs[3] != "aws4_request" || cs[2] != wantService {
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

	kDate := crypto.HMACSHA256([]byte("AWS4"+secretAccessKey), []byte(date))
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
