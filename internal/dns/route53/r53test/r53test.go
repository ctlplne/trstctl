// Package r53test is a faithful in-process double of the AWS Route 53
// ChangeResourceRecordSets API, for testing the route53 DNS-01 provider on CI
// without real AWS. Like acmtest, it verifies the request's Signature Version 4 the
// way the real service does — reconstructing the canonical request from the wire and
// the SignedHeaders the client declared, recomputing the signature under the test
// secret, and rejecting a mismatch with SignatureDoesNotMatch — so a canonical /
// payload-hash / scope bug in the provider's signer is caught here, not papered
// over. It applies UPSERT/DELETE changes to an in-memory zone and serves the
// published TXT records back (satisfying acme.Resolver), so the DNS-01 conformance
// harness can validate end-to-end. No crypto/* (AN-3): the keyed MAC routes through
// the crypto boundary, the same primitive the provider uses.
package r53test

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// Server is a fake Route 53 ChangeResourceRecordSets endpoint.
type Server struct {
	srv             *httptest.Server
	accessKeyID     string
	secretAccessKey string

	mu      sync.Mutex
	records map[string]map[string]bool // record name -> set of unquoted TXT values
	calls   int
}

// New starts a fake Route 53 that accepts SigV4 requests signed with the given
// credentials.
func New(accessKeyID, secretAccessKey string) *Server {
	s := &Server{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		records:         map[string]map[string]bool{},
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

// Calls is the number of authenticated change requests served.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Records returns the TXT values currently published for name (unquoted).
func (s *Server) Records(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for v := range s.records[canonName(name)] {
		out = append(out, v)
	}
	return out
}

// LookupTXT satisfies acme.Resolver, returning the published values for name so the
// DNS-01 validator can read back what the provider wrote.
func (s *Server) LookupTXT(_ context.Context, name string) ([]string, error) {
	return s.Records(name), nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/rrset") {
		s.fail(w, http.StatusNotFound, "NoSuchHostedZone", "no such resource")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	if !s.verifySigV4(r, body) {
		s.fail(w, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature does not match")
		return
	}

	var req changeRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "InvalidChangeBatch", "malformed change batch")
		return
	}

	s.mu.Lock()
	s.calls++
	notFound := false
	for _, c := range req.ChangeBatch.Changes {
		rrs := c.ResourceRecordSet
		if !strings.EqualFold(rrs.Type, "TXT") {
			continue
		}
		name := canonName(rrs.Name)
		switch strings.ToUpper(c.Action) {
		case "UPSERT", "CREATE":
			if s.records[name] == nil {
				s.records[name] = map[string]bool{}
			}
			for _, rr := range rrs.ResourceRecords {
				s.records[name][unquote(rr.Value)] = true
			}
		case "DELETE":
			vs := s.records[name]
			if vs == nil {
				notFound = true
				continue
			}
			for _, rr := range rrs.ResourceRecords {
				v := unquote(rr.Value)
				if !vs[v] {
					notFound = true
				}
				delete(vs, v)
			}
			if len(vs) == 0 {
				delete(s.records, name)
			}
		}
	}
	s.mu.Unlock()

	if notFound {
		// Real Route 53 rejects deletion of an absent record with InvalidChangeBatch;
		// the provider treats this as a no-op so cleanup stays idempotent.
		s.fail(w, http.StatusBadRequest, "InvalidChangeBatch",
			"Tried to delete resource record set but it was not found")
		return
	}

	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<?xml version="1.0"?>`+
		`<ChangeResourceRecordSetsResponse><ChangeInfo>`+
		`<Id>/change/C0000000000000000000000</Id><Status>INSYNC</Status>`+
		`</ChangeInfo></ChangeResourceRecordSetsResponse>`)
}

// verifySigV4 reconstructs the canonical request from the received request and the
// client's declared SignedHeaders, recomputes the signature under the test secret,
// and compares it to the one presented — exactly the server side of SigV4.
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
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<?xml version="1.0"?><ErrorResponse><Error><Code>`+
		code+`</Code><Message>`+msg+`</Message></Error></ErrorResponse>`)
}

// canonName normalizes a record name for comparison: Route 53 may carry a trailing
// dot, but the solver and validator use the un-rooted form.
func canonName(name string) string { return strings.TrimSuffix(name, ".") }

// unquote strips the surrounding double quotes Route 53 stores TXT values under, so
// LookupTXT returns the raw authorization value the validator expects.
func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

// changeRequest mirrors the subset of the Route 53 ChangeResourceRecordSets request
// this double needs to parse.
type changeRequest struct {
	XMLName     xml.Name    `xml:"ChangeResourceRecordSetsRequest"`
	ChangeBatch changeBatch `xml:"ChangeBatch"`
}

type changeBatch struct {
	Changes []change `xml:"Changes>Change"`
}

type change struct {
	Action            string            `xml:"Action"`
	ResourceRecordSet resourceRecordSet `xml:"ResourceRecordSet"`
}

type resourceRecordSet struct {
	Name            string           `xml:"Name"`
	Type            string           `xml:"Type"`
	ResourceRecords []resourceRecord `xml:"ResourceRecords>ResourceRecord"`
}

type resourceRecord struct {
	Value string `xml:"Value"`
}
