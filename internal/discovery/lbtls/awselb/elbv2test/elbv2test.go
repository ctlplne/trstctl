// SPDX-License-Identifier: BUSL-1.1

// Package elbv2test is an in-process Elastic Load Balancing v2 stand-in for
// the read-only Describe operations the listener TLS policy reader calls (X4).
// LocalStack's community image has no ELBv2. It verifies every request's
// Signature Version 4 under the configured key, answers in ELBv2's XML shapes
// from seeded load balancers, listeners and security policies with one item a
// page so paging is exercised, and counts any other action so a test can prove
// nothing was changed.
package elbv2test

import (
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// LoadBalancer is a seeded load balancer.
type LoadBalancer struct {
	ARN, Name, Type string
}

// Listener is a seeded listener.
type Listener struct {
	ARN, LoadBalancerARN, Protocol, SslPolicy string
	Port                                      int
}

// Policy is a seeded security policy.
type Policy struct {
	Name      string
	Protocols []string // as ELBv2 names them: TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
	Ciphers   []string // in priority order
}

// Server is the stand-in.
type Server struct {
	srv                          *httptest.Server
	region, accessKey, secretKey string
	mu                           sync.Mutex
	lbs                          []LoadBalancer
	listeners                    []Listener
	policies                     map[string]Policy
	calls                        map[string]int
	refused                      int
}

// New starts a stand-in that accepts requests signed with the given key.
func New(region, accessKey, secretKey string) *Server {
	s := &Server{region: region, accessKey: accessKey, secretKey: secretKey, policies: map[string]Policy{}, calls: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string          { return s.srv.URL }
func (s *Server) Client() *http.Client { return s.srv.Client() }
func (s *Server) Close()               { s.srv.Close() }

// Seed adds load balancers, listeners and policies.
func (s *Server) Seed(lbs []LoadBalancer, listeners []Listener, policies []Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lbs = append(s.lbs, lbs...)
	s.listeners = append(s.listeners, listeners...)
	for _, p := range policies {
		s.policies[p.Name] = p
	}
}

// SetPolicy points a listener at another policy (an operator's change).
func (s *Server) SetPolicy(listenerARN, policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.listeners {
		if s.listeners[i].ARN == listenerARN {
			s.listeners[i].SslPolicy = policy
		}
	}
}

// Calls reports how many times an action was called.
func (s *Server) Calls(action string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[action]
}

// NonDescribeCalls counts actions other than Describe*: discovery must never
// change the account.
func (s *Server) NonDescribeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for action, count := range s.calls {
		if !strings.HasPrefix(action, "Describe") {
			n += count
		}
	}
	return n
}

// Refused counts requests whose signature did not verify.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

type member[T any] struct {
	Items []T `xml:"member"`
}

type xmlLB struct {
	ARN  string `xml:"LoadBalancerArn"`
	Name string `xml:"LoadBalancerName"`
	Type string `xml:"Type"`
}

type xmlListener struct {
	ARN       string `xml:"ListenerArn"`
	LBARN     string `xml:"LoadBalancerArn"`
	Port      int    `xml:"Port"`
	Protocol  string `xml:"Protocol"`
	SslPolicy string `xml:"SslPolicy,omitempty"`
}

type xmlCipher struct {
	Name     string `xml:"Name"`
	Priority int    `xml:"Priority"`
}

type xmlPolicy struct {
	Name      string            `xml:"Name"`
	Protocols member[string]    `xml:"SslProtocols"`
	Ciphers   member[xmlCipher] `xml:"Ciphers"`
}

type describeLBs struct {
	XMLName xml.Name      `xml:"DescribeLoadBalancersResponse"`
	LBs     member[xmlLB] `xml:"DescribeLoadBalancersResult>LoadBalancers"`
	Next    string        `xml:"DescribeLoadBalancersResult>NextMarker,omitempty"`
}

type describeListeners struct {
	XMLName   xml.Name            `xml:"DescribeListenersResponse"`
	Listeners member[xmlListener] `xml:"DescribeListenersResult>Listeners"`
	Next      string              `xml:"DescribeListenersResult>NextMarker,omitempty"`
}

type describePolicies struct {
	XMLName  xml.Name          `xml:"DescribeSSLPoliciesResponse"`
	Policies member[xmlPolicy] `xml:"DescribeSSLPoliciesResult>SslPolicies"`
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if !s.verify(r, body) {
		s.mu.Lock()
		s.refused++
		s.mu.Unlock()
		http.Error(w, "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>", http.StatusForbidden)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || form.Get("Version") != "2015-12-01" {
		http.Error(w, "<ErrorResponse><Error><Code>MalformedQueryString</Code></Error></ErrorResponse>", http.StatusBadRequest)
		return
	}
	action := form.Get("Action")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[action]++
	var out any
	switch action {
	case "DescribeLoadBalancers":
		i := page(form.Get("Marker"), len(s.lbs))
		resp := describeLBs{}
		if i < len(s.lbs) {
			lb := s.lbs[i]
			resp.LBs.Items = []xmlLB{{ARN: lb.ARN, Name: lb.Name, Type: lb.Type}}
			if i+1 < len(s.lbs) {
				resp.Next = strconv.Itoa(i + 1)
			}
		}
		out = resp
	case "DescribeListeners":
		var of []Listener
		for _, l := range s.listeners {
			if l.LoadBalancerARN == form.Get("LoadBalancerArn") {
				of = append(of, l)
			}
		}
		i := page(form.Get("Marker"), len(of))
		resp := describeListeners{}
		if i < len(of) {
			l := of[i]
			resp.Listeners.Items = []xmlListener{{ARN: l.ARN, LBARN: l.LoadBalancerARN, Port: l.Port, Protocol: l.Protocol, SslPolicy: l.SslPolicy}}
			if i+1 < len(of) {
				resp.Next = strconv.Itoa(i + 1)
			}
		}
		out = resp
	case "DescribeSSLPolicies":
		resp := describePolicies{}
		var names []string
		for k, v := range form {
			if strings.HasPrefix(k, "Names.member.") {
				names = append(names, v...)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			p, ok := s.policies[n]
			if !ok {
				http.Error(w, "<ErrorResponse><Error><Code>SSLPolicyNotFound</Code></Error></ErrorResponse>", http.StatusBadRequest)
				return
			}
			xp := xmlPolicy{Name: p.Name, Protocols: member[string]{Items: p.Protocols}}
			for i, c := range p.Ciphers {
				xp.Ciphers.Items = append(xp.Ciphers.Items, xmlCipher{Name: c, Priority: i + 1})
			}
			resp.Policies.Items = append(resp.Policies.Items, xp)
		}
		out = resp
	default:
		http.Error(w, "<ErrorResponse><Error><Code>UnsupportedOperation</Code></Error></ErrorResponse>", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	_ = xml.NewEncoder(w).Encode(out)
}

func page(marker string, n int) int {
	if marker == "" {
		return 0
	}
	i, err := strconv.Atoi(marker)
	if err != nil || i < 0 {
		return n
	}
	return i
}

// verify recomputes the request's Signature Version 4 under the stand-in's key.
func (s *Server) verify(r *http.Request, body []byte) bool {
	const algo = "AWS4-HMAC-SHA256 "
	auth := r.Header.Get("Authorization")
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
	if len(scope) != 2 || scope[0] != s.accessKey || signedHeaders == "" || sig == "" {
		return false
	}
	cs := strings.Split(scope[1], "/")
	if len(cs) != 4 || cs[1] != s.region || cs[2] != "elasticloadbalancing" || cs[3] != "aws4_request" {
		return false
	}
	var canonHeaders strings.Builder
	for _, h := range strings.Split(signedHeaders, ";") {
		v := strings.TrimSpace(r.Header.Get(h))
		if h == "host" {
			v = r.Host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body)}, "\n")
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope[1], crypto.SHA256Hex([]byte(canonical))}, "\n")
	k := crypto.HMACSHA256([]byte("AWS4"+s.secretKey), []byte(cs[0]))
	k = crypto.HMACSHA256(k, []byte(cs[1]))
	k = crypto.HMACSHA256(k, []byte(cs[2]))
	k = crypto.HMACSHA256(k, []byte("aws4_request"))
	return hex.EncodeToString(crypto.HMACSHA256(k, []byte(toSign))) == sig
}
