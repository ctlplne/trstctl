// SPDX-License-Identifier: BUSL-1.1

package acmtest

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
)

// ELB is a faithful in-process double of the Elastic Load Balancing (v2) Query
// API operations an ACM listener target uses (A166-L2): DescribeListeners and
// ModifyListener, form-encoded POSTs answered in XML, each verified with
// Signature Version 4 for the elasticloadbalancing service exactly as the ACM
// double verifies acm. It holds one HTTPS listener and the certificate ARN it
// serves by default.
type ELB struct {
	srv             *httptest.Server
	accessKeyID     string
	secretAccessKey string
	listenerARN     string

	mu       sync.Mutex
	current  string
	modifies int
}

// NewELB starts a fake load balancer API holding listenerARN, serving no
// certificate yet.
func NewELB(accessKeyID, secretAccessKey, listenerARN string) *ELB {
	e := &ELB{accessKeyID: accessKeyID, secretAccessKey: secretAccessKey, listenerARN: listenerARN}
	e.srv = httptest.NewServer(http.HandlerFunc(e.handle))
	return e
}

// URL is the endpoint base URL of the fake service.
func (e *ELB) URL() string { return e.srv.URL }

// Client returns an HTTP client for the fake service.
func (e *ELB) Client() *http.Client { return e.srv.Client() }

// Close shuts the server down.
func (e *ELB) Close() { e.srv.Close() }

// Serving is the certificate ARN the listener serves by default.
func (e *ELB) Serving() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current
}

// Modifies is the number of ModifyListener calls served.
func (e *ELB) Modifies() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.modifies
}

type elbCertificate struct {
	CertificateArn string `xml:"CertificateArn"`
	IsDefault      bool   `xml:"IsDefault,omitempty"`
}

type elbListener struct {
	ListenerArn  string           `xml:"ListenerArn"`
	Protocol     string           `xml:"Protocol"`
	Port         int              `xml:"Port"`
	Certificates []elbCertificate `xml:"Certificates>member"`
}

type elbListenersResult struct {
	Listeners []elbListener `xml:"Listeners>member"`
}

func (e *ELB) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		e.fail(w, http.StatusNotFound, "UnknownOperation", "no such resource")
		return
	}
	body, _ := io.ReadAll(r.Body)
	if !verifySigV4(r, body, e.accessKeyID, e.secretAccessKey, "elasticloadbalancing") {
		e.fail(w, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature does not match")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || form.Get("Version") != "2015-12-01" {
		e.fail(w, http.StatusBadRequest, "InvalidAction", "a form body with Version 2015-12-01 is required")
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	listener := func() elbListener {
		out := elbListener{ListenerArn: e.listenerARN, Protocol: "HTTPS", Port: 443}
		if e.current != "" {
			out.Certificates = []elbCertificate{{CertificateArn: e.current, IsDefault: true}}
		}
		return out
	}
	switch form.Get("Action") {
	case "DescribeListeners":
		if form.Get("ListenerArns.member.1") != e.listenerARN {
			e.fail(w, http.StatusBadRequest, "ListenerNotFound", "one or more listeners not found")
			return
		}
		e.write(w, xml.Name{Local: "DescribeListenersResponse"}, xml.Name{Local: "DescribeListenersResult"}, elbListenersResult{Listeners: []elbListener{listener()}})
	case "ModifyListener":
		if form.Get("ListenerArn") != e.listenerARN {
			e.fail(w, http.StatusBadRequest, "ListenerNotFound", "one or more listeners not found")
			return
		}
		arn := form.Get("Certificates.member.1.CertificateArn")
		if arn == "" {
			e.fail(w, http.StatusBadRequest, "ValidationError", "an HTTPS listener needs a certificate")
			return
		}
		e.current = arn
		e.modifies++
		e.write(w, xml.Name{Local: "ModifyListenerResponse"}, xml.Name{Local: "ModifyListenerResult"}, elbListenersResult{Listeners: []elbListener{listener()}})
	default:
		e.fail(w, http.StatusBadRequest, "InvalidAction", "unsupported action")
	}
}

func (e *ELB) write(w http.ResponseWriter, response, result xml.Name, body elbListenersResult) {
	type wrapped struct {
		XMLName xml.Name
		Xmlns   string `xml:"xmlns,attr"`
		Result  struct {
			XMLName xml.Name
			elbListenersResult
		}
	}
	out := wrapped{XMLName: response, Xmlns: "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"}
	out.Result.XMLName = result
	out.Result.elbListenersResult = body
	w.Header().Set("Content-Type", "text/xml")
	_ = xml.NewEncoder(w).Encode(out)
}

func (e *ELB) fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	type errorResponse struct {
		XMLName xml.Name `xml:"ErrorResponse"`
		Code    string   `xml:"Error>Code"`
		Message string   `xml:"Error>Message"`
	}
	_ = xml.NewEncoder(w).Encode(errorResponse{Code: code, Message: msg})
}
