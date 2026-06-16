package catemplate

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// conformanceDomain is the identifier the suite asks a plugin to certify.
const conformanceDomain = "conformance.trstctl.test"

// Check is one conformance check and its outcome.
type Check struct {
	Name   string
	Passed bool
	Detail string
}

// Report is the result of running the CA-plugin conformance suite.
type Report struct {
	Checks []Check
}

// OK reports whether every check passed (and at least one ran).
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if !c.Passed {
			return false
		}
	}
	return len(r.Checks) > 0
}

func (r *Report) add(name string, passed bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: passed, Detail: detail})
}

// Conformance runs the shared CA-plugin conformance suite against plugin and
// returns a report. It is what a CA-plugin author runs against their build (with
// the plugin wired to its CA or a faithful test double) to self-validate, and the
// contract every plugin from this template must satisfy: name itself, issue a
// real certificate for a requested identifier, report the serial and a
// future expiry, and reject a malformed request.
//
// The CSR is built through the crypto boundary (AN-3); the suite holds no
// crypto/* itself.
func Conformance(ctx context.Context, plugin ca.CA) Report {
	var r Report

	r.add("names the authority", plugin.Name() != "", "")

	csr, err := conformanceCSR()
	if err != nil {
		r.add("suite can build a CSR", false, err.Error())
		return r
	}

	cert, err := plugin.Issue(ctx, ca.IssueRequest{
		TenantID: "conformance", CSR: csr, DNSNames: []string{conformanceDomain}, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		r.add("issues from a CSR", false, err.Error())
		return r
	}
	r.add("issues from a CSR", true, "")
	r.add("returns a PEM chain", len(cert.CertificatePEM) > 0, "")
	r.add("reports a serial", cert.Serial != "", "")
	r.add("labels the issuer", cert.Issuer == plugin.Name(), cert.Issuer)
	r.add("expiry is in the future", cert.NotAfter.After(time.Now()), cert.NotAfter.String())

	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		r.add("issued chain parses", false, err.Error())
		return r
	}
	r.add("issued chain parses", true, "")
	r.add("carries the requested SAN", containsDNS(info.DNSNames, conformanceDomain), join(info.DNSNames))

	_, err = plugin.Issue(ctx, ca.IssueRequest{TenantID: "conformance"})
	r.add("rejects a request with no CSR", err != nil, "")

	return r
}

// conformanceCSR builds a CSR for the conformance identifier through the crypto
// boundary, with the ephemeral key held in a locked buffer and destroyed.
func conformanceCSR() ([]byte, error) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	return crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: conformanceDomain, DNSNames: []string{conformanceDomain}}, key)
}

func containsDNS(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func join(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
