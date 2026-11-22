// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"errors"
	"net/http"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// A policy is tenant-authored code. Give every compile path the same pure
// builtin set so it cannot use the control plane as an HTTP or DNS client.
func restrictedRego(query, filename, module string) *rego.Rego {
	caps := ast.CapabilitiesForThisVersion()
	caps.AllowNet = []string{}
	allowed := caps.Builtins[:0]
	for _, builtin := range caps.Builtins {
		switch builtin.Name {
		case "http.send", "net.lookup_ip_addr", "print", "internal.print", "trace", "opa.runtime":
			continue
		}
		allowed = append(allowed, builtin)
	}
	caps.Builtins = allowed
	return rego.New(rego.Query(query), rego.Module(filename, module), rego.Capabilities(caps))
}

// This is a second boundary if a later OPA release introduces a new HTTP
// builtin before its capability list is audited. No policy evaluation may dial.
func denyPolicyHTTP(*http.Transport) http.RoundTripper { return deniedPolicyTransport{} }

type deniedPolicyTransport struct{}

func (deniedPolicyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("policy: outbound HTTP is disabled")
}
