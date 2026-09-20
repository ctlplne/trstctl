// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// This independent fixture receives only public IDs and certificate bytes.
// It uses the pinned stock implementation without a compatibility build tag,
// and performs actual certificate-chain and validity checks, not string matching.
func runIdentityChecks() {
	var input struct {
		IDs          []string `json:"ids"`
		Certificates []struct {
			DER         []byte `json:"der"`
			CA          []byte `json:"ca"`
			TrustDomain string `json:"trust_domain"`
		} `json:"certificates"`
	}
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&input); err != nil {
		fail("decode public identity checks: %v", err)
	}
	type outcome struct {
		Accepted bool   `json:"accepted"`
		ID       string `json:"id,omitempty"`
		Error    string `json:"error,omitempty"`
	}
	result := struct {
		IDs          []outcome `json:"ids"`
		Certificates []outcome `json:"certificates"`
	}{}
	for _, raw := range input.IDs {
		id, err := spiffeid.FromString(raw)
		row := outcome{Accepted: err == nil}
		if err != nil {
			row.Error = err.Error()
		} else {
			row.ID = id.String()
		}
		result.IDs = append(result.IDs, row)
	}
	for _, cert := range input.Certificates {
		td, err := spiffeid.TrustDomainFromString(cert.TrustDomain)
		if err != nil {
			fail("invalid fixture trust domain")
		}
		bundle, err := x509bundle.ParseRaw(td, cert.CA)
		if err != nil {
			fail("invalid fixture public CA")
		}
		id, _, err := x509svid.ParseAndVerify([][]byte{cert.DER}, bundle)
		row := outcome{Accepted: err == nil}
		if err != nil {
			row.Error = err.Error()
		} else {
			row.ID = id.String()
		}
		result.Certificates = append(result.Certificates, row)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail("encode identity checks: %v", err)
	}
}
