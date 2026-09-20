// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
)

// The served adapters choose a default lifetime themselves; a CSR does not ask
// for 30 or 90 days. A shorter bound profile must remain usable for enrollment.
// Use the real event log, PostgreSQL repositories and idempotency path here.
func TestProtocolIssuerSelectsLifetimeWithinBoundProfile(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Protocol validity CA", 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var signedTTL time.Duration
	signCalls := 0
	issuer := &protocolIssuer{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			signCalls++
			signedTTL = ttl
			der, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
		},
		orch: h.orch, idem: orchestrator.NewIdempotency(h.store), store: h.store, log: h.log, caID: IssuingCAID(),
	}
	csr := serverTestCSR(t, "short.validity.test", nil)
	for _, tc := range []struct {
		name, protocol           string
		maximum, requested, want time.Duration
	}{
		{"acme-short", "acme", 10 * time.Minute, 90 * 24 * time.Hour, 10 * time.Minute},
		{"est-short", "est", 10 * time.Minute, protocolLeafTTL, 10 * time.Minute},
		{"scep-short", "scep", 10 * time.Minute, protocolLeafTTL, 10 * time.Minute},
		{"cmp-short", "cmp", 10 * time.Minute, protocolLeafTTL, 10 * time.Minute},
		{"shorter-request", "acme", 10 * time.Minute, 30 * time.Second, 30 * time.Second},
		{"zero-default", "est", 10 * time.Minute, 0, 10 * time.Minute},
		{"platform-ceiling", "acme", 60 * 24 * time.Hour, 90 * 24 * time.Hour, protocolLeafTTL},
		{"unlimited-profile", "acme", 0, 90 * 24 * time.Hour, protocolLeafTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeServerTestProfile(t, h.store, h.tenant, tc.name, profile.CertificateProfile{
				Name: tc.name, AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(tc.maximum),
				AllowedProtocols: []string{tc.protocol}, AllowedDNSSuffixes: []string{"validity.test"},
			})
			issuer.defaultProfile = tc.name
			before := time.Now()
			callsBefore := signCalls
			der, err := issuer.IssueProtocolLeaf(ctx, h.tenant, tc.protocol, tc.name, csr, tc.requested)
			if err != nil {
				t.Fatalf("enroll under bound profile: %v", err)
			}
			if signedTTL != tc.want || signCalls != callsBefore+1 {
				t.Fatalf("signed lifetime/calls = %s/%d, want %s/%d", signedTTL, signCalls, tc.want, callsBefore+1)
			}
			info, err := certinfo.Inspect(der)
			if err != nil {
				t.Fatal(err)
			}
			forward := tc.want
			if tc.maximum > 0 && forward+crypto.IssuanceBackdateSkew() > tc.maximum {
				forward = tc.maximum - crypto.IssuanceBackdateSkew()
			}
			if tc.maximum > 0 && info.NotAfter.Sub(info.NotBefore) > tc.maximum {
				t.Fatalf("full signed validity exceeds the bound profile: %s", info.NotAfter.Sub(info.NotBefore))
			}
			if info.NotAfter.Before(before.Add(forward-time.Second)) || info.NotAfter.After(time.Now().Add(forward)) {
				t.Fatalf("signed expiry %s does not reflect selected lifetime %s", info.NotAfter, tc.want)
			}
			// A changed/missing profile cannot prevent returning an already issued
			// result, nor cause its lifetime to be recomputed and signed again.
			issuer.defaultProfile = "removed-after-issuance"
			replayed, err := issuer.IssueProtocolLeaf(ctx, h.tenant, tc.protocol, tc.name, csr, tc.requested)
			if err != nil || !bytes.Equal(der, replayed) || signCalls != callsBefore+1 {
				t.Fatalf("original certificate replay changed: error=%v calls=%d", err, signCalls)
			}
		})
	}

	issuer.defaultProfile = "acme-short"
	for _, tc := range []struct{ name, protocol, host, want string }{
		{"dns-denied", "acme", "outside.example", "DNS"},
		{"protocol-denied", "est", "short.validity.test", "protocol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := signCalls
			_, err := issuer.IssueProtocolLeaf(ctx, h.tenant, tc.protocol, tc.name, serverTestCSR(t, tc.host, nil), protocolLeafTTL)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) || signCalls != before {
				t.Fatalf("policy rejection = %v; signing calls %d -> %d", err, before, signCalls)
			}
		})
	}
	issuer.defaultProfile = "missing"
	before := signCalls
	if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "missing-profile", csr, protocolLeafTTL); err == nil || !strings.Contains(err.Error(), "not found") || signCalls != before {
		t.Fatalf("missing profile must fail before signing: %v", err)
	}
}
