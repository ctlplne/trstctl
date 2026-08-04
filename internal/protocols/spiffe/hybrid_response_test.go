// SPDX-License-Identifier: MPL-2.0

package spiffe

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

type additionalSVIDProbe struct {
	seenID     string
	seenExpiry time.Time
}

func (p *additionalSVIDProbe) IssueAdditionalX509SVID(_ context.Context, id string, expiry time.Time) (AdditionalX509SVID, error) {
	p.seenID, p.seenExpiry = id, expiry
	return AdditionalX509SVID{CertificateDER: []byte("alternate-cert"), PrivateKeyPKCS8: []byte("alternate-key"), Hint: "alternate"}, nil
}

func TestWorkloadAPIAdditionalResponseCarriesTwoDistinctKeysForSameSPIFFEID(t *testing.T) {
	const id = "spiffe://example.org/workload"
	wl, err := New(Config{
		Issuer: testIssuer(t), TenantID: "tenant-a", TrustDomain: "example.org",
		Entries: []RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	probe := &additionalSVIDProbe{}
	api := NewWorkloadAPIServer(wl, []string{"unix"}, WithAdditionalX509SVIDIssuer(probe))
	resp, err := api.buildX509SVIDResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Svids) != 2 {
		t.Fatalf("SVID entries = %d, want classical + additional", len(resp.Svids))
	}
	classical, additional := resp.Svids[0], resp.Svids[1]
	if classical.SpiffeId != id || additional.SpiffeId != id || classical.Hint != "trstctl-hybrid-classical" || additional.Hint != "alternate" {
		t.Fatalf("multi-key entries = classical:%+v additional:%+v", classical, additional)
	}
	if len(classical.X509SvidKey) == 0 || len(additional.X509SvidKey) == 0 || string(classical.X509SvidKey) == string(additional.X509SvidKey) {
		t.Fatal("multi-key Workload API response did not carry two distinct private keys")
	}
	if probe.seenID != id || probe.seenExpiry.IsZero() {
		t.Fatalf("additional issuer input id=%q expiry=%v", probe.seenID, probe.seenExpiry)
	}
	destroyX509SVIDResponse(resp)
	if classical.X509SvidKey != nil || additional.X509SvidKey != nil {
		t.Fatal("Workload API response private keys were not wiped after delivery")
	}
}

// TestWorkloadAPIAdditionalSVIDIsAuditedLikeClassical pins AN-2 parity: the
// additional issuer's mint emits the same spiffe.svid.issued audit shape the
// classical SVID gets, carrying its hint, so the second identity is never
// invisible to the event log.
func TestWorkloadAPIAdditionalSVIDIsAuditedLikeClassical(t *testing.T) {
	const id = "spiffe://example.org/workload"
	var payloads []string
	wl, err := New(Config{
		Issuer: testIssuer(t), TenantID: "tenant-a", TrustDomain: "example.org",
		Entries: []RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix"}}},
		Audit: auditsink.AuditorFunc(func(_ context.Context, eventType, tenantID string, data []byte) error {
			if tenantID != "tenant-a" {
				t.Errorf("audit emit %s carried tenant %q, want tenant-a", eventType, tenantID)
			}
			// Filter to the issuance events this test is about. It previously
			// rejected every other event type, which made it a de-facto
			// assertion that this path emits nothing else — a claim it was
			// never meant to make, and one that B3's local-socket deprecation
			// notice legitimately breaks.
			if eventType != "spiffe.svid.issued" {
				return nil
			}
			payloads = append(payloads, string(data))
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	api := NewWorkloadAPIServer(wl, []string{"unix"}, WithAdditionalX509SVIDIssuer(&additionalSVIDProbe{}))
	resp, err := api.buildX509SVIDResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer destroyX509SVIDResponse(resp)

	var sawClassical, sawAdditional bool
	for _, p := range payloads {
		if strings.Contains(p, `"type":"x509"`) {
			sawClassical = true
		}
		if strings.Contains(p, `"type":"x509-additional:alternate"`) {
			sawAdditional = true
		}
	}
	if !sawClassical || !sawAdditional {
		t.Fatalf("audit payloads = %v, want both the classical x509 and the additional x509-additional:alternate mints", payloads)
	}
}
