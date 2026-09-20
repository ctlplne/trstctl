// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// AUD-10: attested issuance had no operator switch at all.
//
// Deps.AttestedIssuance was never assigned anywhere in production, so
// s.attestedIssuance was nil in every deployment and both routes it gates —
// POST /api/v1/workloads/attested-issuance and POST /api/v1/ssh/attested-user-certs
// — returned 503 forever. There was no config key to set: `grep -ci attested
// internal/config/config.go` returned zero. The six attestors behind those
// routes, including the GitHub OIDC attestor a CI pipeline needs, were
// constructed by code no request could reach.
//
// Off by default is right for a mint that trades a cloud attestation for a
// certificate. Unreachable when ON is the defect.

func TestAttestedIssuanceHasAnOperatorSwitch(t *testing.T) {
	t.Parallel()
	off := attestedIssuanceFromConfig(config.AttestedIssuance{})
	if off.Enabled {
		t.Fatal("attested issuance is on by default; a mint that trades an attestation for a " +
			"certificate must be opted into")
	}
	on := attestedIssuanceFromConfig(config.AttestedIssuance{
		Enabled: true, TrustDomain: "example.org", DefaultTTL: "5m", MaxTTL: "30m",
	})
	if !on.Enabled {
		t.Fatal("the config key does not turn attested issuance on. Without this the route is " +
			"registered, documented, and permanently 503 — which is what shipped")
	}
	if on.TrustDomain != "example.org" {
		t.Fatalf("trust domain = %q; an SVID with no trust domain names nothing", on.TrustDomain)
	}
	if on.DefaultTTL != 5*time.Minute || on.MaxTTL != 30*time.Minute {
		t.Fatalf("ttls = %v/%v, want the operator's values", on.DefaultTTL, on.MaxTTL)
	}
}

// A malformed duration must not silently become a LONGER lifetime than the
// operator wrote. Zero is safe: it takes the built-in bound.
func TestAMalformedTTLNeverLengthensTheLifetime(t *testing.T) {
	t.Parallel()
	got := attestedIssuanceFromConfig(config.AttestedIssuance{
		Enabled: true, TrustDomain: "example.org", DefaultTTL: "not-a-duration", MaxTTL: "also-not",
	})
	if got.DefaultTTL != 0 || got.MaxTTL != 0 {
		t.Fatalf("ttls = %v/%v, want zero so the built-in bound applies", got.DefaultTTL, got.MaxTTL)
	}
	svc, err := newAttestedIssuerService(attestedIssuerDeps{Config: got})
	if err == nil && svc != nil && svc.maxTTL > maxAttestedSVIDTTL {
		t.Fatalf("max ttl = %v, above the built-in ceiling %v", svc.maxTTL, maxAttestedSVIDTTL)
	}
}

// Enabling without a trust domain must fail LOUDLY at boot, not mint SVIDs that
// name nothing.
func TestEnablingWithoutATrustDomainRefusesToBoot(t *testing.T) {
	t.Parallel()
	_, err := newAttestedIssuerService(attestedIssuerDeps{
		Config: AttestedIssuanceConfig{Enabled: true},
	})
	if err == nil {
		t.Fatal("attested issuance booted with an empty trust domain; every SVID it minted would " +
			"name nothing, and the failure would surface at the relying party rather than at boot")
	}
	if !strings.Contains(err.Error(), "trust domain") {
		t.Errorf("error does not name the missing trust domain: %v", err)
	}
}

// The config key must actually reach the server. A mapper nobody calls is the
// exact shape of the original defect: attestedIssuanceFromConfig could be
// perfect and every route still 503 if run.go never assigns Deps.AttestedIssuance.
func TestTheAttestedIssuanceConfigKeyReachesTheAssembledServer(t *testing.T) {
	t.Parallel()
	src, err := readSourceFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	// Matched on the CALL, not on spacing: gofmt aligns struct field values, so
	// an exact "Field: value" string is brittle in a way that would make this
	// guard fail for the wrong reason.
	if !strings.Contains(src, "attestedIssuanceFromConfig(cfg.AttestedIssuance)") {
		t.Fatal("run.go does not assign Deps.AttestedIssuance from config.\n\n" +
			"This is the whole defect (AUD-10): the service, the six attestors, the routes, the " +
			"OpenAPI entry and the docs all existed, and no request could reach any of it because " +
			"this one assignment was missing. A config mapper nobody calls leaves the route 503 " +
			"exactly as before.")
	}
}
