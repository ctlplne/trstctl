// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// AUD-12 and AUD-13, the last two of the dead-Deps family.
//
// Deps.AgentBroker and Deps.PAM were never assigned anywhere in production, so
// POST /api/v1/broker/agent-identities and the four PAM routes returned
// "unavailable" on every deployment. `grep -ci pam internal/config/config.go`
// returned zero: there was no key an operator could set. Off by default is
// right for both; unreachable when on was the defect.

func TestAgentBrokerHasAnOperatorSwitch(t *testing.T) {
	t.Parallel()
	if agentBrokerFromConfig(config.AgentBroker{}).Enabled {
		t.Fatal("the agent broker is on by default; a mint must be opted into")
	}
	on := agentBrokerFromConfig(config.AgentBroker{
		Enabled: true, TrustDomain: "example.org", DefaultTTL: "5m", MaxTTL: "30m",
	})
	if !on.Enabled {
		t.Fatal("the config key does not turn the broker on. Without it the route is registered, " +
			"documented, and permanently unavailable — which is what shipped")
	}
	if on.TrustDomain != "example.org" {
		t.Fatalf("trust domain = %q; an identity with no trust domain names nothing", on.TrustDomain)
	}
	if on.DefaultTTL != 5*time.Minute || on.MaxTTL != 30*time.Minute {
		t.Fatalf("ttls = %v/%v, want the operator's values", on.DefaultTTL, on.MaxTTL)
	}
}

func TestPAMHasAnOperatorSwitch(t *testing.T) {
	t.Parallel()
	if pamFromConfig(config.PAM{}).Enabled {
		t.Fatal("PAM is on by default; privileged access must be opted into")
	}
	on := pamFromConfig(config.PAM{Enabled: true, DefaultTTL: "15m", MaxTTL: "1h"})
	if !on.Enabled {
		t.Fatal("the config key does not turn PAM on. Four routes stayed permanently unavailable " +
			"with no way for an operator to change that")
	}
	if on.DefaultTTL != 15*time.Minute || on.MaxTTL != time.Hour {
		t.Fatalf("ttls = %v/%v", on.DefaultTTL, on.MaxTTL)
	}
}

// A malformed duration must not silently become a LONGER lifetime than the
// operator wrote. Zero takes the built-in bound; zero cannot lengthen anything.
func TestAMalformedTTLNeverLengthensABrokeredOrPAMLifetime(t *testing.T) {
	t.Parallel()
	b := agentBrokerFromConfig(config.AgentBroker{Enabled: true, DefaultTTL: "x", MaxTTL: "y"})
	if b.DefaultTTL != 0 || b.MaxTTL != 0 {
		t.Fatalf("broker ttls = %v/%v, want zero so the built-in bound applies", b.DefaultTTL, b.MaxTTL)
	}
	p := pamFromConfig(config.PAM{Enabled: true, DefaultTTL: "x", MaxTTL: "y"})
	if p.DefaultTTL != 0 || p.MaxTTL != 0 {
		t.Fatalf("pam ttls = %v/%v, want zero", p.DefaultTTL, p.MaxTTL)
	}
}

// The config must actually reach the assembled server. A mapper nobody calls is
// the exact shape of the original defect.
func TestTheBrokerAndPAMConfigKeysReachTheAssembledServer(t *testing.T) {
	t.Parallel()
	src, err := readSourceFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"agentBrokerFromConfig(cfg.AgentBroker)",
		"pamFromConfig(cfg.PAM)",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("run.go does not assign %s.\n\n"+
				"This is the whole defect: the service, the routes, the OpenAPI entry and the "+
				"docs all existed, and no request could reach any of it because one assignment "+
				"was missing. A config mapper nobody calls leaves the route unavailable exactly "+
				"as before.", want)
		}
	}
}
