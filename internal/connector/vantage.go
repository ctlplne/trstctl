// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ShippedTargetVantage returns where a connector family shipped by trstctl
// executes its privileged work. The boolean is false for an unknown family so
// callers can retain the fail-closed control-plane default without presenting
// an unreviewed connector as agent-executable.
//
// This census belongs beside TargetVantage rather than in either binary's
// composition root. The control plane uses it to stamp claimable work, the API
// uses it to explain that work to operators, and tests compare it with the
// agent's actual executor census. One definition prevents the scheduler from
// saying "host agent" while the UI says "control plane" for the same family.
func ShippedTargetVantage(name string) (TargetVantage, bool) {
	if IsRelayVantageFamily(name) {
		return VantageNetworkRelay, true
	}
	switch name {
	case "nginx", "apache", "caddy", "iis", "haproxy", "postfix", "traefik",
		"java-keystore", "postgresql", "mysql", "rabbitmq", "elasticsearch",
		"tomcat", "envoy":
		return VantageHostAgent, true
	default:
		return VantageControlPlane, false
	}
}

// ControlPlaneCarriesNatively reports the relay-vantage families the control
// plane's own egress-guarded client still executes when a tenant has no
// network relay enrolled: the cloud certificate stores (A59). Their deploys,
// previews and GCP's re-bind rollback ran in the control plane before they
// gained relay execution, and an estate that runs no relay keeps that path.
// Appliance families are not in this set: the control plane's conditional
// deploy fallback for them predates E1, but their rollback, readback and
// takedown execute only on a relay by design.
func ControlPlaneCarriesNatively(name string) bool {
	switch name {
	case "aws-acm", "azure-keyvault", "gcp-certificate-manager":
		return true
	}
	return false
}

// VantageConfigKey is the deployment-target config key through which a target
// may declare where its work executes, for the one family that admits a
// per-target choice (A61).
const VantageConfigKey = "vantage"

// VantageNetworkDeclaration is the value an envoy target writes under
// VantageConfigKey to be driven by a network relay. It is the agent role
// name, which is what operators see on the agents and jobs pages.
const VantageNetworkDeclaration = "network"

// TargetVantageOverride reads a target's declared vantage. Only Envoy may
// declare one, and only "network": its SDS management surface is HTTP, so an
// Envoy that is not co-resident with a host agent — a remote proxy or a fleet
// behind one management endpoint — is driven by a network relay instead. Every
// other family's vantage is a property of what the target is, not a choice, so
// a declaration there is an error rather than a request to ignore. Absent and
// empty mean no override. The value must be a string.
func TargetVantageOverride(family string, config json.RawMessage) (TargetVantage, bool, error) {
	if len(config) == 0 {
		return "", false, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(config, &fields); err != nil {
		return "", false, nil
	}
	raw, present := fields[VantageConfigKey]
	if !present || raw == nil {
		return "", false, nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("connector: %s must be a string naming the executor", VantageConfigKey)
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", false, nil
	}
	if family != "envoy" || value != VantageNetworkDeclaration {
		return "", false, fmt.Errorf("connector: %s %q is not permitted for %s targets; only an envoy target may declare %q", VantageConfigKey, value, family, VantageNetworkDeclaration)
	}
	return VantageNetworkRelay, true, nil
}

// EffectiveTargetVantage is ShippedTargetVantage with the target's permitted
// override applied. An invalid declaration is ignored here (the target
// validators refuse it before it is saved); the family answer stands.
func EffectiveTargetVantage(family string, config json.RawMessage) (TargetVantage, bool) {
	if override, ok, err := TargetVantageOverride(family, config); err == nil && ok {
		return override, true
	}
	return ShippedTargetVantage(family)
}
