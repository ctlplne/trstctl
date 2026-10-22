// SPDX-License-Identifier: BUSL-1.1

package connector

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
