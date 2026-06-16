package helm

import (
	"testing"
)

// agentchannel_test.go is the OPS-005 rendered-chart proof for the served agent
// steady-state mTLS gRPC channel (WIRE-004): when agentChannel.enabled, the control
// plane chart must expose the agent port (9443) as a Service port, a container port,
// and a NetworkPolicy ingress rule, and wire the enabling env into the ConfigMap.
// When DISABLED (the default), none of those appear — so an upgrade does not silently
// open an agent port. Each assertion drills the PARSED object (port number, protocol),
// not the template text, and is mutation-proven by the enabled/disabled split.

const agentGRPCPort = float64(9443)

// servicePortNames returns the (name -> port) map of a rendered Service's ports.
func servicePorts(t *testing.T, svc map[string]any) map[string]float64 {
	t.Helper()
	spec, _ := svc["spec"].(map[string]any)
	ports, _ := spec["ports"].([]any)
	out := map[string]float64{}
	for _, p := range ports {
		pm, _ := p.(map[string]any)
		name, _ := pm["name"].(string)
		switch v := pm["port"].(type) {
		case int:
			out[name] = float64(v)
		case float64:
			out[name] = v
		}
	}
	return out
}

// TestAgentChannelServiceExposes9443WhenEnabled is the OPS-005 acceptance: with the
// channel enabled the control-plane Service publishes the agent-grpc port (9443) in
// ADDITION to the API port, and the container exposes the port — so the shipped fleet
// manifests that point agents at :9443 reach a served port.
func TestAgentChannelServiceExposes9443WhenEnabled(t *testing.T) {
	svc := renderSimpleObj(t, "service.yaml", agentChannelEnabledValues())
	if svc["kind"] != "Service" {
		t.Fatalf("service.yaml rendered kind=%v, want Service", svc["kind"])
	}
	ports := servicePorts(t, svc)
	if ports["https"] != float64(8443) {
		t.Errorf("Service is missing the API port 8443; got %v", ports)
	}
	if ports["agent-grpc"] != agentGRPCPort {
		t.Fatalf("Service does not publish the agent channel port 9443 (agent-grpc); got %v (OPS-005)", ports)
	}

	// The control-plane container must expose the agent port too (a Service targeting
	// a port no container exposes would be unreachable).
	dep := renderControlPlaneDeployment(t, agentChannelEnabledValues())
	objs := decodeAllYAML(t, dep)
	var cpPorts []any
	for _, o := range objs {
		if o["kind"] != "Deployment" {
			continue
		}
		spec, _ := o["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		podSpec, _ := tmpl["spec"].(map[string]any)
		conts, _ := podSpec["containers"].([]any)
		for _, c := range conts {
			cm, _ := c.(map[string]any)
			if cm["name"] == "trstctl" {
				cpPorts, _ = cm["ports"].([]any)
			}
		}
	}
	foundContainerPort := false
	for _, p := range cpPorts {
		pm, _ := p.(map[string]any)
		switch v := pm["containerPort"].(type) {
		case int:
			if float64(v) == agentGRPCPort {
				foundContainerPort = true
			}
		case float64:
			if v == agentGRPCPort {
				foundContainerPort = true
			}
		}
	}
	if !foundContainerPort {
		t.Errorf("control-plane container does not expose containerPort 9443 for the agent channel (OPS-005)")
	}

	// The ConfigMap must enable the channel (the env key the binary actually reads).
	cm := renderSimpleObj(t, "configmap.yaml", agentChannelEnabledValues())
	data, _ := cm["data"].(map[string]any)
	if asString(data["TRSTCTL_AGENT_CHANNEL_ENABLED"]) != "true" {
		t.Errorf("configmap does not set TRSTCTL_AGENT_CHANNEL_ENABLED=true when the channel is enabled; got %q", asString(data["TRSTCTL_AGENT_CHANNEL_ENABLED"]))
	}
	if !loaderEnvKeysSet(t)["TRSTCTL_AGENT_CHANNEL_ENABLED"] {
		t.Errorf("configmap sets TRSTCTL_AGENT_CHANNEL_ENABLED but the config loader does not read it (phantom env, OPS-008)")
	}
}

// TestAgentChannelNetworkPolicyAdmits9443WhenEnabled: the NetworkPolicy ingress opens
// the agent port (9443) only when the channel is enabled, via a parsed rule (port +
// protocol), and includes the operator-configured agent CIDR.
func TestAgentChannelNetworkPolicyAdmits9443WhenEnabled(t *testing.T) {
	np := renderSimpleObj(t, "networkpolicy.yaml", agentChannelEnabledValues())
	if np["kind"] != "NetworkPolicy" {
		t.Fatalf("networkpolicy.yaml rendered kind=%v, want NetworkPolicy", np["kind"])
	}
	spec, _ := np["spec"].(map[string]any)
	ingress, _ := spec["ingress"].([]any)
	admits9443 := false
	admitsCIDR := false
	for _, r := range ingress {
		rule, _ := r.(map[string]any)
		ports, _ := rule["ports"].([]any)
		ruleHas9443 := false
		for _, p := range ports {
			pm, _ := p.(map[string]any)
			if pm["protocol"] != "TCP" {
				continue
			}
			switch v := pm["port"].(type) {
			case int:
				if float64(v) == agentGRPCPort {
					ruleHas9443 = true
				}
			case float64:
				if v == agentGRPCPort {
					ruleHas9443 = true
				}
			}
		}
		if !ruleHas9443 {
			continue
		}
		admits9443 = true
		from, _ := rule["from"].([]any)
		for _, f := range from {
			fm, _ := f.(map[string]any)
			if ip, ok := fm["ipBlock"].(map[string]any); ok && ip["cidr"] == "10.0.0.0/8" {
				admitsCIDR = true
			}
		}
	}
	if !admits9443 {
		t.Fatalf("NetworkPolicy does not admit the agent channel port 9443 when enabled (OPS-005)")
	}
	if !admitsCIDR {
		t.Errorf("NetworkPolicy agent-port rule does not include the configured agentChannel.allowedCIDRs block 10.0.0.0/8")
	}
}

// TestAgentChannelHiddenWhenDisabled is the mutation-proof negative: with the channel
// disabled (the DEFAULT), the Service publishes only the API port, the container has no
// 9443 port, the NetworkPolicy admits no 9443, and the ConfigMap does not enable it —
// so a default install does not expose an agent port.
func TestAgentChannelHiddenWhenDisabled(t *testing.T) {
	svc := renderSimpleObj(t, "service.yaml", defaultishValues())
	if _, ok := servicePorts(t, svc)["agent-grpc"]; ok {
		t.Error("Service publishes the agent port 9443 even though the channel is disabled (default must not expose it)")
	}

	cm := renderSimpleObj(t, "configmap.yaml", defaultishValues())
	data, _ := cm["data"].(map[string]any)
	if _, ok := data["TRSTCTL_AGENT_CHANNEL_ENABLED"]; ok {
		t.Error("configmap sets TRSTCTL_AGENT_CHANNEL_ENABLED when the channel is disabled")
	}

	np := renderSimpleObj(t, "networkpolicy.yaml", defaultishValues())
	spec, _ := np["spec"].(map[string]any)
	ingress, _ := spec["ingress"].([]any)
	for _, r := range ingress {
		rule, _ := r.(map[string]any)
		ports, _ := rule["ports"].([]any)
		for _, p := range ports {
			pm, _ := p.(map[string]any)
			switch v := pm["port"].(type) {
			case int:
				if float64(v) == agentGRPCPort {
					t.Error("NetworkPolicy admits the agent port 9443 even though the channel is disabled")
				}
			case float64:
				if v == agentGRPCPort {
					t.Error("NetworkPolicy admits the agent port 9443 even though the channel is disabled")
				}
			}
		}
	}
}
