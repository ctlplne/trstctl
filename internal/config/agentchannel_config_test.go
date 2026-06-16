package config

import (
	"strings"
	"testing"
)

// TestAgentChannelDefaultsOff: the served agent steady-state channel (WIRE-004 /
// OPS-005) is OFF by default, so an upgrade does not silently open an agent port.
func TestAgentChannelDefaultsOff(t *testing.T) {
	if Default().AgentChannel.Enabled {
		t.Fatal("agent_channel must default OFF (an upgrade must not silently open :9443)")
	}
}

// TestAgentChannelEnabledRequiresSigner: enabling the channel without a signer is a
// fail-closed startup error — the agent CA must be custodied in the signer (AN-4), so
// the binary must never advertise an agent channel it cannot back with a
// signer-custodied CA.
func TestAgentChannelEnabledRequiresSigner(t *testing.T) {
	c := Default()
	c.AgentChannel.Enabled = true
	c.Signer.Mode = "" // no signer
	err := c.Validate()
	if err == nil {
		t.Fatal("agent_channel.enabled with no signer must fail validation (AN-4 fail-closed)")
	}
	if !strings.Contains(err.Error(), "agent_channel") || !strings.Contains(err.Error(), "signer") {
		t.Fatalf("error should explain the signer requirement; got %v", err)
	}

	// With the default signer (child mode) it validates.
	c2 := Default()
	c2.AgentChannel.Enabled = true
	if err := c2.Validate(); err != nil {
		t.Fatalf("agent_channel.enabled with the default signer must be valid; got %v", err)
	}
}

// TestAgentChannelHeartbeatIntervalMustParse: a malformed heartbeat interval fails fast
// at startup rather than silently falling back.
func TestAgentChannelHeartbeatIntervalMustParse(t *testing.T) {
	c := Default()
	c.AgentChannel.Enabled = true
	c.AgentChannel.HeartbeatInterval = "not-a-duration"
	if err := c.Validate(); err == nil {
		t.Fatal("a malformed agent_channel.heartbeat_interval must fail validation")
	}

	c.AgentChannel.HeartbeatInterval = "30s"
	if err := c.Validate(); err != nil {
		t.Fatalf("a valid heartbeat interval must pass; got %v", err)
	}
	d, err := c.AgentChannel.HeartbeatIntervalDuration()
	if err != nil || d.Seconds() != 30 {
		t.Fatalf("HeartbeatIntervalDuration = %v, %v; want 30s", d, err)
	}
}

// TestAgentChannelEnvOverrides: the TRSTCTL_AGENT_CHANNEL_* env keys load into the
// config (the chart's ConfigMap wires these).
func TestAgentChannelEnvOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_AGENT_CHANNEL_ENABLED":            "true",
		"TRSTCTL_AGENT_CHANNEL_ADDR":               ":19443",
		"TRSTCTL_AGENT_CHANNEL_SERVER_NAME":        "agents.example.com",
		"TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE":       "/data/ca/agent-ca.crt",
		"TRSTCTL_AGENT_CHANNEL_HEARTBEAT_INTERVAL": "45s",
	}
	c := Default()
	c.applyEnv(func(k string) string { return env[k] })
	if !c.AgentChannel.Enabled {
		t.Error("TRSTCTL_AGENT_CHANNEL_ENABLED did not enable the channel")
	}
	if c.AgentChannel.Addr != ":19443" {
		t.Errorf("addr = %q, want :19443", c.AgentChannel.Addr)
	}
	if c.AgentChannel.ServerName != "agents.example.com" {
		t.Errorf("serverName = %q", c.AgentChannel.ServerName)
	}
	if c.AgentChannel.CACertFile != "/data/ca/agent-ca.crt" {
		t.Errorf("caCertFile = %q", c.AgentChannel.CACertFile)
	}
	if c.AgentChannel.HeartbeatInterval != "45s" {
		t.Errorf("heartbeatInterval = %q", c.AgentChannel.HeartbeatInterval)
	}
}
