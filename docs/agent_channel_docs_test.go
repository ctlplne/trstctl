package docs

import (
	"strings"
	"testing"
)

func TestGettingStartedAgentChannelMatchesBlankCompose(t *testing.T) {
	gettingStarted := read(t, "getting-started.md")
	compose := read(t, "../deploy/docker/docker-compose.yml")
	helmValues := read(t, "../deploy/helm/trstctl/values.yaml")
	helmService := read(t, "../deploy/helm/trstctl/templates/service.yaml")
	install := read(t, "install.md")
	rollout := read(t, "runbooks/fleet-rollout.md")

	if !containsAll(compose, []string{`TRSTCTL_SERVER_ADDR: ":8443"`, `"8443:8443"`}) {
		t.Fatal("blank Compose must keep serving the documented control-plane endpoint at https://localhost:8443")
	}

	composeServesAgentChannel := containsAll(compose, []string{
		`TRSTCTL_AGENT_CHANNEL_ENABLED: "true"`,
		`TRSTCTL_AGENT_CHANNEL_ADDR: ":9443"`,
		`TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE: /data/ca/agent-ca.crt`,
		`"19443:9443"`,
	})
	gettingStartedUsesLocalAgentChannel := strings.Contains(gettingStarted, "--server localhost:19443")
	if strings.Contains(gettingStarted, "--server localhost:9443") {
		t.Fatal("getting-started.md must not point the blank Compose agent at localhost:9443; the demo stack uses that host port")
	}
	if gettingStartedUsesLocalAgentChannel && !composeServesAgentChannel {
		t.Fatal("getting-started.md sends blank-Compose agents to localhost:19443, but blank Compose does not enable and publish that agent channel")
	}
	if !gettingStartedUsesLocalAgentChannel && composeServesAgentChannel {
		t.Fatal("blank Compose serves the agent channel, but getting-started.md no longer documents how to reach it")
	}

	if gettingStartedUsesLocalAgentChannel {
		for _, want := range []string{
			"--server-name localhost",
			"docker compose -f deploy/docker/docker-compose.yml cp trstctl:/data/ca/agent-ca.crt ./trstctl-agent-ca.pem",
			"openssl s_client -connect localhost:8443 -servername localhost -showcerts",
			"cat ./trstctl-https-ca.pem ./trstctl-agent-ca.pem > ./trstctl-ca.pem",
			"--ca-bundle ./trstctl-ca.pem",
		} {
			if !strings.Contains(gettingStarted, want) {
				t.Errorf("getting-started.md local agent command is missing CA/server-name guidance %q", want)
			}
		}
	}

	if !strings.Contains(helmValues, "agentChannel:\n  enabled: false") {
		t.Fatal("Helm agentChannel default changed; update the docs reality test and live-agent install docs together")
	}
	if !containsAll(helmService, []string{".Values.agentChannel.enabled", "agent-grpc", ".Values.agentChannel.servicePort"}) {
		t.Fatal("Helm service must publish agent-grpc only when agentChannel.enabled is set")
	}
	for _, doc := range []struct {
		name string
		body string
	}{
		{"install.md", install},
		{"runbooks/fleet-rollout.md", rollout},
	} {
		if !containsAll(doc.body, []string{"--set agentChannel.enabled=true", "--set agentChannel.serverName=trstctl"}) {
			t.Errorf("%s must show the explicit Helm opt-in for live agent-channel rollout", doc.name)
		}
	}
}
