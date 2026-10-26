// SPDX-License-Identifier: BUSL-1.1

package k8stls

import (
	"encoding/json"
	"testing"
)

func TestFindingsNormalizesIngressAndGateway(t *testing.T) {
	raw := json.RawMessage(`{
		"resources":[
			{"kind":"Ingress","namespace":"payments","name":"payments-web","tls_secret_name":"payments-web-tls","hosts":["payments.example.com"],"auto_issue":true},
			{"kind":"Gateway","namespace":"edge","name":"public","tls_secret_name":"edge-public-tls","hosts":["edge.example.com","API.EXAMPLE.COM","edge.example.com"],"auto_issue":true}
		]
	}`)

	findings, err := Findings(raw)
	if err != nil {
		t.Fatalf("Findings returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Ref != "Ingress:payments/payments-web" ||
		findings[0].DeploymentLocation != "k8s:Ingress:payments/payments-web:secret/payments-web-tls" ||
		findings[0].CommonName != "payments.example.com" ||
		findings[0].Fingerprint != "k8s_ingress_gateway:Ingress:payments/payments-web:payments-web-tls" {
		t.Fatalf("bad ingress finding: %+v", findings[0])
	}
	if findings[1].Ref != "Gateway:edge/public" ||
		findings[1].DeploymentLocation != "k8s:Gateway:edge/public:secret/edge-public-tls" ||
		len(findings[1].DNSNames) != 2 ||
		findings[1].DNSNames[1] != "api.example.com" {
		t.Fatalf("bad gateway finding: %+v", findings[1])
	}
	if findings[1].Metadata["api_version"] != "gateway.networking.k8s.io/v1" {
		t.Fatalf("gateway metadata was not normalized: %+v", findings[1].Metadata)
	}
}

func TestFindingsRejectsUnsafeKubernetesTLSResources(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "unsupported kind",
			raw:  json.RawMessage(`{"resources":[{"kind":"Service","namespace":"payments","name":"web","tls_secret_name":"tls","hosts":["payments.example.com"],"auto_issue":true}]}`),
		},
		{
			name: "host is not dns",
			raw:  json.RawMessage(`{"resources":[{"kind":"Ingress","namespace":"payments","name":"web","tls_secret_name":"tls","hosts":["localhost"],"auto_issue":true}]}`),
		},
		{
			name: "auto issue disabled",
			raw:  json.RawMessage(`{"resources":[{"kind":"Ingress","namespace":"payments","name":"web","tls_secret_name":"tls","hosts":["payments.example.com"],"auto_issue":false}]}`),
		},
		{
			name: "invalid secret name",
			raw:  json.RawMessage(`{"resources":[{"kind":"Ingress","namespace":"payments","name":"web","tls_secret_name":"TLS","hosts":["payments.example.com"],"auto_issue":true}]}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Findings(tt.raw); err == nil {
				t.Fatal("Findings accepted unsafe Kubernetes TLS resource")
			}
		})
	}
}

// A source that binds an in-cluster agent names the agent, the owner of the
// certificates it will request, and optionally the in-cluster listener that
// serves the resources; each finding carries the Secret it delivers into.
func TestDeliverySettingsBindTheClusterAgent(t *testing.T) {
	raw := json.RawMessage(`{
		"cluster_agent_id":"0b9b8a4e-8c1f-4b5e-9d2a-1f0e7c6b5a49",
		"owner_id":"7d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a",
		"verify_address":"ingress-nginx-controller.ingress-nginx.svc:443",
		"resources":[{"kind":"Ingress","namespace":"payments","name":"web","tls_secret_name":"web-tls","hosts":["web.example.test","api.example.test"]}]
	}`)
	delivery, err := DeliverySettings(raw)
	if err != nil {
		t.Fatalf("DeliverySettings: %v", err)
	}
	if delivery.ClusterAgentID != "0b9b8a4e-8c1f-4b5e-9d2a-1f0e7c6b5a49" || delivery.OwnerID != "7d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a" ||
		delivery.VerifyAddress != "ingress-nginx-controller.ingress-nginx.svc:443" {
		t.Fatalf("delivery = %+v", delivery)
	}
	findings, err := Findings(raw)
	if err != nil || len(findings) != 1 {
		t.Fatalf("Findings = %v, %v", findings, err)
	}
	if f := findings[0]; f.Namespace != "payments" || f.TLSSecretName != "web-tls" ||
		len(f.DNSNames) != 2 || f.DNSNames[0] != "web.example.test" {
		t.Fatalf("finding = %+v", f)
	}
	unbound, err := DeliverySettings(json.RawMessage(`{"resources":[{"kind":"Ingress","namespace":"payments","name":"web","tls_secret_name":"web-tls","hosts":["web.example.test"]}]}`))
	if err != nil || unbound.ClusterAgentID != "" {
		t.Fatalf("a source without an agent = %+v, %v", unbound, err)
	}
}

func TestDeliverySettingsRefuseIncompleteBindings(t *testing.T) {
	resource := `"resources":[{"kind":"Ingress","namespace":"payments","name":"web","tls_secret_name":"web-tls","hosts":["web.example.test"]}]`
	for name, raw := range map[string]string{
		"agent without owner":   `{"cluster_agent_id":"0b9b8a4e-8c1f-4b5e-9d2a-1f0e7c6b5a49",` + resource + `}`,
		"agent not a UUID":      `{"cluster_agent_id":"cluster-agent","owner_id":"7d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a",` + resource + `}`,
		"owner not a UUID":      `{"cluster_agent_id":"0b9b8a4e-8c1f-4b5e-9d2a-1f0e7c6b5a49","owner_id":"payments-team",` + resource + `}`,
		"verify without a port": `{"cluster_agent_id":"0b9b8a4e-8c1f-4b5e-9d2a-1f0e7c6b5a49","owner_id":"7d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a","verify_address":"ingress.svc",` + resource + `}`,
	} {
		if _, err := DeliverySettings(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := ValidateConfig(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: source config validation accepted it", name)
		}
	}
}
