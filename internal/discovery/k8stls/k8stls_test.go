// SPDX-License-Identifier: MPL-2.0

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
