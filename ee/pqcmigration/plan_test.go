// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/connector"
)

func TestPQCPlannerTargetsMLDSA65WithHybridEffectiveLeaf(t *testing.T) {
	plan, err := BuildPlan([]Asset{{
		ID: "asset-rsa", Kind: string(cbom.AssetCertKey), Location: "payments.internal:443",
		Algorithm: "RSA", KeyBits: 2048, Strength: "weak", QuantumVulnerable: true,
		Reasons: []string{"RSA is quantum-vulnerable"},
	}}, Request{
		AssetIDs:          []string{"asset-rsa"},
		TargetAlgorithm:   TargetMLDSA65,
		Protocol:          ProtocolACME,
		RollbackOnFailure: true,
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Reissues) != 1 {
		t.Fatalf("reissues = %d, want 1", len(plan.Reissues))
	}
	got := plan.Reissues[0]
	if got.TargetAlgorithm != TargetMLDSA65 || got.EffectiveAlgorithm != EffectiveHybridTLS || got.Protocol != ProtocolACME {
		t.Fatalf("reissue target/effective/protocol = %q/%q/%q", got.TargetAlgorithm, got.EffectiveAlgorithm, got.Protocol)
	}
	if !got.RollbackOnFailure || got.Asset.ID != "asset-rsa" || got.Asset.Reasons[0] != "RSA is quantum-vulnerable" {
		t.Fatalf("reissue payload lost asset/rollback evidence: %+v", got)
	}
}

func TestMLDSAPlannerRejectsUnsupportedOrAlreadyReadyAssets(t *testing.T) {
	_, err := BuildPlan([]Asset{{ID: "tls-1", Kind: string(cbom.AssetTLSEndpoint), QuantumVulnerable: true}}, Request{
		AssetIDs:        []string{"tls-1"},
		TargetAlgorithm: TargetMLDSA65,
		Protocol:        ProtocolACME,
	})
	if err == nil {
		t.Fatal("BuildPlan accepted a TLS protocol finding as certificate-key reissue work")
	}

	_, err = BuildPlan([]Asset{{ID: "mldsa-1", Kind: string(cbom.AssetCertKey), Algorithm: TargetMLDSA65}}, Request{
		AssetIDs:        []string{"mldsa-1"},
		TargetAlgorithm: TargetMLDSA65,
		Protocol:        ProtocolACME,
	})
	if err == nil {
		t.Fatal("BuildPlan accepted an already PQ-ready asset")
	}

	_, err = BuildPlan(nil, Request{
		AssetIDs:        []string{"missing"},
		TargetAlgorithm: TargetMLDSA65,
		Protocol:        ProtocolACME,
	})
	var notFound AssetNotFoundError
	if !errors.As(err, &notFound) || notFound.ID != "missing" {
		t.Fatalf("missing asset error = %v, want AssetNotFoundError", err)
	}
}

func TestPlannerBindsEverySelectedProtocolAndCipherFinding(t *testing.T) {
	desired := connector.TLSPosture{
		MinimumVersion:    connector.TLSVersion13,
		CipherSuites:      []string{"TLS_AES_256_GCM_SHA384"},
		KeyExchangeGroups: []string{HybridTLSGroup, "X25519"},
	}
	plan, err := BuildPlan([]Asset{
		{ID: "protocol-1", Kind: string(cbom.AssetTLSEndpoint), Location: "edge:443", Protocol: "TLSv1.0", Strength: "broken", QuantumVulnerable: true, OutOfPolicy: true},
		{ID: "cipher-1", Kind: string(cbom.AssetHostConfig), Location: "/etc/envoy.yaml", Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Strength: "broken", QuantumVulnerable: true, OutOfPolicy: true},
	}, Request{
		AssetIDs: []string{"protocol-1", "cipher-1"}, TargetAlgorithm: TargetMLDSA65, Protocol: ProtocolACME,
		TLSBindings: []TLSBinding{
			{AssetID: "protocol-1", TargetID: "envoy-edge", Desired: desired},
			{AssetID: "cipher-1", TargetID: "envoy-edge", Desired: desired},
		},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.TLSRollouts) != 2 || len(plan.Reissues) != 0 {
		t.Fatalf("plan = %+v, want two TLS rollouts and no certificate reissue", plan)
	}
	if plan.TLSRollouts[0].FindingKind != "protocol" || plan.TLSRollouts[1].FindingKind != "cipher" {
		t.Fatalf("finding kinds = %q/%q, want protocol/cipher", plan.TLSRollouts[0].FindingKind, plan.TLSRollouts[1].FindingKind)
	}

	_, err = BuildPlan([]Asset{{
		ID: "protocol-1", Kind: string(cbom.AssetTLSEndpoint), Protocol: "TLSv1.0", QuantumVulnerable: true,
	}}, Request{AssetIDs: []string{"protocol-1"}, TargetAlgorithm: TargetMLDSA65, Protocol: ProtocolACME})
	if err == nil {
		t.Fatal("planner accepted an unbound selected TLS finding")
	}
	bad := desired
	bad.KeyExchangeGroups = []string{"X25519"}
	_, err = BuildPlan([]Asset{{
		ID: "protocol-1", Kind: string(cbom.AssetTLSEndpoint), Protocol: "TLSv1.0", QuantumVulnerable: true,
	}}, Request{
		AssetIDs: []string{"protocol-1"}, TargetAlgorithm: TargetMLDSA65, Protocol: ProtocolACME,
		TLSBindings: []TLSBinding{{AssetID: "protocol-1", TargetID: "envoy-edge", Desired: bad}},
	})
	if err == nil {
		t.Fatal("planner accepted a desired posture without the hybrid ML-KEM group")
	}

	conflicting := desired
	conflicting.CipherSuites = []string{"TLS_CHACHA20_POLY1305_SHA256"}
	_, err = BuildPlan([]Asset{
		{ID: "protocol-1", Kind: string(cbom.AssetTLSEndpoint), Protocol: "TLSv1.0", QuantumVulnerable: true},
		{ID: "cipher-1", Kind: string(cbom.AssetHostConfig), Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", QuantumVulnerable: true},
	}, Request{
		AssetIDs: []string{"protocol-1", "cipher-1"}, TargetAlgorithm: TargetMLDSA65, Protocol: ProtocolACME,
		TLSBindings: []TLSBinding{
			{AssetID: "protocol-1", TargetID: "envoy-edge", Desired: desired},
			{AssetID: "cipher-1", TargetID: "envoy-edge", Desired: conflicting},
		},
	})
	if err == nil {
		t.Fatal("planner accepted conflicting desired postures for findings sharing one target")
	}
}

func TestCompletedCapabilitiesLeaveOnlyEvidenceGatedPureCutoverResidual(t *testing.T) {
	residuals := ResidualDenominator()
	var sawCutover bool
	for _, residual := range residuals {
		switch residual.ID {
		case "pure_mldsa_subject_certificates", "spiffe_multi_key_workload_response", "fleetwide_tls_cipher_rollout":
			t.Fatalf("completed capability remains falsely listed as residual: %+v", residual)
		case "hybrid_to_pure_pqc_cutover":
			sawCutover = residual.Status == "planned_gated"
		}
	}
	if !sawCutover {
		t.Fatal("residual denominator must retain the evidence-gated hybrid-to-pure cutover")
	}
}
