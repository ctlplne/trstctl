// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/connector"
)

func TestPQCPlannerTargetsHostMLDSA65WithExactObservedPredecessor(t *testing.T) {
	plan, err := BuildPlan([]Asset{{
		ID: "asset-rsa", Kind: string(cbom.AssetCertKey), Location: "payments.internal:443",
		CertificateFingerprint: strings.Repeat("a", 64),
		Algorithm:              "RSA", KeyBits: 2048, Strength: "weak", QuantumVulnerable: true,
		Reasons: []string{"RSA is quantum-vulnerable"},
	}}, Request{
		AssetIDs:            []string{"asset-rsa"},
		TargetAlgorithm:     TargetMLDSA65,
		Protocol:            ProtocolHostCSR,
		RollbackOnFailure:   true,
		CertificateBindings: []CertificateBinding{{AssetID: "asset-rsa", IdentityID: "identity-a", TargetID: "target-a"}},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Reissues) != 1 {
		t.Fatalf("reissues = %d, want 1", len(plan.Reissues))
	}
	got := plan.Reissues[0]
	if got.TargetAlgorithm != TargetMLDSA65 || got.EffectiveAlgorithm != TargetMLDSA65 || got.Protocol != ProtocolHostCSR {
		t.Fatalf("reissue target/effective/protocol = %q/%q/%q", got.TargetAlgorithm, got.EffectiveAlgorithm, got.Protocol)
	}
	if !got.RollbackOnFailure || got.Asset.ID != "asset-rsa" || got.IdentityID != "identity-a" || got.TargetID != "target-a" || got.Asset.Reasons[0] != "RSA is quantum-vulnerable" {
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
		KeyExchangeGroups: []string{HybridTLSGroup, "X25519"},
	}
	if raw, err := json.Marshal(clonePosture(desired)); err != nil || !bytes.Contains(raw, []byte(`"cipher_suites":[]`)) {
		t.Fatalf("TLS 1.3 unmanaged cipher list must stay an empty array on the wire: %s %v", raw, err)
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
	claimedCipher := desired
	claimedCipher.CipherSuites = []string{"TLS_AES_256_GCM_SHA384"}
	_, err = BuildPlan([]Asset{{
		ID: "protocol-1", Kind: string(cbom.AssetTLSEndpoint), Protocol: "TLSv1.0", QuantumVulnerable: true,
	}}, Request{
		AssetIDs: []string{"protocol-1"}, TargetAlgorithm: TargetMLDSA65, Protocol: ProtocolACME,
		TLSBindings: []TLSBinding{{AssetID: "protocol-1", TargetID: "envoy-edge", Desired: claimedCipher}},
	})
	if err == nil {
		t.Fatal("planner claimed an Envoy TLS 1.3 cipher-suite restriction it cannot enforce")
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

func TestPlannerAcceptsObservedTLS12CompatibilityForExplicitPQCPosture(t *testing.T) {
	desired := connector.TLSPosture{MinimumVersion: connector.TLSVersion13,
		KeyExchangeGroups: []string{HybridTLSGroup}}
	plan, err := BuildPlan([]Asset{{ID: "observed-tls12", Kind: string(cbom.AssetTLSEndpoint),
		Location: "edge:443", Protocol: "TLSv1.2", Strength: "acceptable"}}, Request{
		AssetIDs: []string{"observed-tls12"}, TargetAlgorithm: TargetMLDSA65,
		TLSBindings: []TLSBinding{{AssetID: "observed-tls12", TargetID: "envoy-edge", Desired: desired}},
	})
	if err != nil || len(plan.TLSRollouts) != 1 {
		t.Fatalf("observed TLS 1.2 compatibility path should be actionable: plan=%+v err=%v", plan, err)
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
			sawCutover = residual.Status == "acknowledgment_gated"
		}
	}
	if !sawCutover {
		t.Fatal("residual denominator must retain the evidence-gated hybrid-to-pure cutover")
	}
}

// Every ML-DSA parameter set is a host-bound target (A37); key-establishment
// and classical labels are not certificate-key targets.
func TestPQCPlannerAcceptsEveryMLDSAParameterSet(t *testing.T) {
	asset := Asset{ID: "asset-rsa", Kind: string(cbom.AssetCertKey), Location: "payments.internal:443",
		CertificateFingerprint: strings.Repeat("a", 64), Algorithm: "RSA", KeyBits: 2048, Strength: "weak", QuantumVulnerable: true}
	request := func(target string) Request {
		return Request{AssetIDs: []string{"asset-rsa"}, TargetAlgorithm: target, Protocol: ProtocolHostCSR,
			CertificateBindings: []CertificateBinding{{AssetID: "asset-rsa", IdentityID: "identity-a", TargetID: "target-a"}}}
	}
	for _, target := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		plan, err := BuildPlan([]Asset{asset}, request(target))
		if err != nil || len(plan.Reissues) != 1 || plan.Reissues[0].TargetAlgorithm != target || plan.Reissues[0].EffectiveAlgorithm != target {
			t.Fatalf("%s: plan=%+v err=%v; want the requested parameter set as target and effective algorithm", target, plan.Reissues, err)
		}
	}
	for _, target := range []string{"ML-KEM-768", "ECDSA-P256", "SLH-DSA-SHA2-128s", ""} {
		if _, err := BuildPlan([]Asset{asset}, request(target)); err == nil || !strings.Contains(err.Error(), "ML-DSA") {
			t.Fatalf("%q was accepted as a certificate-key target: %v", target, err)
		}
	}
}

// A217: a hybrid composite leaf is not quantum-vulnerable but still carries a
// classical component, so a pure ML-DSA target plans it as a cutover; a leaf
// that is already pure post-quantum still has nothing to migrate.
func TestPQCPlannerPlansAHybridLeafAsAnAcknowledgmentGatedCutover(t *testing.T) {
	binding := func(id string) []CertificateBinding {
		return []CertificateBinding{{AssetID: id, IdentityID: "identity-" + id, TargetID: "target-" + id}}
	}
	hybrid := Asset{ID: "asset-hybrid", Kind: string(cbom.AssetCertKey), Location: "payments.internal:443",
		Algorithm: EffectiveHybridTLS, CertificateFingerprint: strings.Repeat("a", 64), Strength: "strong"}
	plan, err := BuildPlan([]Asset{hybrid}, Request{AssetIDs: []string{hybrid.ID}, TargetAlgorithm: TargetMLDSA65,
		Protocol: ProtocolHostCSR, CertificateBindings: binding(hybrid.ID)})
	if err != nil || len(plan.Reissues) != 1 || !plan.Reissues[0].Cutover || plan.Reissues[0].EffectiveAlgorithm != TargetMLDSA65 {
		t.Fatalf("hybrid leaf plan = %+v, %v; want one cutover reissue to ML-DSA-65", plan.Reissues, err)
	}
	pure := Asset{ID: "asset-pure", Kind: string(cbom.AssetCertKey), Location: "payments.internal:8443",
		Algorithm: TargetMLDSA65, CertificateFingerprint: strings.Repeat("b", 64), Strength: "strong"}
	if _, err := BuildPlan([]Asset{pure}, Request{AssetIDs: []string{pure.ID}, TargetAlgorithm: TargetMLDSA65,
		Protocol: ProtocolHostCSR, CertificateBindings: binding(pure.ID)}); err == nil || !strings.Contains(err.Error(), "already post-quantum-ready") {
		t.Fatalf("a pure ML-DSA leaf was planned: %v", err)
	}
	classical := Asset{ID: "asset-ecdsa", Kind: string(cbom.AssetCertKey), Location: "payments.internal:9443",
		Algorithm: "ECDSA", QuantumVulnerable: true, CertificateFingerprint: strings.Repeat("c", 64), Strength: "acceptable"}
	plan, err = BuildPlan([]Asset{classical}, Request{AssetIDs: []string{classical.ID}, TargetAlgorithm: TargetMLDSA65,
		Protocol: ProtocolHostCSR, CertificateBindings: binding(classical.ID)})
	if err != nil || len(plan.Reissues) != 1 || plan.Reissues[0].Cutover {
		t.Fatalf("classical leaf plan = %+v, %v; want an ungated reissue", plan.Reissues, err)
	}
}
