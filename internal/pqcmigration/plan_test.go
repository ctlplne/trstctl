package pqcmigration

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
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

func TestSPIFFEMultiKeyResidualStaysExplicit(t *testing.T) {
	residuals := ResidualDenominator()
	var sawSPIFFE, sawPureMLDSA bool
	for _, residual := range residuals {
		if residual.ID == "spiffe_multi_key_workload_response" && residual.Status == "not_served" {
			sawSPIFFE = true
		}
		if residual.ID == "pure_mldsa_subject_certificates" && residual.Status == "not_served" {
			sawPureMLDSA = true
		}
	}
	if !sawSPIFFE {
		t.Fatal("residual denominator must keep SPIFFE multi-key response honest")
	}
	if !sawPureMLDSA {
		t.Fatal("residual denominator must keep pure ML-DSA subject certificates honest")
	}
}
