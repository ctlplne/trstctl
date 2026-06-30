package pqcmigration

import (
	"fmt"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	TargetMLDSA65      = string(crypto.MLDSA65)
	EffectiveHybridTLS = crypto.HybridMLDSA44ECDSAP256Algorithm
	ProtocolACME       = "acme"
)

type Asset struct {
	ID                string
	Kind              string
	Location          string
	Algorithm         string
	KeyBits           int
	Protocol          string
	Cipher            string
	Library           string
	Strength          string
	QuantumVulnerable bool
	OutOfPolicy       bool
	Reasons           []string
}

type Request struct {
	AssetIDs          []string
	TargetAlgorithm   string
	Protocol          string
	RollbackOnFailure bool
}

type Reissue struct {
	Asset              Asset
	TargetAlgorithm    string
	EffectiveAlgorithm string
	Protocol           string
	RollbackOnFailure  bool
}

type Plan struct {
	Reissues  []Reissue
	Residuals []Residual
}

type Residual struct {
	ID     string
	Status string
	Reason string
}

type AssetNotFoundError struct {
	ID string
}

func (e AssetNotFoundError) Error() string {
	return fmt.Sprintf("pqcmigration: asset %s not found", e.ID)
}

func BuildPlan(assets []Asset, req Request) (Plan, error) {
	protocol := req.Protocol
	if protocol == "" {
		protocol = ProtocolACME
	}
	if req.TargetAlgorithm != TargetMLDSA65 {
		return Plan{}, fmt.Errorf("pqcmigration: certificate-key migration target must be %s", TargetMLDSA65)
	}
	if protocol != ProtocolACME {
		return Plan{}, fmt.Errorf("pqcmigration: certificate-key migration protocol must be %s", ProtocolACME)
	}
	byID := make(map[string]Asset, len(assets))
	for _, asset := range assets {
		byID[asset.ID] = asset
	}
	plan := Plan{Residuals: ResidualDenominator()}
	for _, id := range req.AssetIDs {
		asset, ok := byID[id]
		if !ok {
			return Plan{}, AssetNotFoundError{ID: id}
		}
		if asset.Kind != string(cbom.AssetCertKey) {
			return Plan{}, fmt.Errorf("pqcmigration: asset %s is %s, want certificate-key", id, asset.Kind)
		}
		if !asset.QuantumVulnerable {
			return Plan{}, fmt.Errorf("pqcmigration: asset %s is already post-quantum-ready", id)
		}
		plan.Reissues = append(plan.Reissues, Reissue{
			Asset:              cloneAsset(asset),
			TargetAlgorithm:    req.TargetAlgorithm,
			EffectiveAlgorithm: EffectiveHybridTLS,
			Protocol:           protocol,
			RollbackOnFailure:  req.RollbackOnFailure,
		})
	}
	return plan, nil
}

func ResidualDenominator() []Residual {
	return []Residual{
		{
			ID:     "pure_mldsa_subject_certificates",
			Status: "not_served",
			Reason: "stock X.509 clients still require classical subject public keys; the served path uses a hybrid transition leaf with an ML-DSA binding",
		},
		{
			ID:     "spiffe_multi_key_workload_response",
			Status: "not_served",
			Reason: "the served SPIFFE Workload API returns the standard single private key per X509-SVID response; hybrid multi-key SVID delivery remains protocol/client work",
		},
		{
			ID:     "fleetwide_tls_cipher_rollout",
			Status: "not_served",
			Reason: "CBOM TLS protocol and cipher findings are classified and targeted, but automatic deployment rollout is served first for certificate-key assets",
		},
	}
}

func cloneAsset(asset Asset) Asset {
	asset.Reasons = append([]string(nil), asset.Reasons...)
	return asset
}
