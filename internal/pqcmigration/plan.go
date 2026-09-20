// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/connector"
	eepqc "trstctl.com/trstctl/internal/pqc"
)

const (
	TargetMLDSA65      = string(eepqc.MLDSA65)
	EffectiveHybridTLS = eepqc.HybridMLDSA44ECDSAP256Algorithm
	ProtocolACME       = "acme"
	HybridTLSGroup     = "X25519MLKEM768"
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
	TLSBindings       []TLSBinding
}

// TLSBinding is operator-authored intent binding exactly one selected TLS
// protocol/cipher finding to one approved deployment target and desired native
// receiver posture.
type TLSBinding struct {
	AssetID  string
	TargetID string
	Desired  connector.TLSPosture
}

type Reissue struct {
	Asset              Asset
	TargetAlgorithm    string
	EffectiveAlgorithm string
	Protocol           string
	RollbackOnFailure  bool
}

type Plan struct {
	Reissues    []Reissue
	TLSRollouts []TLSRollout
	Residuals   []Residual
}

type TLSRollout struct {
	Asset             Asset
	FindingKind       string
	TargetID          string
	Desired           connector.TLSPosture
	RollbackOnFailure bool
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
	bindings := make(map[string]TLSBinding, len(req.TLSBindings))
	targetPostures := make(map[string]connector.TLSPosture, len(req.TLSBindings))
	for _, binding := range req.TLSBindings {
		if binding.AssetID == "" || binding.TargetID == "" {
			return Plan{}, fmt.Errorf("pqcmigration: TLS binding requires asset_id and target_id")
		}
		if _, duplicate := bindings[binding.AssetID]; duplicate {
			return Plan{}, fmt.Errorf("pqcmigration: TLS finding %s has more than one target binding", binding.AssetID)
		}
		if err := validateDesiredPQCPosture(binding.Desired); err != nil {
			return Plan{}, fmt.Errorf("pqcmigration: TLS binding for %s: %w", binding.AssetID, err)
		}
		if prior, exists := targetPostures[binding.TargetID]; exists && !connector.EqualTLSPosture(prior, binding.Desired) {
			return Plan{}, fmt.Errorf("pqcmigration: findings bound to target %s request conflicting TLS postures", binding.TargetID)
		}
		targetPostures[binding.TargetID] = clonePosture(binding.Desired)
		bindings[binding.AssetID] = binding
	}
	plan := Plan{Residuals: ResidualDenominator()}
	selected := make(map[string]bool, len(req.AssetIDs))
	for _, id := range req.AssetIDs {
		if id == "" || selected[id] {
			return Plan{}, fmt.Errorf("pqcmigration: selected asset ids must be non-empty and unique")
		}
		selected[id] = true
		asset, ok := byID[id]
		if !ok {
			return Plan{}, AssetNotFoundError{ID: id}
		}
		switch asset.Kind {
		case string(cbom.AssetCertKey):
			if _, bound := bindings[id]; bound {
				return Plan{}, fmt.Errorf("pqcmigration: certificate-key asset %s must not have a TLS target binding", id)
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
		case string(cbom.AssetTLSEndpoint), string(cbom.AssetHostConfig):
			if !asset.QuantumVulnerable && !asset.OutOfPolicy {
				return Plan{}, fmt.Errorf("pqcmigration: TLS asset %s is already policy-compliant", id)
			}
			binding, bound := bindings[id]
			if !bound {
				return Plan{}, fmt.Errorf("pqcmigration: selected TLS finding %s has no operator target binding", id)
			}
			kind, err := tlsFindingKind(asset)
			if err != nil {
				return Plan{}, err
			}
			plan.TLSRollouts = append(plan.TLSRollouts, TLSRollout{
				Asset: cloneAsset(asset), FindingKind: kind, TargetID: binding.TargetID,
				Desired: clonePosture(binding.Desired), RollbackOnFailure: req.RollbackOnFailure,
			})
		default:
			return Plan{}, fmt.Errorf("pqcmigration: asset %s has unsupported kind %s", id, asset.Kind)
		}
	}
	for assetID := range bindings {
		if !selected[assetID] {
			return Plan{}, fmt.Errorf("pqcmigration: TLS binding for unselected asset %s is not allowed", assetID)
		}
	}
	if len(plan.Reissues)+len(plan.TLSRollouts) != len(req.AssetIDs) {
		return Plan{}, fmt.Errorf("pqcmigration: every selected asset must produce exactly one migration action")
	}
	return plan, nil
}

func tlsFindingKind(asset Asset) (string, error) {
	hasProtocol := strings.TrimSpace(asset.Protocol) != ""
	hasCipher := strings.TrimSpace(asset.Cipher) != ""
	if hasProtocol == hasCipher {
		return "", fmt.Errorf("pqcmigration: TLS asset %s must describe exactly one protocol or cipher finding", asset.ID)
	}
	if hasProtocol {
		return "protocol", nil
	}
	return "cipher", nil
}

func validateDesiredPQCPosture(posture connector.TLSPosture) error {
	if err := connector.ValidateTLSPosture(posture); err != nil {
		return err
	}
	if posture.MinimumVersion != connector.TLSVersion13 {
		return fmt.Errorf("desired PQC rollout must set minimum_version to %s", connector.TLSVersion13)
	}
	for _, group := range posture.KeyExchangeGroups {
		if strings.EqualFold(group, HybridTLSGroup) {
			return nil
		}
	}
	return fmt.Errorf("desired PQC rollout must include the %s key-exchange group", HybridTLSGroup)
}

func clonePosture(posture connector.TLSPosture) connector.TLSPosture {
	posture.CipherSuites = append([]string(nil), posture.CipherSuites...)
	posture.KeyExchangeGroups = append([]string(nil), posture.KeyExchangeGroups...)
	return posture
}

func ResidualDenominator() []Residual {
	return []Residual{
		{
			ID:     "hybrid_to_pure_pqc_cutover",
			Status: "planned_gated",
			Reason: "succession jobs can target a pure ML-DSA-65 deployment leaf (PostureHybridToPurePQC), but the cutover from the hybrid composite leaf is gated by evidence-based retirement (PCAS-10); the served effective leaf stays hybrid until then",
		},
	}
}

func cloneAsset(asset Asset) Asset {
	asset.Reasons = append([]string(nil), asset.Reasons...)
	return asset
}
