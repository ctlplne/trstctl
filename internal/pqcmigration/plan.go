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
	ProtocolHostCSR    = "host-csr"
	HybridTLSGroup     = "X25519MLKEM768"
)

type Asset struct {
	ID                     string
	CertificateFingerprint string
	Kind                   string
	Location               string
	Algorithm              string
	KeyBits                int
	Protocol               string
	Cipher                 string
	Library                string
	Strength               string
	QuantumVulnerable      bool
	OutOfPolicy            bool
	Reasons                []string
}

type Request struct {
	AssetIDs            []string
	TargetAlgorithm     string
	Protocol            string
	RollbackOnFailure   bool
	TLSBindings         []TLSBinding
	CertificateBindings []CertificateBinding
}

// CertificateBinding joins one observed public key to a tenant-owned identity
// and a host target. The identity supplies owner, profile, issuer and reviewed
// subject choice; the target supplies the exact enrolled host agent and
// independent served-listener address.
type CertificateBinding struct {
	AssetID    string
	IdentityID string
	TargetID   string
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
	IdentityID         string
	TargetID           string
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
	if protocol != ProtocolACME && protocol != ProtocolHostCSR {
		return Plan{}, fmt.Errorf("pqcmigration: migration protocol must be %s or %s", ProtocolACME, ProtocolHostCSR)
	}
	byID := make(map[string]Asset, len(assets))
	for _, asset := range assets {
		byID[asset.ID] = asset
	}
	bindings := make(map[string]TLSBinding, len(req.TLSBindings))
	certBindings := make(map[string]CertificateBinding, len(req.CertificateBindings))
	usedTargets := make(map[string]string, len(req.CertificateBindings))
	for _, binding := range req.CertificateBindings {
		if binding.AssetID == "" || binding.IdentityID == "" || binding.TargetID == "" {
			return Plan{}, fmt.Errorf("pqcmigration: certificate binding requires asset_id, identity_id, and target_id")
		}
		if _, duplicate := certBindings[binding.AssetID]; duplicate {
			return Plan{}, fmt.Errorf("pqcmigration: certificate finding %s has more than one binding", binding.AssetID)
		}
		if first := usedTargets[binding.TargetID]; first != "" {
			return Plan{}, fmt.Errorf("pqcmigration: findings %s and %s cannot change the same certificate target in one run", first, binding.AssetID)
		}
		certBindings[binding.AssetID] = binding
		usedTargets[binding.TargetID] = binding.AssetID
	}
	targetPostures := make(map[string]connector.TLSPosture, len(req.TLSBindings))
	for _, binding := range req.TLSBindings {
		if binding.AssetID == "" || binding.TargetID == "" {
			return Plan{}, fmt.Errorf("pqcmigration: TLS binding requires asset_id and target_id")
		}
		if _, duplicate := bindings[binding.AssetID]; duplicate {
			return Plan{}, fmt.Errorf("pqcmigration: TLS finding %s has more than one target binding", binding.AssetID)
		}
		if first := usedTargets[binding.TargetID]; first != "" {
			return Plan{}, fmt.Errorf("pqcmigration: certificate finding %s and TLS finding %s cannot change the same target in one run", first, binding.AssetID)
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
			binding, bound := certBindings[id]
			if !bound {
				return Plan{}, fmt.Errorf("pqcmigration: certificate-key asset %s has no host identity and target binding", id)
			}
			if asset.CertificateFingerprint == "" {
				return Plan{}, fmt.Errorf("pqcmigration: certificate-key asset %s has no observed leaf fingerprint", id)
			}
			if protocol != "host-csr" {
				return Plan{}, fmt.Errorf("pqcmigration: certificate-key asset %s requires protocol host-csr", id)
			}
			plan.Reissues = append(plan.Reissues, Reissue{
				Asset:              cloneAsset(asset),
				IdentityID:         binding.IdentityID,
				TargetID:           binding.TargetID,
				TargetAlgorithm:    req.TargetAlgorithm,
				EffectiveAlgorithm: TargetMLDSA65,
				Protocol:           protocol,
				RollbackOnFailure:  req.RollbackOnFailure,
			})
		case string(cbom.AssetTLSEndpoint), string(cbom.AssetHostConfig):
			// TLS 1.2 may be allowed by a tenant's general TLS policy, but it
			// cannot negotiate the hybrid ML-KEM key exchange that this explicit
			// PQC rollout asks the target to serve. A confirmed TLS 1.2
			// compatibility path is therefore an actionable migration finding.
			if !asset.QuantumVulnerable && !asset.OutOfPolicy &&
				(asset.Kind != string(cbom.AssetTLSEndpoint) || asset.Protocol != "TLSv1.2") {
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
	for assetID := range certBindings {
		if !selected[assetID] {
			return Plan{}, fmt.Errorf("pqcmigration: certificate binding for unselected asset %s is not allowed", assetID)
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
	if len(posture.CipherSuites) != 0 {
		return fmt.Errorf("desired PQC rollout cannot claim TLS 1.3 cipher-suite enforcement through Envoy")
	}
	for _, group := range posture.KeyExchangeGroups {
		if strings.EqualFold(group, HybridTLSGroup) {
			return nil
		}
	}
	return fmt.Errorf("desired PQC rollout must include the %s key-exchange group", HybridTLSGroup)
}

func clonePosture(posture connector.TLSPosture) connector.TLSPosture {
	posture.CipherSuites = append([]string{}, posture.CipherSuites...)
	posture.KeyExchangeGroups = append([]string{}, posture.KeyExchangeGroups...)
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
