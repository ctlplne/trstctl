// SPDX-License-Identifier: BUSL-1.1

// Package license implements trstctl's offline edition checks.
//
// The package deliberately lives in core so "no phone-home" licensing is
// auditable: a configured license file is verified locally against public keys
// baked into the binary at release time. No license file means Community. A
// configured but corrupt or untrusted file fails startup loudly. An expired file
// loads and walks the grace ladder so commercial read paths remain observable.
package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// Tier names an edition.
type Tier string

const (
	TierCommunity  Tier = "community"
	TierEnterprise Tier = "enterprise"
	TierProvider   Tier = "provider"
)

// Feature is a license-gated capability.
type Feature string

const (
	// FeatureFIPS is documented in the Enterprise row as an artifact-gated
	// distribution posture. Runtime code must report FIPS posture through
	// internal/crypto, not branch on Manager.Has(FeatureFIPS).
	FeatureFIPS            Feature = "fips"
	FeatureRemediation     Feature = "remediation"
	FeatureHASupport       Feature = "ha_support"
	FeatureBYOK            Feature = "byok"
	FeatureGovernance      Feature = "governance"
	FeatureProviderPlane   Feature = "provider_plane"
	FeatureMetering        Feature = "metering"
	FeatureWhiteLabel      Feature = "white_label"
	FeatureSiloedIsolation Feature = "siloed_isolation"
)

// tierFeatures is the only feature-to-tier table in the codebase. The core
// families (PCAS, AGID, XREC, VDEC) and PQC are not features: they ship in the
// BSL core and attach in every build (cmd/trstctl/attach_families.go).
var tierFeatures = map[Tier][]Feature{
	TierEnterprise: {FeatureFIPS, FeatureRemediation, FeatureHASupport, FeatureBYOK, FeatureGovernance},
	TierProvider:   {FeatureProviderPlane, FeatureMetering, FeatureWhiteLabel, FeatureSiloedIsolation},
}

var tierOrder = []Tier{TierEnterprise, TierProvider}

// tierParents defines edition inheritance. Provider is the MSP/resale tier, so
// one Provider license unlocks every Enterprise feature plus Provider-only
// control-plane features. Keep inheritance here beside the feature-to-tier table
// so attachEE remains the single activation seam (AN-9).
var tierParents = map[Tier][]Tier{
	TierProvider: {TierEnterprise},
}

// Right is a commercial use permission derived from the signed tier. It is not
// a separately editable claim: changing the use rights requires issuing a new
// signed license with a different tier.
type Right string

const (
	RightSelfHost       Right = "self_host"
	RightManagedService Right = "managed_service"
	RightResale         Right = "resale"
)

// tierRights is the single tier-to-use-rights table. The core remains usable
// under its repository license (BUSL-1.1); these rows describe the supported product motion
// and the commercial ee/ rights carried by a signed tier. Provider adds the right
// to operate the commercial feature set for customers and resell that service.
var tierRights = map[Tier][]Right{
	TierCommunity:  {RightSelfHost},
	TierEnterprise: {RightSelfHost},
	TierProvider:   {RightSelfHost, RightManagedService, RightResale},
}

// TierFeatures returns a copy of the feature set for a tier.
func TierFeatures(t Tier) []Feature {
	return append([]Feature(nil), tierFeatures[t]...)
}

// EffectiveTierFeatures returns direct and inherited features for a tier.
func EffectiveTierFeatures(t Tier) []Feature {
	var out []Feature
	seen := make(map[Feature]struct{})
	var addTier func(Tier)
	addTier = func(current Tier) {
		for _, parent := range tierParents[current] {
			addTier(parent)
		}
		for _, feature := range tierFeatures[current] {
			if _, ok := seen[feature]; ok {
				continue
			}
			seen[feature] = struct{}{}
			out = append(out, feature)
		}
	}
	addTier(t)
	return out
}

// TierRights returns a copy of the commercial use rights for a tier.
func TierRights(t Tier) []Right {
	return append([]Right(nil), tierRights[t]...)
}

// AllFeatures returns every table feature in stable tier declaration order.
func AllFeatures() []Feature {
	var out []Feature
	for _, tier := range tierOrder {
		out = append(out, tierFeatures[tier]...)
	}
	return out
}

// FeatureTier returns the default tier that grants f, or Community when f is
// only an explicit extra or is unknown to the current table.
func FeatureTier(f Feature) Tier {
	for _, tier := range tierOrder {
		for _, granted := range tierFeatures[tier] {
			if granted == f {
				return tier
			}
		}
	}
	return TierCommunity
}

// Environment names the production meaning of one control-plane deployment.
type Environment string

const (
	EnvironmentProduction    Environment = "production"
	EnvironmentNonProduction Environment = "non_production"
)

// BundledNonProductionDeployments is the public Enterprise/Provider promise.
// Keep the signed-claim validator, editions API, console, and editions docs pinned
// to this one constant so the product cannot sell three while enforcing two.
const BundledNonProductionDeployments = 3

// DeploymentEntitlement is signed into a version 2 license. Explicit IDs make
// the offline allowance mechanically bounded without a phone-home counter.
type DeploymentEntitlement struct {
	ProductionDeploymentID     string   `json:"production_deployment_id"`
	NonProductionDeploymentIDs []string `json:"non_production_deployment_ids,omitempty"`
	NonProductionAllowance     int      `json:"non_production_allowance"`
}

// DeploymentIdentity is operator-owned runtime posture. A version 2 license is
// usable only when both fields match one signed slot.
type DeploymentIdentity struct {
	ID          string      `json:"deployment_id"`
	Environment Environment `json:"environment"`
}

// Claims is the signed license payload. Version 1 licenses predate deployment
// binding and remain loadable as production-only compatibility licenses.
// Version 2 signs one production control plane and the explicitly named
// non-production control planes that share its commercial entitlement.
type Claims struct {
	V                     int                    `json:"v"`
	ID                    string                 `json:"id"`
	Customer              string                 `json:"customer"`
	Tier                  Tier                   `json:"tier"`
	Features              []Feature              `json:"features,omitempty"`
	TenantBand            int                    `json:"tenant_band,omitempty"`
	DeploymentEntitlement *DeploymentEntitlement `json:"environment_entitlement,omitempty"`
	IssuedAt              time.Time              `json:"issued_at"`
	ExpiresAt             time.Time              `json:"expires_at"`
}

// File is the on-disk envelope: exact base64 payload bytes and a detached
// Ed25519 signature over those bytes.
type File struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// GracePeriod is the full-function window after expiry before commercial
// features degrade to read-only.
const GracePeriod = 30 * 24 * time.Hour

// State is the license lifecycle.
type State string

const (
	StateCommunity State = "community"
	StateActive    State = "active"
	StateGrace     State = "grace"
	StateReadOnly  State = "read_only"
)

// Mode is one feature's effective enforcement posture.
type Mode string

const (
	ModeEnabled  Mode = "enabled"
	ModeReadOnly Mode = "read_only"
	ModeOff      Mode = "off"
)

// Manager answers edition questions for one loaded license. It is immutable
// after construction; tests replace clock to prove the grace ladder.
type Manager struct {
	claims        *Claims
	clock         func() time.Time
	deployment    *DeploymentIdentity
	legacyUnbound bool
}

// Community returns the keyless/default-open manager.
func Community() *Manager {
	return &Manager{clock: time.Now}
}

// Verify validates a license file against trusted PEM public keys and returns
// signed claims. Ed25519 verification routes through internal/crypto.
func Verify(raw []byte, trustedPubPEMs [][]byte) (*Claims, error) {
	if len(trustedPubPEMs) == 0 {
		return nil, fmt.Errorf("license: no trusted license keys are baked into this build")
	}
	var file File
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("license: malformed license file: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(file.Payload)
	if err != nil {
		return nil, fmt.Errorf("license: malformed payload encoding: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(file.Signature)
	if err != nil {
		return nil, fmt.Errorf("license: malformed signature encoding: %w", err)
	}
	verified := false
	for _, pemBytes := range trustedPubPEMs {
		pubDER, err := crypto.ParseEd25519PublicKeyPEM(pemBytes)
		if err != nil {
			continue
		}
		if err := crypto.VerifyEd25519(pubDER, payload, sig); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("license: signature verification failed")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("license: malformed claims: %w", err)
	}
	if err := validateClaims(claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func validateClaims(claims Claims) error {
	if claims.V != 1 && claims.V != 2 {
		return fmt.Errorf("license: unsupported license version %d", claims.V)
	}
	if claims.Tier != TierEnterprise && claims.Tier != TierProvider {
		return fmt.Errorf("license: unknown tier %q", claims.Tier)
	}
	if claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) {
		return fmt.Errorf("license: invalid validity window")
	}
	if claims.TenantBand < 0 {
		return fmt.Errorf("license: managed customer band cannot be negative")
	}
	if claims.V == 1 {
		if claims.DeploymentEntitlement != nil {
			return fmt.Errorf("license: version 1 cannot carry a deployment entitlement")
		}
		return nil
	}
	if err := validateDeploymentEntitlement(claims.DeploymentEntitlement); err != nil {
		return err
	}
	return nil
}

// ValidateClaims applies the same strict schema checks used after signature
// verification. The vendor-side helper calls it before signing so it cannot mint
// an unusable or over-allocated file and discover that only at customer startup.
func ValidateClaims(claims Claims) error {
	return validateClaims(claims)
}

func validateDeploymentEntitlement(entitlement *DeploymentEntitlement) error {
	if entitlement == nil {
		return fmt.Errorf("license: version 2 requires an environment entitlement")
	}
	if err := validateDeploymentID(entitlement.ProductionDeploymentID); err != nil {
		return fmt.Errorf("license: production deployment id: %w", err)
	}
	if entitlement.NonProductionAllowance != BundledNonProductionDeployments {
		return fmt.Errorf("license: non-production allowance must be %d", BundledNonProductionDeployments)
	}
	if len(entitlement.NonProductionDeploymentIDs) > entitlement.NonProductionAllowance {
		return fmt.Errorf("license: %d non-production deployments exceed allowance %d", len(entitlement.NonProductionDeploymentIDs), entitlement.NonProductionAllowance)
	}
	seen := map[string]struct{}{entitlement.ProductionDeploymentID: {}}
	for _, id := range entitlement.NonProductionDeploymentIDs {
		if err := validateDeploymentID(id); err != nil {
			return fmt.Errorf("license: non-production deployment id: %w", err)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("license: deployment id %q is duplicated across environment slots", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateDeploymentID(id string) error {
	if id == "" {
		return fmt.Errorf("deployment id is required")
	}
	if len(id) > 128 || id != strings.TrimSpace(id) {
		return fmt.Errorf("must be 1-128 trimmed ASCII letters, digits, dot, underscore, colon, or hyphen")
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return fmt.Errorf("must be 1-128 trimmed ASCII letters, digits, dot, underscore, colon, or hyphen")
	}
	return nil
}

// Load reads and verifies a configured license. Empty path is Community.
func Load(path string, trustedPubPEMs [][]byte) (*Manager, error) {
	if path == "" {
		return Community(), nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied license file path (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("license: read %s: %w", path, err)
	}
	claims, err := Verify(raw, trustedPubPEMs)
	if err != nil {
		return nil, err
	}
	return &Manager{claims: claims, clock: time.Now}, nil
}

// LoadForDeployment verifies a license and binds it to the operator-declared
// runtime identity. Version 2 fails closed unless the ID and environment match a
// signed slot. Version 1 remains production-only so an upgrade does not brick an
// existing paid deployment while also never inventing a non-production right.
func LoadForDeployment(path string, trustedPubPEMs [][]byte, identity DeploymentIdentity) (*Manager, error) {
	manager, err := Load(path, trustedPubPEMs)
	if err != nil {
		return nil, err
	}
	if manager.claims == nil {
		return manager, nil
	}
	if manager.claims.V == 1 {
		if identity.Environment == "" {
			identity.Environment = EnvironmentProduction
		}
		if identity.Environment != EnvironmentProduction {
			return nil, fmt.Errorf("license: version 1 licenses are production-only; issue a bound version 2 license for non-production")
		}
		if identity.ID != "" {
			if err := validateDeploymentID(identity.ID); err != nil {
				return nil, fmt.Errorf("license: deployment id: %w", err)
			}
		}
		manager.deployment = &identity
		manager.legacyUnbound = true
		return manager, nil
	}
	if err := validateDeploymentID(identity.ID); err != nil {
		return nil, fmt.Errorf("license: deployment id: %w", err)
	}
	if identity.Environment != EnvironmentProduction && identity.Environment != EnvironmentNonProduction {
		return nil, fmt.Errorf("license: environment must be production or non_production")
	}
	entitlement := manager.claims.DeploymentEntitlement
	switch identity.Environment {
	case EnvironmentProduction:
		if identity.ID != entitlement.ProductionDeploymentID {
			return nil, fmt.Errorf("license: deployment id %q does not match licensed production deployment", identity.ID)
		}
	case EnvironmentNonProduction:
		matched := false
		for _, id := range entitlement.NonProductionDeploymentIDs {
			if identity.ID == id {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("license: deployment id %q is not licensed as non-production", identity.ID)
		}
	}
	manager.deployment = &identity
	return manager, nil
}

// Sign serializes claims and signs the exact payload bytes with a PEM Ed25519
// private key. It is used by the vendor-side trstctl-license tool and tests.
func Sign(claims Claims, privPEM []byte) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("license: marshal claims: %w", err)
	}
	sig, err := crypto.SignEd25519(privPEM, payload)
	if err != nil {
		return nil, fmt.Errorf("license: sign: %w", err)
	}
	file := File{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	return json.MarshalIndent(file, "", "  ")
}

// State reports the lifecycle state at the manager's clock.
func (m *Manager) State() State {
	if m == nil || m.claims == nil {
		return StateCommunity
	}
	now := m.clock()
	if now.Before(m.claims.ExpiresAt) {
		return StateActive
	}
	if now.Before(m.claims.ExpiresAt.Add(GracePeriod)) {
		return StateGrace
	}
	return StateReadOnly
}

// Tier returns the current tier, Community when unlicensed.
func (m *Manager) Tier() Tier {
	if m == nil || m.claims == nil {
		return TierCommunity
	}
	return m.claims.Tier
}

func (m *Manager) granted(f Feature) bool {
	if m == nil || m.claims == nil {
		return false
	}
	for _, granted := range EffectiveTierFeatures(m.claims.Tier) {
		if granted == f {
			return true
		}
	}
	for _, granted := range m.claims.Features {
		if granted == f {
			return true
		}
	}
	return false
}

// Rights returns commercial use rights derived from the signed tier.
func (m *Manager) Rights() []Right {
	return TierRights(m.Tier())
}

// Mode returns f's effective posture.
func (m *Manager) Mode(f Feature) Mode {
	if !m.granted(f) {
		return ModeOff
	}
	if m.State() == StateReadOnly {
		return ModeReadOnly
	}
	return ModeEnabled
}

// Has reports whether f is licensed at all. Read-only still counts as present
// so attach seams can construct read paths for expired licenses.
func (m *Manager) Has(f Feature) bool {
	return m.Mode(f) != ModeOff
}

// TenantBand returns the licensed tenant count, where zero means unlimited or
// not applicable.
func (m *Manager) TenantBand() int {
	if m == nil || m.claims == nil {
		return 0
	}
	return m.claims.TenantBand
}

// ManagedCustomerBand returns the contracted number of managed customers. A
// Provider normally serves those customers as tenants in one shared control
// plane, but the commercial band does not change when dedicated deployments are
// used. Zero means the band is unlimited or governed by negotiated terms.
func (m *Manager) ManagedCustomerBand() int {
	if m.Tier() != TierProvider {
		return 0
	}
	return m.TenantBand()
}

// FeatureInfo is one Editions view row.
type FeatureInfo struct {
	Name     Feature `json:"name"`
	Tier     Tier    `json:"tier"`
	Licensed bool    `json:"licensed"`
	Mode     Mode    `json:"mode"`
}

// Info is the operator-visible Editions payload.
type Info struct {
	Tier                  Tier                       `json:"tier"`
	State                 State                      `json:"state"`
	Customer              string                     `json:"customer,omitempty"`
	LicenseID             string                     `json:"license_id,omitempty"`
	ExpiresAt             *time.Time                 `json:"expires_at,omitempty"`
	ReadOnlyAt            *time.Time                 `json:"read_only_at,omitempty"`
	TenantBand            int                        `json:"tenant_band,omitempty"`
	ManagedCustomerBand   int                        `json:"managed_customer_band,omitempty"`
	Rights                []Right                    `json:"rights"`
	Features              []FeatureInfo              `json:"features"`
	DeploymentEntitlement *DeploymentEntitlementInfo `json:"deployment_entitlement,omitempty"`
}

// DeploymentEntitlementInfo is the effective, safe-to-serve result of matching
// runtime configuration to the signed deployment bundle.
type DeploymentEntitlementInfo struct {
	DeploymentID                       string      `json:"deployment_id,omitempty"`
	Environment                        Environment `json:"environment"`
	ProductionUnitsConsumed            int         `json:"production_units_consumed"`
	BundledNonProductionDeployments    int         `json:"bundled_non_production_deployments"`
	RegisteredNonProductionDeployments int         `json:"registered_non_production_deployments"`
	NonProductionSlotsRemaining        int         `json:"non_production_slots_remaining"`
	LegacyUnbound                      bool        `json:"legacy_unbound"`
}

// Info renders the current license truth.
func (m *Manager) Info() Info {
	info := Info{Tier: m.Tier(), State: m.State(), Rights: m.Rights(), Features: []FeatureInfo{}}
	if m != nil && m.claims != nil {
		info.Customer = m.claims.Customer
		info.LicenseID = m.claims.ID
		exp := m.claims.ExpiresAt
		ro := exp.Add(GracePeriod)
		info.ExpiresAt = &exp
		info.ReadOnlyAt = &ro
		info.TenantBand = m.claims.TenantBand
		info.ManagedCustomerBand = m.ManagedCustomerBand()
		if m.deployment != nil {
			posture := &DeploymentEntitlementInfo{
				DeploymentID:  m.deployment.ID,
				Environment:   m.deployment.Environment,
				LegacyUnbound: m.legacyUnbound,
			}
			if m.deployment.Environment == EnvironmentProduction {
				posture.ProductionUnitsConsumed = 1
			}
			if m.claims.DeploymentEntitlement != nil {
				posture.BundledNonProductionDeployments = BundledNonProductionDeployments
				posture.RegisteredNonProductionDeployments = len(m.claims.DeploymentEntitlement.NonProductionDeploymentIDs)
				posture.NonProductionSlotsRemaining = m.claims.DeploymentEntitlement.NonProductionAllowance - posture.RegisteredNonProductionDeployments
			}
			info.DeploymentEntitlement = posture
		}
	}
	for _, f := range AllFeatures() {
		info.Features = append(info.Features, FeatureInfo{
			Name:     f,
			Tier:     FeatureTier(f),
			Licensed: m.granted(f),
			Mode:     m.Mode(f),
		})
	}
	return info
}
