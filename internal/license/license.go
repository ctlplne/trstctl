// Package license implements trstctl's offline open-core edition checks.
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
	FeatureFIPS        Feature = "fips"
	FeatureRemediation Feature = "remediation"
)

// tierFeatures is the only feature-to-tier table in the codebase.
var tierFeatures = map[Tier][]Feature{
	TierEnterprise: {FeatureFIPS, FeatureRemediation},
	TierProvider:   {},
}

var tierOrder = []Tier{TierEnterprise, TierProvider}

// TierFeatures returns a copy of the feature set for a tier.
func TierFeatures(t Tier) []Feature {
	return append([]Feature(nil), tierFeatures[t]...)
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

// Claims is the signed license payload.
type Claims struct {
	V          int       `json:"v"`
	ID         string    `json:"id"`
	Customer   string    `json:"customer"`
	Tier       Tier      `json:"tier"`
	Features   []Feature `json:"features,omitempty"`
	TenantBand int       `json:"tenant_band,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
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
	claims *Claims
	clock  func() time.Time
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
	if claims.V != 1 {
		return fmt.Errorf("license: unsupported license version %d", claims.V)
	}
	if claims.Tier != TierEnterprise && claims.Tier != TierProvider {
		return fmt.Errorf("license: unknown tier %q", claims.Tier)
	}
	if claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) {
		return fmt.Errorf("license: invalid validity window")
	}
	return nil
}

// Load reads and verifies a configured license. Empty path is Community.
func Load(path string, trustedPubPEMs [][]byte) (*Manager, error) {
	if path == "" {
		return Community(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("license: read %s: %w", path, err)
	}
	claims, err := Verify(raw, trustedPubPEMs)
	if err != nil {
		return nil, err
	}
	return &Manager{claims: claims, clock: time.Now}, nil
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
	for _, granted := range tierFeatures[m.claims.Tier] {
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

// FeatureInfo is one Editions view row.
type FeatureInfo struct {
	Name     Feature `json:"name"`
	Tier     Tier    `json:"tier"`
	Licensed bool    `json:"licensed"`
	Mode     Mode    `json:"mode"`
}

// Info is the operator-visible Editions payload.
type Info struct {
	Tier       Tier          `json:"tier"`
	State      State         `json:"state"`
	Customer   string        `json:"customer,omitempty"`
	LicenseID  string        `json:"license_id,omitempty"`
	ExpiresAt  *time.Time    `json:"expires_at,omitempty"`
	ReadOnlyAt *time.Time    `json:"read_only_at,omitempty"`
	TenantBand int           `json:"tenant_band,omitempty"`
	Features   []FeatureInfo `json:"features"`
}

// Info renders the current license truth.
func (m *Manager) Info() Info {
	info := Info{Tier: m.Tier(), State: m.State(), Features: []FeatureInfo{}}
	if m != nil && m.claims != nil {
		info.Customer = m.claims.Customer
		info.LicenseID = m.claims.ID
		exp := m.claims.ExpiresAt
		ro := exp.Add(GracePeriod)
		info.ExpiresAt = &exp
		info.ReadOnlyAt = &ro
		info.TenantBand = m.claims.TenantBand
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
