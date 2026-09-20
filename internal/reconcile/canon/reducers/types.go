// SPDX-License-Identifier: BUSL-1.1

package reducers

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/reconcile/canon"
)

type ObservationMode string

const (
	ModePoll         ObservationMode = "poll"
	ModeSubscription ObservationMode = "subscription"
)

var (
	ErrMissingAuthority = errors.New("xrec reducers: authority id required")
	ErrMissingSource    = errors.New("xrec reducers: source required")
	ErrMissingWatermark = errors.New("xrec reducers: watermark position required")
)

type ReducerConfig struct {
	AuthorityID string
	Scope       string
	Mode        ObservationMode
	Grant       Grant
	Transport   AuthorityTransport
}

type Grant interface {
	Empty() bool
	Allows(cap Capability, resource string) bool
}

type Capability = capability

type Watermark struct {
	Mode       ObservationMode
	Position   string
	ObservedAt time.Time
}

type Observation struct {
	AuthorityID string
	TenantID    string
	Set         canon.Set
	Watermark   Watermark
	Denied      int
}

type VaultInventorySource interface {
	VaultSnapshot(ctx context.Context, tenantID string, sb *ObservationSandbox) (VaultSnapshot, error)
}

type CloudKMSInventorySource interface {
	CloudKMSSnapshot(ctx context.Context, tenantID string, sb *ObservationSandbox) (CloudKMSSnapshot, error)
}

type SelfInventorySource interface {
	SelfSnapshot(ctx context.Context, tenantID string) (SelfSnapshot, error)
}

type VaultSnapshot struct {
	Watermark       Watermark
	Secrets         []VaultSecretRef
	PKICertificates []VaultPKICertificate
	Keys            []VaultKey
}

type VaultSecretRef struct {
	Namespace                string
	Path                     string
	Status                   string
	CreatedAt                time.Time
	DeletedAt                time.Time
	ProviderVersionID        string
	ProviderValueSHA256Hex   string
	ProviderNativeResourceID string
	Value                    []byte
}

type VaultPKICertificate struct {
	IssuerNameDER []byte
	SerialHex     string
	Algorithm     string
	Status        string
	NotBefore     time.Time
	NotAfter      time.Time
	SubjectDN     string
	NativeID      string
}

type VaultKey struct {
	LogicalID string
	Algorithm string
	Status    string
	CreatedAt time.Time
	DeletedAt time.Time
	NativeID  string
}

type CloudKMSSnapshot struct {
	Watermark Watermark
	Keys      []CloudKMSKey
}

type CloudKMSKey struct {
	KeyID           string
	AlgorithmSpec   string
	Status          string
	CreatedAt       time.Time
	DeletedAt       time.Time
	RotationEnabled bool
	NativeID        string
}

type SelfSnapshot struct {
	Watermark    Watermark
	Certificates []SelfCertificate
	Keys         []SelfKey
	Workloads    []SelfWorkloadIdentity
}

type SelfCertificate struct {
	IssuerNameDER []byte
	SerialHex     string
	Algorithm     string
	Status        string
	NotBefore     time.Time
	NotAfter      time.Time
	SubjectDN     string
	NativeID      string
}

type SelfKey struct {
	LogicalID string
	Algorithm string
	Status    string
	CreatedAt time.Time
	DeletedAt time.Time
	NativeID  string
}

type SelfWorkloadIdentity struct {
	SPIFFEID  string
	Algorithm string
	Status    string
	NativeID  string
}

func normalizeWatermark(w Watermark, fallback ObservationMode) (Watermark, error) {
	if w.Mode == "" {
		w.Mode = fallback
	}
	if w.Mode == "" {
		w.Mode = ModePoll
	}
	if w.Position == "" {
		return Watermark{}, ErrMissingWatermark
	}
	if w.ObservedAt.IsZero() {
		w.ObservedAt = time.Now().UTC()
	}
	return w, nil
}

func validateConfig(cfg ReducerConfig) (ReducerConfig, error) {
	if cfg.AuthorityID == "" {
		return ReducerConfig{}, ErrMissingAuthority
	}
	if cfg.Mode == "" {
		cfg.Mode = ModePoll
	}
	if cfg.Transport == nil {
		cfg.Transport = noopTransport{}
	}
	if cfg.Grant == nil || cfg.Grant.Empty() {
		cfg.Grant = ReadOnlyObservationGrant(cfg.Scope)
	}
	return cfg, nil
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
