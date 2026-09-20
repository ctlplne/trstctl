// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

const (
	TLSVersion12 = "TLSv1.2"
	TLSVersion13 = "TLSv1.3"
)

// TLSPosture is the public, non-secret part of a TLS listener configuration.
// Connector implementations translate this stable shape into their receiver's
// native API and read the same shape back after a mutation.
type TLSPosture struct {
	MinimumVersion    string   `json:"minimum_version"`
	CipherSuites      []string `json:"cipher_suites"`
	KeyExchangeGroups []string `json:"key_exchange_groups"`
}

// TLSPostureMutation pins an operator-approved posture to one immutable,
// tenant-scoped deployment-target revision. TenantID comes only from the sealed
// outbox envelope and is never decoded from durable JSON (AN-1).
type TLSPostureMutation struct {
	RunID          string          `json:"run_id"`
	FindingID      string          `json:"finding_id"`
	FindingKind    string          `json:"finding_kind"`
	TargetID       string          `json:"target_id"`
	TargetRevision string          `json:"target_revision"`
	Connector      string          `json:"connector"`
	Target         string          `json:"target"`
	TargetConfig   json.RawMessage `json:"target_config"`
	Desired        TLSPosture      `json:"desired"`
	// ExpectedPrevious is a durable pre-mutation observation. When present,
	// Registry applies only if the receiver is still at this posture or already
	// equals Desired after an ambiguous successful attempt.
	ExpectedPrevious *TLSPosture `json:"expected_previous,omitempty"`
	TenantID         string      `json:"-"`
}

// TLSPostureReceipt is durable read-after-write evidence. Previous is retained
// so an operator rollback can restore the exact receiver configuration rather
// than guessing at a generic legacy policy.
type TLSPostureReceipt struct {
	RunID          string     `json:"run_id"`
	FindingID      string     `json:"finding_id"`
	FindingKind    string     `json:"finding_kind"`
	TargetID       string     `json:"target_id"`
	TargetRevision string     `json:"target_revision"`
	Connector      string     `json:"connector"`
	Previous       TLSPosture `json:"previous"`
	Observed       TLSPosture `json:"observed"`
	Applied        bool       `json:"applied"`
}

// TLSPostureConnector is an optional extension implemented by native
// deployment connectors that can both mutate and observe listener TLS policy.
// A connector without this interface is unsupported and fails before enqueue.
type TLSPostureConnector interface {
	ReadTLSPosture(context.Context, Sandbox, string) (TLSPosture, error)
	ApplyTLSPosture(context.Context, Sandbox, string, TLSPosture) error
}

// TLSPostureDeployer is the feature-neutral server/edition seam used by a
// licensed policy-rollout worker. Registry is the shipped implementation.
type TLSPostureDeployer interface {
	SupportsTLSPosture(connectorName string) bool
	ReadTLSPosture(context.Context, TLSPostureMutation) (TLSPosture, error)
	ApplyTLSPosture(context.Context, TLSPostureMutation) (TLSPostureReceipt, error)
	RestoreTLSPosture(context.Context, TLSPostureMutation) (TLSPostureReceipt, error)
}

// ValidateTLSPosture rejects unsafe desired state. It intentionally recognizes
// a small protocol vocabulary and rejects legacy/anonymous/export cipher names;
// connector-specific APIs must not weaken this policy during translation.
func ValidateTLSPosture(p TLSPosture) error {
	if p.MinimumVersion != TLSVersion12 && p.MinimumVersion != TLSVersion13 {
		return fmt.Errorf("connector: desired TLS minimum version must be %s or %s", TLSVersion12, TLSVersion13)
	}
	if err := validateTLSPostureLists(p); err != nil {
		return err
	}
	for _, cipher := range p.CipherSuites {
		upper := strings.ToUpper(cipher)
		for _, weak := range []string{"NULL", "RC4", "3DES", "DES", "EXPORT", "MD5", "ANON"} {
			if strings.Contains(upper, weak) {
				return fmt.Errorf("connector: TLS cipher suite %q is not an approved desired cipher", cipher)
			}
		}
	}
	return nil
}

// ValidateObservedTLSPosture validates bounded receiver data without rejecting
// TLS 1.0/1.1 legacy protocol facts that a migration exists to replace. SSL and
// unknown version strings remain rejected instead of being normalized loosely.
func ValidateObservedTLSPosture(p TLSPosture) error {
	switch p.MinimumVersion {
	case "TLSv1.0", "TLSv1.1", TLSVersion12, TLSVersion13:
	default:
		return fmt.Errorf("connector: observed TLS minimum version %q is unsupported", p.MinimumVersion)
	}
	return validateTLSPostureLists(p)
}

func validateTLSPostureLists(p TLSPosture) error {
	if len(p.CipherSuites) == 0 || len(p.CipherSuites) > 64 {
		return fmt.Errorf("connector: TLS posture requires between 1 and 64 cipher suites")
	}
	if len(p.KeyExchangeGroups) == 0 || len(p.KeyExchangeGroups) > 32 {
		return fmt.Errorf("connector: TLS posture requires between 1 and 32 key-exchange groups")
	}
	if err := validatePostureTokens("cipher suite", p.CipherSuites); err != nil {
		return err
	}
	if err := validatePostureTokens("key-exchange group", p.KeyExchangeGroups); err != nil {
		return err
	}
	return nil
}

func validatePostureTokens(kind string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
			return fmt.Errorf("connector: invalid TLS %s %q", kind, value)
		}
		for _, r := range value {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
				continue
			}
			return fmt.Errorf("connector: invalid TLS %s %q", kind, value)
		}
		canonical := strings.ToUpper(value)
		if _, ok := seen[canonical]; ok {
			return fmt.Errorf("connector: duplicate TLS %s %q", kind, value)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

// EqualTLSPosture compares the exact receiver-observable policy. Order remains
// significant because several TLS APIs preserve preference order.
func EqualTLSPosture(a, b TLSPosture) bool {
	return a.MinimumVersion == b.MinimumVersion &&
		slices.Equal(a.CipherSuites, b.CipherSuites) &&
		slices.Equal(a.KeyExchangeGroups, b.KeyExchangeGroups)
}

func cloneTLSPosture(p TLSPosture) TLSPosture {
	p.CipherSuites = append([]string(nil), p.CipherSuites...)
	p.KeyExchangeGroups = append([]string(nil), p.KeyExchangeGroups...)
	return p
}
