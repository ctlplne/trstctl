// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// EventProtection supplies independent software custody for tenant opt-in.
// Configuring a directory does not enable protection for any tenant. Custody
// and operator-pinned public evidence trust stay outside managed restore paths.
type EventProtection struct {
	KeyDirectory         string `json:"key_directory,omitempty"`
	VerificationKeysFile string `json:"verification_keys_file,omitempty"`
	// AuditRetentionFloor is the operator's audit retention floor (OD-11): an
	// offboarded tenant's key is never destroyed sooner than this after the
	// offboard, whatever shorter retention the tenant chose, so its audit
	// archives, history and backups stay readable that long. A legal hold
	// still wins. Unset means the default, a year (8760h); "0s" turns the
	// floor off; at most ten years.
	AuditRetentionFloor string `json:"audit_retention_floor,omitempty"`
}

// DefaultAuditRetentionFloor is the floor when the operator sets none: a year.
const DefaultAuditRetentionFloor = 8760 * time.Hour

// maxAuditRetentionFloor matches the longest retention a tenant may choose.
const maxAuditRetentionFloor = 10 * 365 * 24 * time.Hour

// AuditRetentionFloorDuration parses privacy.event_protection.audit_retention_floor.
func (c EventProtection) AuditRetentionFloorDuration() (time.Duration, error) {
	raw := strings.TrimSpace(c.AuditRetentionFloor)
	if raw == "" {
		return DefaultAuditRetentionFloor, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("privacy.event_protection.audit_retention_floor: %w", err)
	}
	if d < 0 || d > maxAuditRetentionFloor {
		return 0, fmt.Errorf("privacy.event_protection.audit_retention_floor must be 0s (off) to %s", maxAuditRetentionFloor)
	}
	return d, nil
}

func validateEventProtection(c EventProtection) []error {
	var errs []error
	if c.KeyDirectory != "" && (strings.TrimSpace(c.KeyDirectory) != c.KeyDirectory || !filepath.IsAbs(c.KeyDirectory)) {
		errs = append(errs, errors.New("privacy.event_protection.key_directory must be an absolute path without surrounding whitespace"))
	}
	if c.VerificationKeysFile != "" && (strings.TrimSpace(c.VerificationKeysFile) != c.VerificationKeysFile || !filepath.IsAbs(c.VerificationKeysFile)) {
		errs = append(errs, errors.New("privacy.event_protection.verification_keys_file must be an absolute path without surrounding whitespace"))
	}
	if _, err := c.AuditRetentionFloorDuration(); err != nil {
		errs = append(errs, err)
	}
	return errs
}
