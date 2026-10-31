// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"path/filepath"
	"strings"
)

// EventProtection supplies independent software custody for tenant opt-in.
// Configuring a directory does not enable protection for any tenant. Custody
// and operator-pinned public evidence trust stay outside managed restore paths.
type EventProtection struct {
	KeyDirectory         string `json:"key_directory,omitempty"`
	VerificationKeysFile string `json:"verification_keys_file,omitempty"`
}

func validateEventProtection(c EventProtection) []error {
	var errs []error
	if c.KeyDirectory != "" && (strings.TrimSpace(c.KeyDirectory) != c.KeyDirectory || !filepath.IsAbs(c.KeyDirectory)) {
		errs = append(errs, errors.New("privacy.event_protection.key_directory must be an absolute path without surrounding whitespace"))
	}
	if c.VerificationKeysFile != "" && (strings.TrimSpace(c.VerificationKeysFile) != c.VerificationKeysFile || !filepath.IsAbs(c.VerificationKeysFile)) {
		errs = append(errs, errors.New("privacy.event_protection.verification_keys_file must be an absolute path without surrounding whitespace"))
	}
	return errs
}
