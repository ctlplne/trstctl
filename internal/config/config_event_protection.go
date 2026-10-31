// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"path/filepath"
	"strings"
)

// EventProtection supplies independent software custody for tenant opt-in.
// Configuring a directory does not enable protection for any tenant. The
// directory must remain outside ordinary backup sources and destinations.
type EventProtection struct {
	KeyDirectory string `json:"key_directory,omitempty"`
}

func validateEventProtection(c EventProtection) []error {
	if c.KeyDirectory == "" {
		return nil
	}
	if strings.TrimSpace(c.KeyDirectory) != c.KeyDirectory || !filepath.IsAbs(c.KeyDirectory) {
		return []error{errors.New("privacy.event_protection.key_directory must be an absolute path without surrounding whitespace")}
	}
	return nil
}
