// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// installAgentDistrust adds the operator's distrust entries to the shipped
// list (eMudhra, Part 4). The agent rates what it discovers against the
// combined list, and removes a trust-store root only when that list names it,
// so an operator entry the control plane knows must be given to the agent too.
// A missing or malformed file stops the agent instead of rating with less.
func installAgentDistrust(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied agent flag naming a local distrust list (CWE-22)
	if err != nil {
		return fmt.Errorf("--distrust-file: %w", err)
	}
	extra, err := trust.Parse(data)
	if err != nil {
		return fmt.Errorf("--distrust-file: %w", err)
	}
	if err := trust.SetOperator(extra); err != nil {
		return fmt.Errorf("--distrust-file: %w", err)
	}
	return nil
}
