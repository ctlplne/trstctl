// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// When two settings are bad, startup names the same one first it always did:
// the leaf validity (with the plugin, AI model and machine-auth settings) is
// checked before the ownership attestation cadence. c177cba48 moved the
// cadence into the lifecycle-window stage, ahead of them.
func TestRunConfigReportsLeafValidityBeforeAttestationCadence(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit.pem")
	cfg.Lifecycle.LeafValidity = "ninety days"
	cfg.Lifecycle.OwnershipAttestationCadence = "quarterly"
	_, err := buildRunDeps(context.Background(), cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, testAuditSigningKey(t))
	if err == nil || !strings.Contains(err.Error(), "lifecycle leaf validity") {
		t.Fatalf("two bad settings: %v; want the leaf validity reported first", err)
	}
}
