// SPDX-License-Identifier: MPL-2.0

package demo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// The partner lab ships a configured secret sync target for the lab tenant, so
// the rotation-schedule and sync journeys are cold-testable on the lab: without
// it POST /api/v1/secrets/rotation-schedules answers 503 "secret sync target is
// not configured" (RACE-CONFIG-005c). The target is LocalStack's Secrets Manager
// on the plane's loopback, with the already-approved credential reference and the
// explicit insecure-loopback grant the endpoint rule requires.
func TestPartnerLabConfigDeclaresASecretSyncTarget(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("lab", "trstctl-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parse lab config: %v", err)
	}
	var target *config.SecretSyncTargetConfig
	for i := range cfg.SecretIntegrations.SyncTargets {
		if cfg.SecretIntegrations.SyncTargets[i].ID == "ci" && cfg.SecretIntegrations.SyncTargets[i].TenantID == "11111111-1111-4111-8111-111111111111" {
			target = &cfg.SecretIntegrations.SyncTargets[i]
		}
	}
	if target == nil {
		t.Fatal("lab config declares no secret sync target 'ci' for the lab tenant")
	}
	if target.Type != "aws-secrets-manager" || target.Region == "" {
		t.Fatalf("sync target ci = %+v, want an aws-secrets-manager target with a region", *target)
	}
	if !strings.HasPrefix(target.Endpoint, "http://127.0.0.1:") || !target.AllowInsecureLoopback || !target.AllowPrivate {
		t.Fatalf("sync target ci must point at the plane's loopback LocalStack with the insecure-loopback and private-endpoint grants: %+v", *target)
	}
	if !strings.HasPrefix(target.SecretAccessRef, "env:") {
		t.Fatalf("sync target ci must reference its secret through an operator-approved env credential, got %q", target.SecretAccessRef)
	}
	// The reference must be one the demo control plane approves for outbound use.
	compose, err := os.ReadFile(filepath.Join("docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), target.SecretAccessRef) {
		t.Fatalf("TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS in deploy/demo/docker-compose.yml does not approve %q", target.SecretAccessRef)
	}
	// The control plane validates the whole file at startup; the lab bring-up
	// (deploy/demo/lab/run.sh) is where an invalid entry would fail loudly.
}
