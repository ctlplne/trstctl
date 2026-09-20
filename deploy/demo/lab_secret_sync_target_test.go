// SPDX-License-Identifier: BUSL-1.1

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
// on the plane's loopback, with a mounted file credential (the only reference kind sync
// targets accept besides secret://) and the explicit insecure-loopback grant the endpoint rule requires.
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
	// The control plane validates the whole file at startup with this exact
	// validator; an entry it refuses crash-loops the plane before any journey.
	if err := config.ValidateSecretIntegrations(cfg.SecretIntegrations, true); err != nil {
		t.Fatalf("the control plane would refuse the lab's secret integrations at boot: %v", err)
	}
	// The credential is a file the lab compose mounts into the plane read-only.
	const ref = "file:/etc/trstctl/ci-secret-access-key"
	if target.SecretAccessRef != ref {
		t.Fatalf("sync target ci secret_access_key_ref = %q, want %q (a mounted file; env refs are not accepted for sync targets)", target.SecretAccessRef, ref)
	}
	compose, err := os.ReadFile(filepath.Join("lab", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	const mount = "./lab/ci-secret-access-key:/etc/trstctl/ci-secret-access-key:ro"
	if !strings.Contains(string(compose), mount) {
		t.Fatalf("deploy/demo/lab/docker-compose.yml does not mount the credential file (%s)", mount)
	}
	cred, err := os.ReadFile(filepath.Join("lab", "ci-secret-access-key"))
	if err != nil || strings.TrimSpace(string(cred)) == "" {
		t.Fatalf("lab credential file missing or empty: %v", err)
	}
}
