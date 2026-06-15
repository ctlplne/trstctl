package helm

import (
	"strings"
	"testing"
)

// TestSignerIsolationChart (S15.1 / SIGNER-005) verifies the chart carries the
// isolated-signer topology — its own pod, hardened security context, network
// policy, and the mTLS Service — now that the cross-node mTLS transport is
// implemented. It reuses the read/containsAll helpers from helm_test.go.
func TestSignerIsolationChart(t *testing.T) {
	dep := read(t, "templates", "signer-deployment.yaml")
	containsAll(t, "signer-deployment.yaml", dep,
		"kind: Deployment",
		"app.kubernetes.io/component: signer",
		"readOnlyRootFilesystem: true",
		"runAsNonRoot: true",
		`drop: ["ALL"]`,
		`eq .Values.signer.mode "isolated"`,
		// SIGNER-005: the isolated pod actually serves the cross-node mTLS listener
		// and mounts the pinned cert material.
		"--mtls-listen=:9443",
		"--mtls-cert=",
		"--mtls-peer-ca=",
		"--mtls-peer-pin=",
	)
	np := read(t, "templates", "signer-networkpolicy.yaml")
	containsAll(t, "signer-networkpolicy.yaml", np,
		"kind: NetworkPolicy",
		"Ingress",
		"Egress",
		"port: 9443",
	)
	svc := read(t, "templates", "signer-service.yaml")
	containsAll(t, "signer-service.yaml", svc, "kind: Service", "grpc-mtls")

	vals := read(t, "values.yaml")
	containsAll(t, "values.yaml", vals, "signer:", "mode: sidecar", "mtls:", "serverName:", "externalKMS:", "provider:")
}

// TestIsolatedSignerModeIsValidated (SIGNER-005, formerly OPS-001) asserts the
// chart now SUPPORTS the isolated/mTLS signer topology and validates it instead of
// rendering an inoperative pod:
//
//   - the guard helper exists and is invoked from an always-rendered template, so
//     every install validates signer.mode; an unrecognized mode still fails fast,
//     and an isolated install missing its mTLS server name fails with guidance;
//   - the signer template DOES now pass --mtls-listen (and the cert/peer flags),
//     which the binary defines — closing the prior crash-loop class — and still
//     runs from the single multi-binary image (no un-built -signer image).
//
// The full render-time behaviour (sidecar renders; bogus modes fail; the flags it
// passes are all real binary flags) is exercised against the binary's real flag
// set in deploy/deploycheck_test.go.
func TestIsolatedSignerModeIsValidated(t *testing.T) {
	helpers := read(t, "templates", "_helpers.tpl")
	containsAll(t, "_helpers.tpl", helpers,
		`define "trustctl.signer.guardMode"`,
		`fail`,                               // still fails fast on a bad/half-configured mode
		`not .Values.signer.mtls.serverName`, // isolated requires the mTLS SAN
	)

	// The guard is invoked from the always-rendered deployment.yaml, so every
	// render validates the signer mode (not only the gated isolated-mode files).
	dep := read(t, "templates", "deployment.yaml")
	if !strings.Contains(dep, `include "trustctl.signer.guardMode"`) {
		t.Error("deployment.yaml must invoke trustctl.signer.guardMode so a default render validates signer.mode")
	}

	signer := read(t, "templates", "signer-deployment.yaml")
	// SIGNER-005: --mtls-listen is now a REAL binary flag and must be passed by the
	// isolated topology (the inverse of the old OPS-001 assertion).
	if !strings.Contains(signer, "--mtls-listen=:9443") {
		t.Error("signer-deployment.yaml must pass --mtls-listen for the isolated mTLS topology (SIGNER-005)")
	}
	// It must still NOT reference a separate, un-built -signer image (OPS-002).
	if strings.Contains(signer, `{{ .Values.image.repository }}-signer`) {
		t.Error("signer-deployment.yaml references an un-built -signer image (OPS-002 regression)")
	}
	// It runs the signer from the single multi-binary image.
	containsAll(t, "signer-deployment.yaml runs the built image's signer", signer,
		`include "trustctl.image"`,
		"trustctl-signer",
	)
}
