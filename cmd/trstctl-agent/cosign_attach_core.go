// SPDX-License-Identifier: MPL-2.0

//go:build trstctl_core

package main

import (
	"context"
	"errors"
)

// cosign_attach_core.go is the core-build stub for the workload co-sign seam: the
// ee/succession/agent CoSignerService is an enterprise feature, so the core build
// refuses to start it. The type and function mirror the enterprise seam for build
// parity; main.go references only these symbols and never imports ee/.

type workloadCoSignConfig struct {
	Listen             string
	DeploymentScope    string
	IdentityID         string
	TenantID           string
	PredecessorKeyPath string
}

func runWorkloadCoSign(_ context.Context, _ workloadCoSignConfig) error {
	return errors.New("workload co-sign requires the enterprise build (built without trstctl_core)")
}
