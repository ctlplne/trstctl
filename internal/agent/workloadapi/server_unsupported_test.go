// SPDX-License-Identifier: MPL-2.0

//go:build !linux && !darwin

package workloadapi_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/workloadapi"
)

func TestWorkloadAPIFailsClosedWithoutKernelPeerAttestation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workload.sock")
	err := workloadapi.New(nil, nil).Serve(context.Background(), path)
	if !errors.Is(err, workloadapi.ErrAttestationUnsupported) {
		t.Fatalf("Serve error = %v, want ErrAttestationUnsupported", err)
	}
	matches, statErr := filepath.Glob(path)
	if statErr != nil {
		t.Fatalf("inspect unsupported endpoint path: %v", statErr)
	}
	if len(matches) != 0 {
		t.Fatalf("unsupported Workload API created endpoint state: %v", matches)
	}
}
