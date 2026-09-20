// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package tpm_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/tpm"
)

func TestSwtpmEdgeCAHandleSurvivesDeviceRestart(t *testing.T) {
	path := os.Getenv("TRSTCTL_SWTPM_PATH")
	if path == "" {
		t.Skip("TRSTCTL_SWTPM_PATH is required")
	}
	open := func(t *testing.T) *tpm.Backend {
		t.Helper()
		device, err := tpm.OpenDevice(tpm.DeviceConfig{Path: path, PersistentHandleBase: 0x81018000})
		if err != nil {
			t.Fatalf("open swtpm device: %v", err)
		}
		return tpm.New(device)
	}

	ctx := context.Background()
	first := open(t)
	handle, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(
		ctx, "aud26-swtpm-edge-generation-1", "swtpm edge CA", crypto.ECDSAP256, first,
	)
	if err != nil {
		_ = first.Close()
		t.Fatalf("create edge CA in swtpm: %v", err)
	}
	raw, err := json.Marshal(handle)
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "private_key") {
		_ = first.Close()
		t.Fatalf("public TPM handle contains private material: %s", raw)
	}
	// go-tpm's emulator transport disconnects after every command, so Close may
	// report that no command connection is currently open. The next OpenDevice
	// is the restart boundary this test cares about.
	_ = first.Close()

	parentSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := crypto.SelfSignedHierarchyCA(parentSigner, crypto.HierarchyCAProfile{
		CommonName: "swtpm edge parent", MaxPathLen: 1, TTL: 24 * time.Hour,
		PermittedDNSDomains: []string{"edge.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, csrDER, crypto.EdgeCARequest{
		CommonName: "swtpm edge CA", PermittedDNSDomains: []string{"edge.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	second := open(t)
	t.Cleanup(func() { _ = second.Close() })
	leaf, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, second, crypto.EdgeLeafRequest{
		CommonName: "db.edge.example.test", TTL: 10 * time.Minute,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue after reopening swtpm: %v", err)
	}
	if _, err := crypto.InspectEdgeReportedLeaf(delegation.CertificateDER, leaf.CertificateDER); err != nil {
		t.Fatalf("reopened TPM did not sign the edge leaf: %v", err)
	}
	t.Logf("SWTPM_EDGE_CA_OK handle=%s", handle.KeyID)
}
