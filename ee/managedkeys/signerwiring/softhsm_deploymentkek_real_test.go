// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build pkcs11cgo && cgo

package signerwiring_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// A198 against SoftHSM: the deployment KEK's next generation is created by
// the signer under the operator's HSM AES key with the deployment binding. A
// credential the key file sealed moves to that generation (only its data key
// is re-wrapped), the key file alone can no longer open it, and it opens only
// through the signer: once the promoted generation is the only one, a signer
// whose HSM key is gone cannot open it either.
func TestSoftHSMSignerHoldsTheDeploymentKEK(t *testing.T) {
	config := softHSMTenantKEKConfig(t, softHSMTenantKEKLabel)
	ctx := context.Background()
	keyFile, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x4d}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Destroy()

	client, stop := serveTenantKEK(t, config)
	registry, err := tenantseal.NewSignerWrapperRegistry([]string{"hsm-a"}, func() tenantseal.SignerTenantKEK { return client })
	if err != nil {
		t.Fatal(err)
	}
	ring, err := tenantseal.NewDeploymentKeyring(keyFile, nil, registry)
	if err != nil {
		t.Fatal(err)
	}
	const domainID = "4f0c6a3e-8d2b-4c71-9a51-2b7d0e6f1c90"
	binding, err := tenantseal.DeploymentBinding(domainID, 1)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := client.CreateTenantDomainKEK(ctx, "hsm-a", binding)
	if err != nil || !bytes.HasPrefix(wrapped, []byte("TDH1")) {
		t.Fatalf("create the deployment generation's key in the signer = %v", err)
	}
	rotating := &store.DeploymentKEKDomain{
		DomainID: domainID, NextGeneration: 1,
		NextWrapperKind: tenantseal.WrapperKindPKCS11, NextWrapperID: "hsm-a", NextWrappedKEK: wrapped,
		OperationStatus: store.DeploymentKEKOperationRunning,
	}
	aad := []byte("tenant/credential/ref/name")
	sealed, err := seal.Seal(keyFile, []byte("credential under the key file"), aad)
	if err != nil {
		t.Fatal(err)
	}
	view := ring.View(rotating)
	moved, changed, err := seal.RewrapContainerDEK(sealed, view.Rewrap)
	view.Destroy()
	if err != nil || !changed {
		t.Fatalf("re-wrap through the signer: changed=%v err=%v", changed, err)
	}
	if _, err := seal.Open(keyFile, moved, aad); err == nil {
		t.Fatal("the key file opened a credential re-wrapped under the HSM generation")
	}

	promoted := &store.DeploymentKEKDomain{
		DomainID: domainID, Generation: 1,
		WrapperKind: tenantseal.WrapperKindPKCS11, WrapperID: "hsm-a", WrappedKEK: wrapped,
		OperationStatus: store.DeploymentKEKOperationCompleted,
	}
	view = ring.View(promoted)
	plain, err := seal.Open(view, moved, aad)
	view.Destroy()
	if err != nil || string(plain) != "credential under the key file" {
		t.Fatalf("open through the signer = %q %v", plain, err)
	}
	stop()

	// A signer without the HSM custody cannot open it, and nothing falls back
	// to the key file.
	bare, stopBare := serveSignerWithoutCustody(t)
	defer stopBare()
	bareRegistry, err := tenantseal.NewSignerWrapperRegistry([]string{"hsm-a"}, func() tenantseal.SignerTenantKEK { return bare })
	if err != nil {
		t.Fatal(err)
	}
	bareRing, err := tenantseal.NewDeploymentKeyring(keyFile, nil, bareRegistry)
	if err != nil {
		t.Fatal(err)
	}
	view = bareRing.View(promoted)
	defer view.Destroy()
	if _, err := seal.Open(view, moved, aad); err == nil {
		t.Fatal("the credential opened through a signer without the HSM custody")
	}
	t.Log("SOFTHSM_DEPLOYMENT_KEK_OK")
}

// serveSignerWithoutCustody runs a signer with no tenant KEK custody.
func serveSignerWithoutCustody(t *testing.T) (*signing.Client, func()) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "bare-signer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(), signing.ServeOptions{})
	}()
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial the signer: %v", err)
	}
	return client, func() {
		_ = client.Close()
		cancel()
		<-served
	}
}
