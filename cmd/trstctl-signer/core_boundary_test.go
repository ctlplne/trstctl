// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedKeyProviderAttachmentRequiresBYOKLicense(t *testing.T) {
	if _, err := appendManagedKeyOptions(nil, nil, "provider.json", "keystore"); err == nil {
		t.Fatal("unlicensed/core managed-key signer attachment succeeded")
	}
}

func TestCoreSignerDependencyClosureExcludesEnterpriseManagedKeyProviders(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "-tags", "trstctl_core", "./cmd/trstctl-signer")
	command.Dir = repo
	command.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list core signer dependencies: %v\n%s", err, output)
	}
	dependencies := map[string]bool{}
	for _, dependency := range strings.Fields(string(output)) {
		dependencies[dependency] = true
	}
	for _, forbidden := range []string{
		"trstctl.com/trstctl/" + "ee/managedkeys/signerwiring",
		"trstctl.com/trstctl/internal/kms/awskms",
		"trstctl.com/trstctl/internal/kms/azurekv",
		"trstctl.com/trstctl/internal/kms/gcpkms",
		"trstctl.com/trstctl/internal/kms/pkcs11",
		"trstctl.com/trstctl/internal/kms/tpm",
		"trstctl.com/trstctl/internal/kms/yubihsm",
	} {
		if dependencies[forbidden] {
			t.Errorf("core signer links Enterprise managed-key provider %s", forbidden)
		}
	}
	for dependency := range dependencies {
		if strings.HasPrefix(dependency, "trstctl.com/trstctl/ee/") {
			t.Errorf("core signer links Enterprise package %s", dependency)
		}
	}
}

func TestManagedKeySignerWiringPreservesSacredDependencyClosure(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "-deps", "./ee/managedkeys/signerwiring")
	command.Dir = repo
	command.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list managed-key signer wiring dependencies: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		for _, forbidden := range []string{
			"trstctl.com/trstctl/internal/server",
			"database/sql",
			"github.com/jackc/pgx",
			"github.com/nats-io",
		} {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
				t.Errorf("managed-key signer wiring links forbidden sacred-process dependency %s", dependency)
			}
		}
	}
}
