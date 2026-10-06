// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesIssuerConfigFailsBeforeAgentBootstrap(t *testing.T) {
	if err := (k8sOptions{signerURL: "https://trstctl.example.test/issue"}).validateIssuerConfig(); err == nil || !strings.Contains(err.Error(), "require --cert-manager-controller") {
		t.Fatalf("orphan signer flags did not fail closed: %v", err)
	}
	valid := k8sOptions{
		controller: true, signerURL: "https://trstctl.example.test/api/v1/ca/authorities/ca/issue",
		signerTokenFile: t.TempDir() + "/token", reconcileEvery: 30 * time.Second,
	}
	if err := valid.validateIssuerConfig(); err != nil {
		t.Fatalf("valid operator configuration rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*k8sOptions)
		want string
	}{
		{name: "missing-url", edit: func(k *k8sOptions) { k.signerURL = "" }, want: "--bridge-signer-url"},
		{name: "missing-token", edit: func(k *k8sOptions) { k.signerTokenFile = "" }, want: "--bridge-signer-token-file"},
		{name: "insecure-url", edit: func(k *k8sOptions) { k.signerURL = "http://trstctl.example.test/issue" }, want: "must be HTTPS"},
		{name: "url-credential", edit: func(k *k8sOptions) { k.signerURL = "https://user:pass@trstctl.example.test/issue" }, want: "without credentials"},
		{name: "zero-interval", edit: func(k *k8sOptions) { k.reconcileEvery = 0 }, want: "must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := valid
			tc.edit(&options)
			if err := options.validateIssuerConfig(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("configuration error %v, want %q", err, tc.want)
			}
		})
	}
}
