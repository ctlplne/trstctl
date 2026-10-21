// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
)

const k8sInventoryTestCertPEM = `-----BEGIN CERTIFICATE-----
MIIBjDCCATGgAwIBAgIUbUBdvVyLGrRCJmc3v/XUcPHXkiMwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZGlzY292ZXJ5LTEudGVzdDAeFw0yNjA1MzAxODA5NTFaFw0z
NjA1MjcxODA5NTFaMBsxGTAXBgNVBAMMEGRpc2NvdmVyeS0xLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS/wgFIHrQZaIbPLJiTFRAw7jskcfmHyR3bK9v4
SA1pf3qDdiQB251mv+nF3qDY23d/fY3C96wgySv56nhoW/N7o1MwUTAdBgNVHQ4E
FgQUagh6v1IAMWknG6X38HDrLuL/bN0wHwYDVR0jBBgwFoAUagh6v1IAMWknG6X3
8HDrLuL/bN0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA6Uv9
Q944+/6g4qbJ1TvNUXdphxwfq+j91btwxC9ENq8CIQDHIBCvC3Hvx4DN08ItES2l
vGsFCZlEd32emYdgZuAgcw==
-----END CERTIFICATE-----
`

type fakeNamespaceEnumerator struct {
	certs map[string][]byte
	err   error
}

func (f fakeNamespaceEnumerator) EnumerateCertificates(context.Context) (map[string][]byte, error) {
	return f.certs, f.err
}

func TestResolveKubernetesInventoryNamespaces(t *testing.T) {
	ctx := context.Background()
	list := func(context.Context) ([]string, error) { return []string{"a", "b"}, nil }
	if got, err := resolveKubernetesInventoryNamespaces("own", "", list, ctx); err != nil || len(got) != 1 || got[0] != "own" {
		t.Fatalf("default: %v %v", got, err)
	}
	if got, err := resolveKubernetesInventoryNamespaces("own", "all", list, ctx); err != nil || len(got) != 2 {
		t.Fatalf("all: %v %v", got, err)
	}
	if got, err := resolveKubernetesInventoryNamespaces("own", " x, y ", list, ctx); err != nil || len(got) != 2 || got[1] != "y" {
		t.Fatalf("named: %v %v", got, err)
	}
	if _, err := resolveKubernetesInventoryNamespaces("", "", list, ctx); err == nil {
		t.Fatal("an unknown own namespace with no flag must fail")
	}
	denied := func(context.Context) ([]string, error) { return nil, errors.New("403 forbidden") }
	if _, err := resolveKubernetesInventoryNamespaces("own", "all", denied, ctx); err == nil || !strings.Contains(err.Error(), "cluster-scoped") {
		t.Fatalf("a forbidden namespace list must explain the RBAC gap: %v", err)
	}
}

// Readable namespaces are reported; a namespace that cannot be read fails by
// name instead of contributing an empty inventory.
func TestCollectKubernetesSecretInventoryReportsPartialFailure(t *testing.T) {
	ctx := context.Background()
	cert := []byte(k8sInventoryTestCertPEM)
	enumerators := map[string]fakeNamespaceEnumerator{
		"apps":   {certs: map[string][]byte{"web-tls": cert}},
		"locked": {err: errors.New("k8s: list secrets in locked: status 403")},
	}
	found, err := collectKubernetesSecretInventory(ctx, "apps", "apps,locked", nil, func(ns string) agentdiscovery.KubernetesSecretEnumerator {
		return enumerators[ns]
	})
	if len(found) != 1 || found[0].Metadata["namespace"] != "apps" || found[0].Metadata["secret_name"] != "web-tls" {
		t.Fatalf("found=%+v", found)
	}
	if err == nil || !strings.Contains(err.Error(), "namespace locked") || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("partial failure must name the namespace: %v", err)
	}
	found, err = collectKubernetesSecretInventory(ctx, "apps", "", nil, func(ns string) agentdiscovery.KubernetesSecretEnumerator {
		return enumerators[ns]
	})
	if err != nil || len(found) != 1 {
		t.Fatalf("own namespace: found=%d err=%v", len(found), err)
	}
}
