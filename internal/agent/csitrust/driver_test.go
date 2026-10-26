// SPDX-License-Identifier: BUSL-1.1

package csitrust_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/csitrust"
)

type bundles struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (b *bundles) TrustBundlePEM(_ context.Context, name string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	pem, ok := b.m[name]
	if !ok {
		return nil, csitrust.ErrBundleNotFound
	}
	return pem, nil
}

func (b *bundles) set(name, pem string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[name] = []byte(pem)
}

// A139: over the Unix socket the kubelet uses, the driver names itself and its
// node, publishes the named TrustBundle into the target directory as one
// read-only file, rewrites it on a republish after the bundle changed, refuses
// volumes it does not serve, and unpublishes idempotently.
func TestCSITrustDriverServesTrustBundlesOverTheKubeletSocket(t *testing.T) {
	source := &bundles{m: map[string][]byte{}}
	source.set("roots", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	dir := t.TempDir()
	// Unix socket paths are capped near 104 bytes; the test's own temp dir
	// name is too long for one.
	socketDir, err := os.MkdirTemp("", "csi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "plugin", "csi.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- csitrust.NewDriver(source, "node-a", "test").Serve(ctx, socket) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the driver never opened its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	identity, node := csi.NewIdentityClient(conn), csi.NewNodeClient(conn)
	call, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()

	info, err := identity.GetPluginInfo(call, &csi.GetPluginInfoRequest{})
	if err != nil || info.GetName() != csitrust.DriverName {
		t.Fatalf("GetPluginInfo = %v, %v", info, err)
	}
	if probe, err := identity.Probe(call, &csi.ProbeRequest{}); err != nil || !probe.GetReady().GetValue() {
		t.Fatalf("Probe = %v, %v", probe, err)
	}
	if nodeInfo, err := node.NodeGetInfo(call, &csi.NodeGetInfoRequest{}); err != nil || nodeInfo.GetNodeId() != "node-a" {
		t.Fatalf("NodeGetInfo = %v, %v", nodeInfo, err)
	}

	target := filepath.Join(dir, "pods", "uid", "volumes", "kubernetes.io~csi", "trust", "mount")
	publish := func(attributes map[string]string, path string) error {
		_, err := node.NodePublishVolume(call, &csi.NodePublishVolumeRequest{
			VolumeId: "csi-1", TargetPath: path, Readonly: true, VolumeContext: attributes,
			VolumeCapability: &csi.VolumeCapability{
				AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
				AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY},
			},
		})
		return err
	}
	attributes := map[string]string{"csi.storage.k8s.io/ephemeral": "true", "trustBundle": "roots"}
	if err := publish(attributes, target); err != nil {
		t.Fatalf("publish: %v", err)
	}
	read := func() string {
		data, err := os.ReadFile(filepath.Join(target, "ca.crt")) // #nosec G304 -- the file the driver wrote under this test's temp dir (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if got := read(); got != "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" {
		t.Fatalf("published bundle = %q", got)
	}
	if info, err := os.Stat(filepath.Join(target, "ca.crt")); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("published file mode = %v, %v", info.Mode(), err)
	}
	source.set("roots", "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")
	if err := publish(attributes, target); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if got := read(); got != "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n" {
		t.Fatalf("republished bundle = %q", got)
	}

	for name, tc := range map[string]struct {
		attributes map[string]string
		path       string
		code       codes.Code
	}{
		"persistent volume": {map[string]string{"trustBundle": "roots"}, target, codes.InvalidArgument},
		"no bundle name":    {map[string]string{"csi.storage.k8s.io/ephemeral": "true"}, target, codes.InvalidArgument},
		"escaping key":      {map[string]string{"csi.storage.k8s.io/ephemeral": "true", "trustBundle": "roots", "key": "../x"}, target, codes.InvalidArgument},
		"relative target":   {attributes, "relative/mount", codes.InvalidArgument},
		"unknown bundle":    {map[string]string{"csi.storage.k8s.io/ephemeral": "true", "trustBundle": "missing"}, target, codes.NotFound},
	} {
		if err := publish(tc.attributes, tc.path); status.Code(err) != tc.code {
			t.Fatalf("%s: publish = %v, want %s", name, err, tc.code)
		}
	}

	for range 2 {
		if _, err := node.NodeUnpublishVolume(call, &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-1", TargetPath: target}); err != nil {
			t.Fatalf("unpublish: %v", err)
		}
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("the volume outlived unpublish: %v", err)
	}
}
