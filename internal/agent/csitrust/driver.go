// SPDX-License-Identifier: BUSL-1.1

// Package csitrust serves trust bundles to pods as ephemeral inline CSI
// volumes (A139). A pod names a trstctl TrustBundle in its volume attributes;
// the kubelet asks this node plugin to publish the volume, and the plugin writes
// the bundle's public CA certificates into it as one file. The plugin only
// writes files into the directory the kubelet hands it — it never mounts — and
// the CSIDriver object asks the kubelet to republish periodically, so a changed
// bundle reaches running pods.
package csitrust

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DriverName is the CSI driver pods name in their inline volumes.
const DriverName = "trust.csi.trstctl.com"

// Volume attributes a pod sets on the inline volume.
const (
	AttributeTrustBundle = "trustBundle"
	AttributeKey         = "key"
	ephemeralAttribute   = "csi.storage.k8s.io/ephemeral"
	defaultKey           = "ca.crt"
)

// ErrBundleNotFound reports a TrustBundle the cluster does not have.
var ErrBundleNotFound = errors.New("csitrust: TrustBundle not found")

// BundleSource returns a TrustBundle's public CA certificates, normalized and
// checked to hold only CERTIFICATE blocks.
type BundleSource interface {
	TrustBundlePEM(ctx context.Context, name string) ([]byte, error)
}

var (
	bundleNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	fileKeyRE    = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// Driver is the CSI Identity and Node service for trust-bundle volumes.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer
	source  BundleSource
	nodeID  string
	version string
}

// NewDriver returns a driver that reads bundles from source and reports
// nodeID to the kubelet.
func NewDriver(source BundleSource, nodeID, version string) *Driver {
	return &Driver{source: source, nodeID: nodeID, version: version}
}

// GetPluginInfo names the driver.
func (d *Driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: DriverName, VendorVersion: d.version}, nil
}

// GetPluginCapabilities reports none: there is no controller service, since
// trust-bundle volumes are ephemeral and node-local.
func (d *Driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

// Probe reports the driver ready.
func (d *Driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}

// NodeGetCapabilities reports none: volumes are published directly, with no
// staging step.
func (d *Driver) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

// NodeGetInfo reports this node.
func (d *Driver) NodeGetInfo(context.Context, *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: d.nodeID}, nil
}

// NodePublishVolume writes the named bundle into the target directory as one
// read-only file. A republish rewrites it only when the bundle changed.
func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	attributes := req.GetVolumeContext()
	if attributes[ephemeralAttribute] != "true" {
		return nil, status.Error(codes.InvalidArgument, "trust-bundle volumes are inline ephemeral volumes only")
	}
	name := attributes[AttributeTrustBundle]
	if !bundleNameRE.MatchString(name) {
		return nil, status.Errorf(codes.InvalidArgument, "volume attribute %s must name a TrustBundle", AttributeTrustBundle)
	}
	key := attributes[AttributeKey]
	if key == "" {
		key = defaultKey
	}
	if !fileKeyRE.MatchString(key) || key == "." || key == ".." {
		return nil, status.Errorf(codes.InvalidArgument, "volume attribute %s must be a file name", AttributeKey)
	}
	target := req.GetTargetPath()
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, status.Error(codes.InvalidArgument, "target path must be a clean absolute path")
	}
	bundle, err := d.source.TrustBundlePEM(ctx, name)
	if errors.Is(err, ErrBundleNotFound) {
		return nil, status.Errorf(codes.NotFound, "TrustBundle %s does not exist", name)
	}
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read TrustBundle %s: %v", name, err)
	}
	if err := writeBundle(target, key, bundle); err != nil {
		return nil, status.Errorf(codes.Internal, "write trust bundle into the volume: %v", err)
	}
	return &csi.NodePublishVolumeResponse{}, nil
}

// NodeUnpublishVolume removes what NodePublishVolume wrote. Removing a volume
// that is already gone succeeds.
func (d *Driver) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	target := req.GetTargetPath()
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, status.Error(codes.InvalidArgument, "target path must be a clean absolute path")
	}
	if err := os.RemoveAll(target); err != nil {
		return nil, status.Errorf(codes.Internal, "remove trust-bundle volume: %v", err)
	}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// writeBundle makes dir/key hold bundle, replacing it atomically and only when
// it differs, readable by every container user.
func writeBundle(dir, key string, bundle []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- the volume holds public CA certificates the pod's containers read (CWE-276)
		return err
	}
	path := filepath.Join(dir, key)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, bundle) { // #nosec G304 -- path is the kubelet's target directory joined with a validated file name (CWE-22)
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".trust-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(bundle); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o444); err != nil { // #nosec G302 -- public CA certificates, read by any container user (CWE-276)
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Serve listens on the Unix socket at socketPath (the kubelet's plugin
// registration names it) and serves until ctx ends.
func (d *Driver) Serve(ctx context.Context, socketPath string) error {
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("csitrust: remove stale socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return fmt.Errorf("csitrust: socket directory: %w", err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("csitrust: listen on %s: %w", socketPath, err)
	}
	// The kubelet is the only client: it reaches this socket through the node's
	// plugin directory, so the channel is node-local and unauthenticated by the
	// CSI design.
	server := grpc.NewServer()
	csi.RegisterIdentityServer(server, d)
	csi.RegisterNodeServer(server, d)
	go func() {
		<-ctx.Done()
		server.GracefulStop()
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}
