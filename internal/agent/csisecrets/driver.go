// SPDX-License-Identifier: BUSL-1.1

// Package csisecrets serves secrets to pods as inline CSI volumes (A238), a
// delivery path with no Kubernetes Secret object. A pod names its secrets in
// the volume's attributes. When the kubelet publishes the volume, this node
// plugin logs in to the control plane with the pod's own service-account
// token (which the CSIDriver asks the kubelet for), reads what that identity
// may read, and writes the values into a memory filesystem it mounts at the
// volume, so they never reach the node's disk or the Kubernetes API. The
// plugin holds no credential of its own and no Kubernetes API access. The
// kubelet republishes volumes periodically: a republish writes new versions,
// removes a file the pod may no longer read, and applies the volume's
// freshness bound while the control plane can't be reached.
package csisecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// DriverName is the CSI driver pods name in their inline volumes.
const DriverName = "secrets.csi.trstctl.com"

// Volume attributes a pod sets on the inline volume.
const (
	// AttributeSecrets lists the volume's files as file=secret-name pairs,
	// separated by commas or newlines.
	AttributeSecrets = "secrets"
	// AttributeFreshness bounds how long the last values keep serving without
	// the control plane (a Go duration, 1m to 168h; 1h by default).
	AttributeFreshness = "freshness"
	// AttributeOnStale is what happens past the bound: remove (the default)
	// or keep.
	AttributeOnStale = "onStale"

	ephemeralAttribute    = "csi.storage.k8s.io/ephemeral"
	podNameAttribute      = "csi.storage.k8s.io/pod.name"
	podNamespaceAttribute = "csi.storage.k8s.io/pod.namespace"
	tokensKey             = "csi.storage.k8s.io/serviceAccount.tokens" // #nosec G101 -- the kubelet's request key name, not a credential (CWE-798)
)

const (
	defaultFreshness = time.Hour
	minFreshness     = time.Minute
	maxFreshness     = 7 * 24 * time.Hour
	maxItems         = 32
	// tmpfsBytes caps each volume's memory filesystem.
	tmpfsBytes = 8 << 20
	// sessionMargin is how long before its expiry a session is replaced.
	sessionMargin = 5 * time.Minute
	stateVersion  = 1
)

var (
	fileNameRE   = regexp.MustCompile(`^[A-Za-z0-9][-._A-Za-z0-9]{0,252}$`)
	secretNameRE = regexp.MustCompile(`^[A-Za-z0-9][-._A-Za-z0-9/]{0,510}$`)
	errRefused   = errors.New("csisecrets: the control plane refused the login")
)

// Config is the node plugin's configuration file.
type Config struct {
	Server string `yaml:"server" json:"server"`
	CAFile string `yaml:"ca_file" json:"ca_file"`
	Tenant string `yaml:"tenant" json:"tenant"`
	// LoginMethod is the machine-login method a pod's token is exchanged
	// through; "kubernetes" when empty.
	LoginMethod string `yaml:"login_method" json:"login_method"`
	// Audience is the audience of the service-account token the CSIDriver
	// requests; "trstctl" when empty.
	Audience string `yaml:"audience" json:"audience"`
	// StateDir keeps each volume's value-free state: the fetch time and the
	// versions written and reported.
	StateDir string `yaml:"state_dir" json:"state_dir"`
}

// Validate checks the configuration and fills its defaults.
func (c *Config) Validate() error {
	if c.LoginMethod == "" {
		c.LoginMethod = "kubernetes"
	}
	if c.Audience == "" {
		c.Audience = "trstctl"
	}
	switch {
	case c.Server == "" || c.Tenant == "" || c.StateDir == "":
		return errors.New("csisecrets: server, tenant and state_dir are required")
	case !filepath.IsAbs(c.StateDir):
		return errors.New("csisecrets: state_dir must be an absolute path")
	}
	return nil
}

// Mounter mounts the memory filesystem each volume's files live in.
type Mounter interface {
	// MountTmpfs mounts a private memory filesystem of at most size bytes,
	// with mode 0750, at the existing directory target.
	MountTmpfs(target string, size int) error
	IsMountPoint(target string) (bool, error)
	Unmount(target string) error
}

// Driver is the CSI Identity and Node service for secret volumes.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer
	cfg     Config
	client  *http.Client
	mounter Mounter
	log     *slog.Logger
	nodeID  string
	version string
	now     func() time.Time

	mu      sync.Mutex
	volumes map[string]*volume
}

// volume is one published volume's in-memory session. Its lock serializes
// the kubelet's calls for that volume.
type volume struct {
	mu      sync.Mutex
	session *session
}

type session struct {
	client  *secretrender.HTTPClient
	expires time.Time
}

// volumeState is a volume's value-free record, kept across plugin restarts so
// the freshness bound holds.
type volumeState struct {
	Version   int            `json:"version"`
	FetchedAt time.Time      `json:"fetched_at"`
	Versions  map[string]int `json:"versions,omitempty"`
	Reported  map[string]int `json:"reported,omitempty"`
}

type volumeItem struct{ file, name string }

type volumeSpec struct {
	items     []volumeItem
	freshness time.Duration
	keep      bool
}

// NewDriver returns a driver that reaches the control plane through client (a
// client built through a reviewed path: a CA-pinned transport or netsec's
// endpoint rule) and mounts through mounter.
func NewDriver(cfg Config, client *http.Client, mounter Mounter, log *slog.Logger, nodeID, version string) (*Driver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil || mounter == nil {
		return nil, errors.New("csisecrets: a control-plane client and a mounter are required")
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	return &Driver{cfg: cfg, client: client, mounter: mounter, log: log, nodeID: nodeID, version: version,
		now: time.Now, volumes: map[string]*volume{}}, nil
}

// GetPluginInfo names the driver.
func (d *Driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: DriverName, VendorVersion: d.version}, nil
}

// GetPluginCapabilities reports none: volumes are ephemeral and node-local, so
// there is no controller service.
func (d *Driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

// Probe reports the driver ready.
func (d *Driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}

// NodeGetCapabilities asks the kubelet for the pod's fsGroup on each publish
// (VOLUME_MOUNT_GROUP): the driver gives the files that group itself, so a
// non-root container can read them and a rewrite never loses the group.
func (d *Driver) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{Capabilities: []*csi.NodeServiceCapability{{
		Type: &csi.NodeServiceCapability_Rpc{Rpc: &csi.NodeServiceCapability_RPC{
			Type: csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP,
		}},
	}}}, nil
}

// NodeGetInfo reports this node.
func (d *Driver) NodeGetInfo(context.Context, *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: d.nodeID}, nil
}

// NodePublishVolume makes the volume hold the pod's secrets: on the first
// publish it mounts the memory filesystem; on every publish it reads the
// secrets with the pod's identity and writes the versions that changed.
func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	attributes := req.GetVolumeContext()
	if attributes[ephemeralAttribute] != "true" {
		return nil, status.Error(codes.InvalidArgument, "secret volumes are inline ephemeral volumes only")
	}
	spec, err := parseVolume(attributes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	namespace, pod := attributes[podNamespaceAttribute], attributes[podNameAttribute]
	if namespace == "" || pod == "" {
		return nil, status.Error(codes.InvalidArgument, "the CSIDriver must set podInfoOnMount")
	}
	target := req.GetTargetPath()
	if !cleanAbsolute(target) {
		return nil, status.Error(codes.InvalidArgument, "target path must be a clean absolute path")
	}
	id := req.GetVolumeId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id is required")
	}
	gid, err := mountGroup(req.GetVolumeCapability())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	podToken, err := d.podToken(req)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(podToken)

	v := d.volume(id)
	v.mu.Lock()
	defer v.mu.Unlock()
	st := d.loadState(id)
	if err := d.ensureMount(target, gid); err != nil {
		return nil, status.Errorf(codes.Internal, "mount the volume's memory filesystem: %v", err)
	}
	if err := d.refresh(ctx, v, st, id, spec, target, gid, podToken, consumerFor(namespace, pod)); err != nil {
		if st.FetchedAt.IsZero() && final(err) {
			// After a final error the kubelet takes a volume that was never
			// published as not mounted and won't unpublish it: leave nothing
			// mounted behind.
			_ = d.mounter.Unmount(target)
		}
		return nil, err
	}
	return &csi.NodePublishVolumeResponse{}, nil
}

// final reports whether the kubelet takes err as the end of the operation
// rather than an outcome still in progress, which it retries and unpublishes.
func final(err error) bool {
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.ResourceExhausted, codes.Aborted:
		return false
	}
	return true
}

// refresh brings the files up to date. It writes a value only into the memory
// filesystem, and only when its version changed.
func (d *Driver) refresh(ctx context.Context, v *volume, st *volumeState, id string, spec volumeSpec, target string, gid int, podToken []byte, consumer string) error {
	now := d.now()
	if v.session == nil || !now.Before(v.session.expires.Add(-sessionMargin)) {
		s, err := d.login(ctx, podToken, now)
		if errors.Is(err, errRefused) {
			d.stale(st, id, spec, target, now)
			return status.Error(codes.PermissionDenied, "the pod's service account could not log in to trstctl")
		}
		if err != nil {
			d.stale(st, id, spec, target, now)
			return status.Error(codes.Unavailable, err.Error())
		}
		v.drop()
		v.session = s
	}
	values := map[string][]byte{}
	defer func() {
		for _, value := range values {
			secret.Wipe(value)
		}
	}()
	versions := map[string]int{}
	for _, item := range spec.items {
		value, version, err := v.session.client.Fetch(ctx, item.name)
		if errors.Is(err, secretrender.ErrUnauthenticated) {
			// The session ended (it expired or was revoked): log in again on the
			// next publish; the last values serve within the freshness bound.
			v.drop()
			d.stale(st, id, spec, target, now)
			return status.Error(codes.Unavailable, "the control plane ended the volume's session; it logs in again on the next publish")
		}
		if errors.Is(err, secretrender.ErrRefused) {
			// The pod may no longer read it, or it is gone: stop serving it now.
			_ = os.Remove(filepath.Join(target, item.file))
			delete(st.Versions, item.name)
			d.saveState(id, st)
			d.log.Warn("removed a secret the pod may not read", "volume", id, "consumer", consumer, "secret", item.name)
			return status.Errorf(codes.PermissionDenied, "the pod may not read %s", item.name)
		}
		if err != nil {
			d.stale(st, id, spec, target, now)
			return status.Error(codes.Unavailable, err.Error())
		}
		values[item.file] = value
		versions[item.name] = version
	}
	written := 0
	for _, item := range spec.items {
		if _, err := os.Lstat(filepath.Join(target, item.file)); err == nil && st.Versions[item.name] == versions[item.name] {
			continue
		}
		if err := writeFile(target, item.file, values[item.file], gid); err != nil {
			return status.Errorf(codes.Internal, "write %s into the volume: %v", item.file, err)
		}
		written++
	}
	st.FetchedAt, st.Versions = now, versions
	d.saveState(id, st)
	if written > 0 {
		d.log.Info("wrote secrets into a volume", "volume", id, "consumer", consumer, "versions", versions)
	}
	if !maps.Equal(st.Reported, versions) {
		if err := v.session.client.Report(ctx, consumer, "injected", versions); err != nil {
			d.log.Warn("delivery report not sent; it is retried on the next publish", "volume", id, "error", err)
		} else {
			st.Reported = maps.Clone(versions)
			d.saveState(id, st)
		}
	}
	return nil
}

// stale applies the freshness bound when the values can't be refreshed: past
// it, the files go unless the volume keeps them.
func (d *Driver) stale(st *volumeState, id string, spec volumeSpec, target string, now time.Time) {
	if !spec.keep && !st.FetchedAt.IsZero() && now.After(st.FetchedAt.Add(spec.freshness)) && len(st.Versions) > 0 {
		for _, item := range spec.items {
			_ = os.Remove(filepath.Join(target, item.file))
		}
		st.Versions = nil
		d.saveState(id, st)
		d.log.Warn("removed secrets past their freshness bound", "volume", id, "fetched_at", st.FetchedAt, "freshness", spec.freshness)
	}
}

// NodeUnpublishVolume unmounts the memory filesystem, which discards the
// values, and forgets the volume. Unpublishing a volume that is gone succeeds.
func (d *Driver) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	target := req.GetTargetPath()
	if !cleanAbsolute(target) {
		return nil, status.Error(codes.InvalidArgument, "target path must be a clean absolute path")
	}
	id := req.GetVolumeId()
	v := d.volume(id)
	v.mu.Lock()
	if mounted, err := d.mounter.IsMountPoint(target); err == nil && mounted {
		if err := d.mounter.Unmount(target); err != nil {
			v.mu.Unlock()
			return nil, status.Errorf(codes.Internal, "unmount the volume: %v", err)
		}
	}
	if err := os.RemoveAll(target); err != nil {
		v.mu.Unlock()
		return nil, status.Errorf(codes.Internal, "remove the volume directory: %v", err)
	}
	_ = os.Remove(d.statePath(id))
	v.drop()
	v.mu.Unlock()
	d.mu.Lock()
	delete(d.volumes, id)
	d.mu.Unlock()
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (d *Driver) volume(id string) *volume {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.volumes[id]
	if !ok {
		v = &volume{}
		d.volumes[id] = v
	}
	return v
}

// drop forgets the volume's session and wipes its token.
func (v *volume) drop() {
	if v.session != nil {
		v.session.client.Wipe()
		v.session = nil
	}
}

// ensureMount mounts the memory filesystem at target unless it is already
// there, and refuses to go on when target is not a mount point: values are
// never written to a directory on the node's disk.
func (d *Driver) ensureMount(target string, gid int) error {
	if err := os.MkdirAll(target, 0o750); err != nil {
		return err
	}
	mounted, err := d.mounter.IsMountPoint(target)
	if err != nil {
		return err
	}
	if !mounted {
		if err := d.mounter.MountTmpfs(target, tmpfsBytes); err != nil {
			return err
		}
		if mounted, err = d.mounter.IsMountPoint(target); err != nil || !mounted {
			return errors.New("the memory filesystem is not mounted; refusing to write values to disk")
		}
	}
	if gid >= 0 {
		if err := os.Chown(target, -1, gid); err != nil {
			_ = d.mounter.Unmount(target)
			return err
		}
	}
	return nil
}

// login exchanges the pod's token for a session. Its idempotency key is the
// token's digest and a ten-minute window, so a retry or a restarted plugin
// within the window gets the same session back rather than another one, and a
// later login gets a fresh session even when the kubelet still holds the token.
func (d *Driver) login(ctx context.Context, podToken []byte, now time.Time) (*session, error) {
	body, err := json.Marshal(struct {
		Method     string           `json:"method"`
		Credential secret.JSONBytes `json:"credential"`
	}{d.cfg.LoginMethod, secret.JSONBytes(podToken)})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.Server+"/api/v1/secrets/login", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", d.cfg.Tenant)
	req.Header.Set("Idempotency-Key", "csi-secrets-login-"+crypto.SHA256Hex(podToken)[:32]+"-"+strconv.FormatInt(now.Unix()/600, 10))
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, errRefused
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the control plane answered %d to the login", resp.StatusCode)
	}
	var out struct {
		Token     secret.JSONBytes `json:"token"`
		ExpiresAt time.Time        `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil || len(out.Token) == 0 {
		secret.Wipe(out.Token)
		return nil, errors.New("the control plane's login answer could not be read")
	}
	client, err := secretrender.NewSessionHTTPClient(d.cfg.Server, d.cfg.Tenant, out.Token, d.client)
	if err != nil {
		secret.Wipe(out.Token)
		return nil, err
	}
	return &session{client: client, expires: out.ExpiresAt}, nil
}

// podToken returns the pod's service-account token for the configured
// audience, from the request's secrets (serviceAccountTokenInSecrets) or, on
// an older kubelet, its volume context.
func (d *Driver) podToken(req *csi.NodePublishVolumeRequest) ([]byte, error) {
	raw, ok := req.GetSecrets()[tokensKey]
	if !ok {
		raw, ok = req.GetVolumeContext()[tokensKey]
	}
	if !ok || raw == "" {
		return nil, status.Errorf(codes.InvalidArgument, "the CSIDriver must request a service-account token for the %q audience", d.cfg.Audience)
	}
	var tokens map[string]struct {
		Token secret.JSONBytes `json:"token"`
	}
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return nil, status.Error(codes.InvalidArgument, "the service-account tokens could not be read")
	}
	var token []byte
	for audience, t := range tokens {
		if audience == d.cfg.Audience {
			token = t.Token
			continue
		}
		secret.Wipe(t.Token)
	}
	if len(token) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "the CSIDriver must request a service-account token for the %q audience", d.cfg.Audience)
	}
	return token, nil
}

func (d *Driver) statePath(id string) string {
	return filepath.Join(d.cfg.StateDir, "volume-"+crypto.SHA256Hex([]byte(id))[:32]+".json")
}

func (d *Driver) loadState(id string) *volumeState {
	st := &volumeState{Version: stateVersion}
	raw, err := os.ReadFile(d.statePath(id))
	if err == nil {
		var saved volumeState
		if json.Unmarshal(raw, &saved) == nil && saved.Version == stateVersion {
			st = &saved
		}
	}
	return st
}

func (d *Driver) saveState(id string, st *volumeState) {
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := writeFile(d.cfg.StateDir, filepath.Base(d.statePath(id)), raw, -1); err != nil {
		d.log.Warn("volume state not saved", "volume", id, "error", err)
	}
}

// writeFile makes dir/name hold value, replacing it atomically: a private
// temporary file in the same directory is written, given mode 0440 and the
// pod's group, then renamed over the old file.
func writeFile(dir, name string, value []byte, gid int) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(value); err != nil {
		_ = tmp.Close()
		return err
	}
	if gid >= 0 {
		if err := tmp.Chown(-1, gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Chmod(0o440); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// parseVolume reads the volume's attributes.
func parseVolume(attributes map[string]string) (volumeSpec, error) {
	spec := volumeSpec{freshness: defaultFreshness}
	files := map[string]bool{}
	for _, field := range strings.FieldsFunc(attributes[AttributeSecrets], func(r rune) bool { return r == ',' || r == '\n' }) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		file, name, ok := strings.Cut(field, "=")
		file, name = strings.TrimSpace(file), strings.TrimSpace(name)
		switch {
		case !ok || !fileNameRE.MatchString(file):
			return spec, fmt.Errorf("volume attribute %s takes file=secret-name pairs; %q is not one", AttributeSecrets, field)
		case !validSecretName(name):
			return spec, fmt.Errorf("volume attribute %s: %q is not a secret name", AttributeSecrets, name)
		case files[file]:
			return spec, fmt.Errorf("volume attribute %s names the file %s twice", AttributeSecrets, file)
		}
		files[file] = true
		spec.items = append(spec.items, volumeItem{file: file, name: name})
	}
	if len(spec.items) == 0 || len(spec.items) > maxItems {
		return spec, fmt.Errorf("volume attribute %s must name 1 to %d secrets", AttributeSecrets, maxItems)
	}
	if raw := attributes[AttributeFreshness]; raw != "" {
		freshness, err := time.ParseDuration(raw)
		if err != nil || freshness < minFreshness || freshness > maxFreshness {
			return spec, fmt.Errorf("volume attribute %s must be a duration from 1m to 168h", AttributeFreshness)
		}
		spec.freshness = freshness
	}
	switch attributes[AttributeOnStale] {
	case "", "remove":
	case "keep":
		spec.keep = true
	default:
		return spec, fmt.Errorf("volume attribute %s is remove or keep", AttributeOnStale)
	}
	return spec, nil
}

func validSecretName(name string) bool {
	if !secretNameRE.MatchString(name) || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func mountGroup(capability *csi.VolumeCapability) (int, error) {
	raw := capability.GetMount().GetVolumeMountGroup()
	if raw == "" {
		return -1, nil
	}
	gid, err := strconv.Atoi(raw)
	if err != nil || gid < 0 {
		return 0, fmt.Errorf("volume mount group %q is not a group id", raw)
	}
	return gid, nil
}

// consumerFor names the pod in delivery reports, within the report's
// 128-character label.
func consumerFor(namespace, pod string) string {
	consumer := "pod:" + namespace + "/" + pod
	if len(consumer) <= 128 {
		return consumer
	}
	return consumer[:111] + "-" + crypto.SHA256Hex([]byte(consumer))[:16]
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

// Serve listens on the Unix socket at socketPath (the kubelet's plugin
// registration names it) and serves until ctx ends.
func (d *Driver) Serve(ctx context.Context, socketPath string) error {
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("csisecrets: remove stale socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return fmt.Errorf("csisecrets: socket directory: %w", err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("csisecrets: listen on %s: %w", socketPath, err)
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
