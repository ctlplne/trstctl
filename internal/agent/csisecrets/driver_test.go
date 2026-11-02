// SPDX-License-Identifier: BUSL-1.1

// The node plugin serves Linux nodes only; its tests read Unix file ownership.

//go:build unix

package csisecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
)

// fakeMounter records memory-filesystem mounts; broken leaves a "mounted"
// directory looking like plain disk.
type fakeMounter struct {
	mu      sync.Mutex
	mounted map[string]bool
	mounts  int
	broken  bool
}

func (m *fakeMounter) MountTmpfs(target string, size int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mounts++
	if !m.broken {
		m.mounted[target] = true
	}
	return nil
}

func (m *fakeMounter) IsMountPoint(target string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mounted[target], nil
}

func (m *fakeMounter) Unmount(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mounted, target)
	return nil
}

// controlPlane is a stand-in for the served login, read and report routes: a
// pod token logs in as its service account, which may read some names.
type controlPlane struct {
	mu       sync.Mutex
	down     bool
	tokens   map[string]string          // pod token -> principal
	readable map[string]map[string]bool // principal -> secret names
	values   map[string]string
	versions map[string]int
	sessions map[string]string // session token -> principal
	expires  time.Time         // the expiry of the sessions it issues
	logins   int
	reports  []string
	srv      *httptest.Server
}

func newControlPlane(t *testing.T) *controlPlane {
	cp := &controlPlane{tokens: map[string]string{}, readable: map[string]map[string]bool{},
		values: map[string]string{}, versions: map[string]int{}, sessions: map[string]string{},
		expires: time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC)}
	cp.srv = httptest.NewServer(http.HandlerFunc(cp.serve))
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *controlPlane) set(name, value string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.values[name] = value
	cp.versions[name]++
}

func (cp *controlPlane) serve(w http.ResponseWriter, r *http.Request) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("X-Tenant-ID") != "tenant-a" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/login":
		var body struct{ Method, Credential string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		principal, ok := cp.tokens[body.Credential]
		if !ok || body.Method != "kubernetes" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "csi-secrets-login-"+crypto.SHA256Hex([]byte(body.Credential))[:32]+"-") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cp.logins++
		session := "session-" + strconv.Itoa(cp.logins)
		cp.sessions[session] = principal
		_ = json.NewEncoder(w).Encode(map[string]any{"token": session, "expires_at": cp.expires})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/secrets/store/"):
		principal, ok := cp.sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/store/")
		if !cp.readable[principal][name] || r.URL.Query().Get("resolve") != "true" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": cp.values[name], "version": cp.versions[name]})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/deliveries":
		if _, ok := cp.sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]; !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			Consumer, State string
			Secrets         []struct {
				Name    string
				Version int
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, s := range body.Secrets {
			cp.reports = append(cp.reports, body.Consumer+" "+body.State+" "+s.Name+" v"+strconv.Itoa(s.Version))
		}
		_, _ = w.Write([]byte("{}"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (cp *controlPlane) take() (logins int, reports []string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	logins, reports = cp.logins, cp.reports
	cp.reports = nil
	return logins, reports
}

func publishRequest(target, token, group string, attributes map[string]string) *csi.NodePublishVolumeRequest {
	volumeContext := map[string]string{
		"csi.storage.k8s.io/ephemeral":           "true",
		"csi.storage.k8s.io/pod.name":            "api-0",
		"csi.storage.k8s.io/pod.namespace":       "payments",
		"csi.storage.k8s.io/serviceAccount.name": "api",
	}
	maps.Copy(volumeContext, attributes)
	tokens, _ := json.Marshal(map[string]any{"trstctl": map[string]string{"token": token, "expirationTimestamp": "2026-11-02T01:00:00Z"}})
	return &csi.NodePublishVolumeRequest{
		VolumeId: "csi-0f1e2d", TargetPath: target, VolumeContext: volumeContext,
		Secrets: map[string]string{"csi.storage.k8s.io/serviceAccount.tokens": string(tokens)},
		VolumeCapability: &csi.VolumeCapability{AccessType: &csi.VolumeCapability_Mount{
			Mount: &csi.VolumeCapability_MountVolume{VolumeMountGroup: group}}},
	}
}

func newTestDriver(t *testing.T, cp *controlPlane, mounter *fakeMounter, stateDir string, logs *bytes.Buffer) *Driver {
	t.Helper()
	d, err := NewDriver(Config{Server: cp.srv.URL, Tenant: "tenant-a", StateDir: stateDir}, cp.srv.Client(), mounter,
		slog.New(slog.NewTextHandler(logs, nil)), "node-a", "test")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func codeOf(err error) codes.Code { return status.Code(err) }

// A238: a pod's volume is filled with the pod's own identity, in a memory
// filesystem, with mode 0440 and the pod's fsGroup; a republish writes only a
// changed version and reports it as injected for the pod; a session is reused
// until it nears expiry; a secret the pod may no longer read is removed at
// once; unpublishing unmounts and forgets the volume.
func TestDriverServesSecretsWithThePodsOwnIdentityA238(t *testing.T) {
	cp := newControlPlane(t)
	cp.tokens["pod-token-1"] = "system:serviceaccount:payments:api"
	cp.readable["system:serviceaccount:payments:api"] = map[string]bool{"payments/prod/db-password": true}
	cp.set("payments/prod/db-password", "pw-one")
	cp.set("payments/prod/other-team", "not-for-this-pod")
	mounter := &fakeMounter{mounted: map[string]bool{}}
	var logs bytes.Buffer
	stateDir := filepath.Join(t.TempDir(), "state")
	d := newTestDriver(t, cp, mounter, stateDir, &logs)
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	target := filepath.Join(t.TempDir(), "pods", "uid-1", "volumes", "kubernetes.io~csi", "secrets", "mount")
	group := strconv.Itoa(os.Getgid())
	req := publishRequest(target, "pod-token-1", group, map[string]string{"secrets": "password=payments/prod/db-password"})
	ctx := t.Context()

	if _, err := d.NodePublishVolume(ctx, req); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(target, "password")
	raw, err := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil || string(raw) != "pw-one" {
		t.Fatalf("file %q err %v", raw, err)
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0o440 || int(info.Sys().(*syscall.Stat_t).Gid) != os.Getgid() || !mounter.mounted[target] {
		t.Fatalf("mode %v gid %d mounted %v", info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid, mounter.mounted[target])
	}
	if logins, reports := cp.take(); logins != 1 || len(reports) != 1 || reports[0] != "pod:payments/api-0 injected payments/prod/db-password v1" {
		t.Fatalf("logins %d reports %v", logins, reports)
	}

	// An unchanged republish logs in no more, rewrites nothing, reports nothing.
	now = now.Add(time.Minute)
	if _, err := d.NodePublishVolume(ctx, req); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.Stat(file); !os.SameFile(info, again) {
		t.Fatal("an unchanged republish rewrote the file")
	}
	if logins, reports := cp.take(); logins != 1 || len(reports) != 0 {
		t.Fatalf("unchanged republish: logins %d reports %v", logins, reports)
	}

	// A new version is written atomically and reported.
	cp.set("payments/prod/db-password", "pw-two")
	if _, err := d.NodePublishVolume(ctx, req); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(file); string(raw) != "pw-two" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("after rotation, file %q", raw)
	}
	if _, reports := cp.take(); len(reports) != 1 || !strings.HasSuffix(reports[0], "v2") {
		t.Fatalf("rotation reports %v", reports)
	}

	// Near its expiry the session is replaced with a fresh login.
	cp.mu.Lock()
	cp.expires = time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC)
	cp.mu.Unlock()
	now = time.Date(2026, 11, 2, 0, 56, 0, 0, time.UTC)
	if _, err := d.NodePublishVolume(ctx, req); err != nil {
		t.Fatal(err)
	}
	if logins, _ := cp.take(); logins != 2 {
		t.Fatalf("a session near its expiry was not replaced (logins %d)", logins)
	}

	// An ended session (here revoked) is not a lost read: the file stays, and
	// the next publish logs in again.
	cp.mu.Lock()
	clear(cp.sessions)
	cp.mu.Unlock()
	if _, err := d.NodePublishVolume(ctx, req); codeOf(err) != codes.Unavailable {
		t.Fatalf("an ended session answered %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("an ended session removed the file")
	}
	if _, err := d.NodePublishVolume(ctx, req); err != nil {
		t.Fatal(err)
	}
	if logins, _ := cp.take(); logins != 3 {
		t.Fatalf("after an ended session, logins %d", logins)
	}

	// The pod loses access: the next publish removes the file.
	cp.mu.Lock()
	cp.readable["system:serviceaccount:payments:api"] = map[string]bool{}
	cp.mu.Unlock()
	if _, err := d.NodePublishVolume(ctx, req); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("a revoked read answered %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("a secret the pod may no longer read is still in its volume")
	}

	// Another team's secret is refused and never written.
	other := publishRequest(target, "pod-token-1", group, map[string]string{"secrets": "token=payments/prod/other-team"})
	if _, err := d.NodePublishVolume(ctx, other); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("another team's secret answered %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "token")); !os.IsNotExist(err) {
		t.Fatal("a secret the pod may not read was written")
	}

	if _, err := d.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{VolumeId: req.VolumeId, TargetPath: target}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) || mounter.mounted[target] {
		t.Fatal("unpublish left the volume behind")
	}
	if entries, _ := os.ReadDir(stateDir); len(entries) != 0 {
		t.Fatalf("unpublish left state %v", entries)
	}
	if _, err := d.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{VolumeId: req.VolumeId, TargetPath: target}); err != nil {
		t.Fatalf("a second unpublish: %v", err)
	}
	for _, value := range []string{"pw-one", "pw-two", "not-for-this-pod", "pod-token-1", "session-1", "session-2"} {
		if strings.Contains(logs.String(), value) {
			t.Fatalf("%s reached the logs: %s", value, logs.String())
		}
	}
}

// A238: through a control-plane outage the last values serve until the
// volume's freshness bound, which a restarted plugin still honors; past it the
// file goes (unless the volume keeps it) and comes back with the control
// plane.
func TestDriverHonorsTheFreshnessBoundAcrossARestartA238(t *testing.T) {
	cp := newControlPlane(t)
	cp.tokens["pod-token-1"] = "system:serviceaccount:payments:api"
	cp.readable["system:serviceaccount:payments:api"] = map[string]bool{"payments/prod/api-key": true}
	cp.set("payments/prod/api-key", "key-one")
	mounter := &fakeMounter{mounted: map[string]bool{}}
	var logs bytes.Buffer
	stateDir := filepath.Join(t.TempDir(), "state")
	start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	targets := map[string]string{}
	for _, onStale := range []string{"remove", "keep"} {
		targets[onStale] = filepath.Join(t.TempDir(), onStale, "mount")
	}
	request := func(onStale string) *csi.NodePublishVolumeRequest {
		req := publishRequest(targets[onStale], "pod-token-1", "", map[string]string{
			"secrets": "api-key=payments/prod/api-key", "freshness": "5m", "onStale": onStale})
		req.VolumeId = "csi-" + onStale
		return req
	}
	d := newTestDriver(t, cp, mounter, stateDir, &logs)
	d.now = func() time.Time { return start }
	for onStale := range targets {
		if _, err := d.NodePublishVolume(t.Context(), request(onStale)); err != nil {
			t.Fatal(err)
		}
	}
	cp.mu.Lock()
	cp.down = true
	cp.mu.Unlock()
	d.now = func() time.Time { return start.Add(4 * time.Minute) }
	if _, err := d.NodePublishVolume(t.Context(), request("remove")); codeOf(err) != codes.Unavailable {
		t.Fatalf("during the outage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targets["remove"], "api-key")); err != nil {
		t.Fatal("the file was removed inside its freshness bound")
	}
	// A restarted plugin has no session and no memory of the fetch, but its
	// state file holds the fetch time.
	restarted := newTestDriver(t, cp, mounter, stateDir, &logs)
	restarted.now = func() time.Time { return start.Add(6 * time.Minute) }
	for onStale := range targets {
		if _, err := restarted.NodePublishVolume(t.Context(), request(onStale)); codeOf(err) != codes.Unavailable {
			t.Fatalf("past the bound (%s): %v", onStale, err)
		}
	}
	if _, err := os.Stat(filepath.Join(targets["remove"], "api-key")); !os.IsNotExist(err) {
		t.Fatal("a file past its freshness bound survived a plugin restart")
	}
	if _, err := os.Stat(filepath.Join(targets["keep"], "api-key")); err != nil {
		t.Fatal("onStale keep removed the file")
	}
	cp.mu.Lock()
	cp.down = false
	cp.mu.Unlock()
	if _, err := restarted.NodePublishVolume(t.Context(), request("remove")); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(targets["remove"], "api-key")); string(raw) != "key-one" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("after recovery, file %q", raw)
	}
	if strings.Contains(logs.String(), "key-one") {
		t.Fatalf("a value reached the logs: %s", logs.String())
	}
}

// A238: the driver serves only inline ephemeral volumes with well-formed
// attributes and the pod's token, refuses a pod the control plane doesn't
// accept, and never writes a value outside a memory filesystem.
func TestDriverRefusesUnsafeVolumesA238(t *testing.T) {
	cp := newControlPlane(t)
	cp.tokens["pod-token-1"] = "system:serviceaccount:payments:api"
	cp.readable["system:serviceaccount:payments:api"] = map[string]bool{"payments/prod/db-password": true}
	cp.set("payments/prod/db-password", "pw-one")
	var logs bytes.Buffer
	d := newTestDriver(t, cp, &fakeMounter{mounted: map[string]bool{}}, filepath.Join(t.TempDir(), "state"), &logs)
	target := filepath.Join(t.TempDir(), "mount")
	good := map[string]string{"secrets": "password=payments/prod/db-password"}
	for name, mutate := range map[string]func(*csi.NodePublishVolumeRequest){
		"not ephemeral":   func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, "csi.storage.k8s.io/ephemeral") },
		"no secrets":      func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, "secrets") },
		"path in file":    func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["secrets"] = "../x=payments/prod/db-password" },
		"hidden file":     func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["secrets"] = ".x=payments/prod/db-password" },
		"dot-dot name":    func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["secrets"] = "x=payments/../db-password" },
		"duplicate file":  func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["secrets"] = "x=a/b,x=a/c" },
		"short freshness": func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["freshness"] = "10s" },
		"unknown onStale": func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["onStale"] = "panic" },
		"no pod info":     func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, "csi.storage.k8s.io/pod.name") },
		"relative target": func(r *csi.NodePublishVolumeRequest) { r.TargetPath = "relative/mount" },
		"no token":        func(r *csi.NodePublishVolumeRequest) { r.Secrets = nil },
		"other audience": func(r *csi.NodePublishVolumeRequest) {
			r.Secrets = map[string]string{tokensKey: `{"vault":{"token":"x"}}`} // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		"bad mount group":  func(r *csi.NodePublishVolumeRequest) { r.VolumeCapability.GetMount().VolumeMountGroup = "staff" },
		"too many secrets": func(r *csi.NodePublishVolumeRequest) { r.VolumeContext["secrets"] = manyItems(33) },
	} {
		req := publishRequest(target, "pod-token-1", "", good)
		mutate(req)
		if _, err := d.NodePublishVolume(t.Context(), req); codeOf(err) != codes.InvalidArgument {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A pod whose token the control plane doesn't accept gets nothing, and its
	// never-published volume is left unmounted: the kubelet won't unpublish it.
	if _, err := d.NodePublishVolume(t.Context(), publishRequest(target, "pod-token-unknown", "", good)); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("an unaccepted pod: %v", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 || d.mounter.(*fakeMounter).mounted[target] {
		t.Fatalf("a refused pod's volume holds %v (mounted %v)", entries, d.mounter.(*fakeMounter).mounted[target])
	}
	// A mount that didn't take leaves the directory on disk: nothing is written.
	broken := newTestDriver(t, cp, &fakeMounter{mounted: map[string]bool{}, broken: true}, filepath.Join(t.TempDir(), "state"), &logs)
	diskTarget := filepath.Join(t.TempDir(), "disk")
	if _, err := broken.NodePublishVolume(t.Context(), publishRequest(diskTarget, "pod-token-1", "", good)); codeOf(err) != codes.Internal {
		t.Fatalf("a failed mount: %v", err)
	}
	if entries, _ := os.ReadDir(diskTarget); len(entries) != 0 {
		t.Fatalf("values were written to disk: %v", entries)
	}
}

func manyItems(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = "f" + strconv.Itoa(i) + "=payments/prod/s" + strconv.Itoa(i)
	}
	return strings.Join(items, ",")
}

// A238: over the kubelet's Unix socket the driver names itself and asks for
// the pod's fsGroup.
func TestDriverServesTheKubeletSocketA238(t *testing.T) {
	cp := newControlPlane(t)
	var logs bytes.Buffer
	d := newTestDriver(t, cp, &fakeMounter{mounted: map[string]bool{}}, filepath.Join(t.TempDir(), "state"), &logs)
	// Unix socket paths are capped near 104 bytes; the test's own temp dir
	// name is too long for one.
	socketDir, err := os.MkdirTemp("", "csi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "csi.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, socket) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the driver never opened its socket")
		}
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	info, err := csi.NewIdentityClient(conn).GetPluginInfo(t.Context(), &csi.GetPluginInfoRequest{})
	if err != nil || info.GetName() != DriverName {
		t.Fatalf("plugin info %v err %v", info, err)
	}
	capabilities, err := csi.NewNodeClient(conn).NodeGetCapabilities(t.Context(), &csi.NodeGetCapabilitiesRequest{})
	if err != nil || len(capabilities.GetCapabilities()) != 1 ||
		capabilities.GetCapabilities()[0].GetRpc().GetType() != csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP {
		t.Fatalf("node capabilities %v err %v", capabilities, err)
	}
}
