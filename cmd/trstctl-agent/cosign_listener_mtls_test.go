// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/succession/agent"
	"trstctl.com/trstctl/internal/succession/agent/cosignpb"
)

// callCoSignF261 sends opaque field bytes. A service that received the call
// answers InvalidArgument (it never signs undecodable bytes); a refused caller
// never reaches it.
func callCoSignF261(t *testing.T, target string, fields []byte, opts ...grpc.DialOption) codes.Code {
	t.Helper()
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cosignpb.NewCoSignerServiceClient(conn).CoSign(ctx, &cosignpb.CoSignRequest{Purpose: agent.Purpose, Fields: fields})
	return status.Code(err)
}

// F261: the TCP listener serves only the pinned control-plane key. Plaintext and
// foreign-CA callers are refused at the handshake; the pinned caller reaches the
// service, and an oversized request is refused before it reaches the signer.
func TestWorkloadCoSignRequiresThePinnedCaller(t *testing.T) {
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "cosign.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "cosign.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	addr := freeLoopbackAddrF261(t)
	run := startCoSignF261(t, workloadCoSignConfig{
		Listen: addr, DeploymentScope: "spiffe://d", IdentityID: "spiffe://d/app", TenantID: "tenant-a",
		PredecessorKeyPath: writePredecessorKeyF261(t), PeerUID: -1,
		TLSCertFile: material.Signer.CertFile, TLSKeyFile: material.Signer.KeyFile,
		PeerCAFile: material.Signer.PeerCAFile, PeerPinHex: material.Signer.PeerPinHex,
	})
	if err, ended := run.wait(500 * time.Millisecond); ended {
		t.Fatalf("pinned co-sign listener stopped: %v", err)
	}
	target := "passthrough:///" + addr
	if code := callCoSignF261(t, target, []byte("opaque"), grpc.WithTransportCredentials(insecure.NewCredentials())); code != codes.Unavailable {
		t.Fatalf("plaintext caller code = %v, want Unavailable (handshake refused)", code)
	}
	foreignCreds, err := mtls.SignerClientCredentials(mtls.SignerPeerConfig{
		CertFile: foreign.ControlPlane.CertFile, KeyFile: foreign.ControlPlane.KeyFile,
		PeerCAFile: material.ControlPlane.PeerCAFile, PeerPinHex: material.ControlPlane.PeerPinHex,
	}, "cosign.test")
	if err != nil {
		t.Fatal(err)
	}
	if code := callCoSignF261(t, target, []byte("opaque"), grpc.WithTransportCredentials(foreignCreds)); code != codes.Unavailable {
		t.Fatalf("foreign-CA caller code = %v, want Unavailable (handshake refused)", code)
	}
	pinned, err := mtls.SignerClientCredentials(material.ControlPlane, "cosign.test")
	if err != nil {
		t.Fatal(err)
	}
	if code := callCoSignF261(t, target, []byte("opaque"), grpc.WithTransportCredentials(pinned)); code != codes.InvalidArgument {
		t.Fatalf("pinned caller code = %v, want InvalidArgument from the service itself", code)
	}
	if code := callCoSignF261(t, target, make([]byte, 2*coSignMaxMessageBytes), grpc.WithTransportCredentials(pinned)); code != codes.ResourceExhausted {
		t.Fatalf("oversized request code = %v, want ResourceExhausted (AN-7 bound)", code)
	}
}

// F261: a TCP listener without the pinned mutual-TLS material refuses to start,
// before the predecessor key is ever loaded.
func TestWorkloadCoSignNetworkListenerWithoutTLSRefusesToStart(t *testing.T) {
	err := runWorkloadCoSign(context.Background(), workloadCoSignConfig{
		Listen: freeLoopbackAddrF261(t), PredecessorKeyPath: filepath.Join(t.TempDir(), "missing.key"), PeerUID: -1,
	})
	if err == nil || !strings.Contains(err.Error(), "mutual TLS") || strings.Contains(err.Error(), "predecessor key") {
		t.Fatalf("plain TCP co-sign start = %v; want a mutual-TLS refusal before the key is read", err)
	}
}

// F261: the local listener is not left to the process umask. The socket is 0600
// in a 0700 directory (a loose pre-existing directory is tightened), and only the
// allowed uid may connect; a peer whose uid cannot be read is refused too.
func TestWorkloadCoSignUnixSocketIsOwnerOnly(t *testing.T) {
	dir, err := os.MkdirTemp("", "cosign")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockDir := filepath.Join(dir, "run")
	if err := os.Mkdir(sockDir, 0o777); err != nil { // #nosec G301 -- deliberately loose, to prove it is tightened (CWE-276)
		t.Fatal(err)
	}
	if err := os.Chmod(sockDir, 0o777); err != nil { // #nosec G302 -- deliberately loose, to prove it is tightened (CWE-276)
		t.Fatal(err)
	}
	path := filepath.Join(sockDir, "c.sock")
	lis, err := listenWorkloadCoSign("unix", path, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("co-sign socket mode = %s, want 0600", strconv.FormatUint(uint64(mode), 8))
	}
	dinfo, err := os.Stat(sockDir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := dinfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("co-sign socket directory mode = %s, want 0700", strconv.FormatUint(uint64(mode), 8))
	}

	for _, tc := range []struct {
		name string
		uid  func(net.Conn) (int, error)
	}{
		{"foreign uid", func(net.Conn) (int, error) { return os.Geteuid() + 1, nil }},
		{"unreadable peer", func(net.Conn) (int, error) { return 0, errors.New("no peer credentials") }},
	} {
		inner, err := net.Listen("unix", filepath.Join(dir, "p.sock"))
		if err != nil {
			t.Fatal(err)
		}
		guarded := &coSignPeerListener{Listener: inner, allowedUID: os.Geteuid(), peerUID: tc.uid}
		gs := grpc.NewServer()
		cosignpb.RegisterCoSignerServiceServer(gs, cosignpb.UnimplementedCoSignerServiceServer{})
		go func() { _ = gs.Serve(guarded) }()
		code := callCoSignF261(t, "unix://"+filepath.Join(dir, "p.sock"), []byte("x"), grpc.WithTransportCredentials(insecure.NewCredentials()))
		gs.Stop()
		_ = os.Remove(filepath.Join(dir, "p.sock"))
		if code != codes.Unavailable {
			t.Fatalf("%s reached the co-sign service (code %v); want the connection refused", tc.name, code)
		}
	}
}
