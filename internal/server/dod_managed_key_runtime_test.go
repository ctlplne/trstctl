//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodManagedKeyProbe                         = "independent managed-key device signature proof"
	dodManagedKeyRestartProbe                  = "post-restart TPM custody signature proof"
	dodManagedKeyPostgresImage                 = "postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229"
	dodManagedKeyPostgresUser                  = "trstctl_dod"
	dodManagedKeyPostgresDatabase              = "trstctl_dod"
	dodManagedKeyPostgresPassword              = "trstctl-dod-isolated-postgres-password"
	dodManagedKeySignTokenHelperEnv            = "TRSTCTL_DOD_MANAGED_KEY_SIGN_TOKEN_HELPER"
	dodManagedKeySignTokenSecretFileEnv        = "TRSTCTL_DOD_MANAGED_KEY_SIGN_TOKEN_SECRET_FILE"
	dodRuntimeDockerHostEnv                    = "TRSTCTL_RUNTIME_DOCKER_HOST"
	dodManagedKeyRuntimePlatform               = "linux/amd64"
	dodManagedKeyLoopbackProxyPort             = 18080
	dodTPMOwnerPersistentFirst          uint64 = 0x81000000
	dodTPMOwnerPersistentLast           uint64 = 0x817fffff
	dodPKCS11KeyIDHexLength                    = 32
)

type dodManagedKeyArtifacts struct {
	licenseFile      string
	licensePublicKey []byte
	network          string
	postgresDSN      string
	root             string
	repo             string
	runtimeImage     string
}

type dodManagedKeyFileState struct {
	Mode       os.FileMode
	Size       int64
	ModifiedNS int64
}

type dodManagedKeyWire struct {
	KeyID       string           `json:"key_id"`
	Algorithm   crypto.Algorithm `json:"algorithm"`
	State       string           `json:"state"`
	PublicDER   []byte           `json:"public_der"`
	Extractable bool             `json:"extractable"`
}

type dodManagedKeyReadback struct {
	KeyID        string `json:"key_id"`
	State        string `json:"state"`
	PublicDER    string `json:"public_der"`
	Signature    string `json:"signature"`
	Digest       string `json:"digest"`
	ExportDenial string `json:"private_export"`
}

type dodTPMPublicWitness struct {
	PublicDER []byte
	Name      []byte
}

type dodManagedKeySubstrateConfig struct {
	Endpoint          string `json:"endpoint"`
	ContainerEndpoint string `json:"container_endpoint"`
	AWSAccessKey      string `json:"aws_access_key_id"`
	AWSSecretKey      string `json:"aws_secret_access_key"`
	AWSRegion         string `json:"aws_region"`
	AzureToken        string `json:"azure_token"`
	GCPToken          string `json:"gcp_token"`
	GCPParent         string `json:"gcp_parent"`
}

type dodManagedKeyRuntime struct {
	t                       *testing.T
	entryID                 string
	provider                string
	external                *proof.ExternalSubstrate
	artifacts               dodManagedKeyArtifacts
	dir                     string
	containerName           string
	signerPort              int
	serverPort              int
	control                 *proof.ShippedProcess
	token                   string
	approvalTokens          []string
	approvalSubjects        []string
	controlProviderEndpoint string
	env                     []string
	mtlsMaterial            *mtls.SignerPeerMaterial
	tpmForeignHandle        string
	tpmGenerateOperationTag string
	closed                  bool
}

// TestDODManagedKeyProductionAssembly launches the real licensed cmd/trstctl
// composition and the exact cgo signer image built by the release Dockerfile.
// Each route crosses the durable PostgreSQL outbox into that separate signer.
// Rotation is submitted while the signer is stopped, then completes after the
// same signer journal/device state restarts, proving real redelivery/recovery.
func TestDODManagedKeyProductionAssembly(t *testing.T) {
	artifacts := dodBuildManagedKeyArtifacts(t)
	only := os.Getenv("TRSTCTL_HSM_PROOF_ONLY")
	if only == "" {
		only = proof.OnlyExpectation(t)
	}
	if only == "" || only == "hsm_kms.runtime" {
		runtimeEntry := proof.StartCommand(t, "hsm_kms.runtime")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.runtime", config.ManagedKeyProviderAWS, runtimeEntry, runtimeEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.aws_kms" {
		awsEntry := proof.StartCommand(t, "hsm_kms.aws_kms")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.aws_kms", config.ManagedKeyProviderAWS, awsEntry, awsEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.azure_key_vault" {
		azureEntry := proof.StartCommand(t, "hsm_kms.azure_key_vault")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.azure_key_vault", config.ManagedKeyProviderAzureKeyVault, azureEntry, azureEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.gcp_kms" {
		gcpEntry := proof.StartCommand(t, "hsm_kms.gcp_kms")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.gcp_kms", config.ManagedKeyProviderGCPKMS, gcpEntry, gcpEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.pkcs11" {
		pkcsEntry := proof.StartCommand(t, "hsm_kms.pkcs11")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.pkcs11", config.ManagedKeyProviderPKCS11, pkcsEntry, pkcsEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.tpm2" {
		tpmEntry := proof.StartCommand(t, "hsm_kms.tpm2")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.tpm2", config.ManagedKeyProviderTPM2, tpmEntry, tpmEntry.Endpoint())
	}
	if only == "" || only == "hsm_kms.yubihsm2" {
		yubiEntry := proof.StartCommand(t, "hsm_kms.yubihsm2")
		dodRunManagedKeyProvider(t, artifacts, "hsm_kms.yubihsm2", config.ManagedKeyProviderYubiHSM2, yubiEntry, yubiEntry.Endpoint())
	}
}

// TestDODManagedKeySignTokenHelper is invoked as a separate process by the
// production AuthTokenCommand seam. It holds the approval-authority side of the
// content-authorization secret; the control-plane process receives only the
// command path and never maps the shared secret into its address space.
func TestDODManagedKeySignTokenHelper(t *testing.T) {
	if os.Getenv(dodManagedKeySignTokenHelperEnv) != "1" {
		return
	}
	var request struct {
		KeyHandle string `json:"key_handle"`
		Purpose   int32  `json:"purpose"`
		Hash      string `json:"hash"`
		Padding   string `json:"padding"`
		DigestB64 string `json:"digest_b64"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		t.Fatalf("decode signer authorization intent: %v", err)
	}
	digest, err := base64.StdEncoding.DecodeString(request.DigestB64)
	if err != nil {
		t.Fatalf("decode signer authorization digest: %v", err)
	}
	authorizer, err := signing.LoadOrCreateAuthorizer(os.Getenv(dodManagedKeySignTokenSecretFileEnv))
	if err != nil {
		t.Fatalf("load independent signer authorizer: %v", err)
	}
	defer authorizer.Destroy()
	token, err := authorizer.Authorize(crypto.SignIntent{
		KeyHandle: request.KeyHandle,
		Purpose:   request.Purpose,
		Hash:      crypto.Hash(request.Hash),
		Padding:   crypto.RSAPadding(request.Padding),
		Digest:    digest,
	})
	if err != nil {
		t.Fatalf("authorize signer intent: %v", err)
	}
	if _, err := os.Stdout.WriteString(base64.StdEncoding.EncodeToString(token)); err != nil {
		t.Fatalf("write signer authorization token: %v", err)
	}
	os.Exit(0)
}

func dodBuildManagedKeyArtifacts(t *testing.T) dodManagedKeyArtifacts {
	t.Helper()
	root := t.TempDir()
	repo := dodManagedKeyRepoRoot(t)
	// A prior buggy proof omitted signer state env vars, so cmd/trstctl used its
	// package cwd and created internal/server/data. Preserve any pre-existing tree
	// exactly as found and fail if this launched proof changes it; cleanup must not
	// hide the regression by deleting evidence.
	cwdDataRoot := filepath.Join(repo, "internal", "server", "data")
	cwdDataBefore, err := dodManagedKeySnapshotTree(cwdDataRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cwdDataAfter, snapshotErr := dodManagedKeySnapshotTree(cwdDataRoot)
		if snapshotErr != nil {
			t.Errorf("snapshot managed-key proof cwd data after run: %v", snapshotErr)
			return
		}
		if !dodManagedKeySnapshotsEqual(cwdDataBefore, cwdDataAfter) {
			t.Errorf("launched managed-key proof changed default cwd data tree; before=%v after=%v", cwdDataBefore, cwdDataAfter)
		}
	})
	privateKey, publicKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	claims := license.Claims{
		V: 1, ID: "dod-managed-key-license", Customer: "DoD runtime", Tier: license.TierEnterprise,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	rawLicense, err := license.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	licenseFile := filepath.Join(root, "enterprise-license.json")
	if err := os.WriteFile(licenseFile, rawLicense, 0o600); err != nil {
		t.Fatal(err)
	}
	trustedKey := base64.StdEncoding.EncodeToString(publicKey)
	signerLDFlags := "-s -w -buildid= -X trstctl.com/trstctl/internal/license.builtinPubKeysB64=" + trustedKey
	goVersion := dodManagedKeyToolchainVersion(t, repo)
	buildBase := dodPinnedBaseImage(t, "golang:"+goVersion+"-bookworm", "golang")
	runtimeBase := dodPinnedBaseImage(t, "debian:bookworm-slim", "debian")
	dodRunCommandAt(t, repo, "build shipped cgo signer image", "docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "deploy/docker/Dockerfile.signer-hsm", "--build-arg", "BUILD_IMAGE="+buildBase, "--build-arg", "BASE_IMAGE="+runtimeBase, "--build-arg", "LDFLAGS="+signerLDFlags, "-t", "trstctl-signer-hsm:dod", ".")
	signerImage := dodBuiltImageID(t, "trstctl-signer-hsm:dod", dodManagedKeyRuntimePlatform)
	// BuildKit resolves a bare sha256 image ID as a registry repository name.
	// Docker's local image-ID resolver is the path that can consume these exact
	// just-built bytes without falling back to a mutable local tag or registry.
	t.Setenv("DOCKER_BUILDKIT", "0")
	dodRunCommandAt(t, repo, "build independent device-reader image", "docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "tools/dodcensus/Dockerfile.managed-key-runtime", "--build-arg", "SIGNER_IMAGE="+signerImage, "-t", "trstctl-managed-key-runtime:dod", ".")
	runtimeImage := dodBuiltImageID(t, "trstctl-managed-key-runtime:dod", dodManagedKeyRuntimePlatform)
	network := "trstctl-dod-hsm-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dodRunCommand(t, "create isolated managed-key proof network", "docker", "network", "create", network)
	t.Cleanup(func() {
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	t.Setenv("TRSTCTL_HSM_PROOF_NETWORK", network)
	t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", runtimeImage)
	return dodManagedKeyArtifacts{
		licenseFile: licenseFile, licensePublicKey: append([]byte(nil), publicKey...),
		postgresDSN: dodManagedKeyPostgresDSN(t), root: root, repo: repo, network: network, runtimeImage: runtimeImage,
	}
}

type dodManagedKeyPostgresInspect struct {
	Image  string
	Config struct {
		Image, User string
		Env         []string
	}
	HostConfig struct {
		ReadonlyRootfs bool
		Privileged     bool
		CapDrop        []string
		CapAdd         []string
		SecurityOpt    []string
		NetworkMode    string
		PidMode        string
		PidsLimit      int64
		Memory         int64
		Tmpfs          map[string]string
		PortBindings   map[string][]struct {
			HostIP, HostPort string
		}
	}
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	}
	State struct{ Running bool }
}

// dodManagedKeyPostgresDSN keeps the proof database outside the runtime
// runner's PID namespace. The former embedded helper launched a non-dumpable
// same-UID postgres sibling beside the shipped process; the global socket-owner
// census correctly refused to guess whether that unreadable sibling shared a
// socket. This digest-pinned container is published only on host loopback and
// reached through the one already-validated cross-host routing seam.
func dodManagedKeyPostgresDSN(t *testing.T) string {
	t.Helper()
	port := dodFreePort(t)
	containerName := "trstctl-dod-hsm-postgres-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	passwordFile := filepath.Join(t.TempDir(), "postgres-password")
	if err := os.WriteFile(passwordFile, []byte(dodManagedKeyPostgresPassword), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid < 0 {
		t.Fatalf("managed-key PostgreSQL requires a non-root runtime owner, got %d:%d", uid, gid)
	}
	postgresUser := strconv.Itoa(uid) + ":" + strconv.Itoa(gid)
	passwdFile, groupFile := dodManagedKeyPostgresNSS(t, filepath.Dir(passwordFile), uid, gid)
	passwordMountSource := proof.DockerHostMountSource(t, passwordFile)
	passwdMountSource := proof.DockerHostMountSource(t, passwdFile)
	groupMountSource := proof.DockerHostMountSource(t, groupFile)
	dodRunCommand(t, "pull exact managed-key PostgreSQL image", "docker", "pull", dodManagedKeyPostgresImage)
	imageID := dodManagedKeyPostgresImageID(t)
	args := []string{
		"run", "-d", "--name", containerName, "--pull", "never",
		"--user", postgresUser,
		"--read-only", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
		"--network", "bridge", "--pids-limit", "256", "--memory", "512m",
		"--tmpfs", fmt.Sprintf("/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=256m,uid=%d,gid=%d,mode=0700", uid, gid),
		"--tmpfs", fmt.Sprintf("/var/run/postgresql:rw,nosuid,nodev,noexec,size=1m,uid=%d,gid=%d,mode=0750", uid, gid),
		"--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,noexec,size=16m,uid=%d,gid=%d,mode=1777", uid, gid),
		"--mount", "type=bind,src=" + passwordMountSource + ",dst=/run/secrets/postgres-password,readonly",
		"--mount", "type=bind,src=" + passwdMountSource + ",dst=/etc/passwd,readonly",
		"--mount", "type=bind,src=" + groupMountSource + ",dst=/etc/group,readonly",
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", port),
		"-e", "POSTGRES_USER=" + dodManagedKeyPostgresUser,
		"-e", "POSTGRES_DB=" + dodManagedKeyPostgresDatabase,
		"-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		dodManagedKeyPostgresImage,
	}
	dodRunCommand(t, "start isolated managed-key PostgreSQL", "docker", args...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerName).Run() })
	dodInspectManagedKeyPostgres(t, containerName, imageID, postgresUser,
		map[string]string{
			"/run/secrets/postgres-password": passwordMountSource,
			"/etc/passwd":                    passwdMountSource,
			"/etc/group":                     groupMountSource,
		},
		uid, gid, port)

	host, err := dodRuntimeDockerHost()
	if err != nil {
		t.Fatal(err)
	}
	dsnURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(dodManagedKeyPostgresUser, dodManagedKeyPostgresPassword),
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/" + dodManagedKeyPostgresDatabase,
	}
	query := dsnURL.Query()
	query.Set("sslmode", "disable")
	dsnURL.RawQuery = query.Encode()
	dsn := dsnURL.String()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		connection, connectErr := pgx.Connect(ctx, dsn)
		if connectErr == nil {
			pingErr := connection.Ping(ctx)
			_ = connection.Close(ctx)
			cancel()
			if pingErr == nil {
				return dsn
			}
			lastErr = pingErr
		} else {
			cancel()
			lastErr = connectErr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("isolated managed-key PostgreSQL did not become ready: %v state=%s logs=%s", lastErr,
		dodManagedKeyCompactDiagnostic(dodCommandOutput("docker", "inspect", "--format={{json .State}}", containerName)),
		dodManagedKeyCompactDiagnostic(dodCommandOutput("docker", "logs", "--tail=80", containerName)))
	return ""
}

func dodManagedKeyPostgresImageID(t *testing.T) string {
	t.Helper()
	command := exec.Command("docker", "image", "inspect", "--format={{.Id}} {{.Os}}/{{.Architecture}}", dodManagedKeyPostgresImage)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect pinned managed-key PostgreSQL image: %v output=%s", err, output)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || (fields[1] != "linux/amd64" && fields[1] != "linux/arm64") {
		t.Fatalf("pinned managed-key PostgreSQL image inspect = %q, want bounded Linux architecture", strings.TrimSpace(string(output)))
	}
	id, err := dodParseContentImageID(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func dodInspectManagedKeyPostgres(t *testing.T, containerName, imageID, postgresUser string, mountSources map[string]string, uid, gid, port int) {
	t.Helper()
	command := exec.Command("docker", "inspect", containerName)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect isolated managed-key PostgreSQL: %v output=%s", err, output)
	}
	var rows []dodManagedKeyPostgresInspect
	if err := json.Unmarshal(output, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("decode isolated managed-key PostgreSQL inspect: rows=%d err=%v", len(rows), err)
	}
	row := rows[0]
	if row.Image != imageID || row.Config.Image != dodManagedKeyPostgresImage || row.Config.User != postgresUser || !row.State.Running {
		t.Fatalf("isolated PostgreSQL image/user/state changed: image=%q config_image=%q user=%q running=%v", row.Image, row.Config.Image, row.Config.User, row.State.Running)
	}
	if !row.HostConfig.ReadonlyRootfs || row.HostConfig.Privileged || len(row.HostConfig.CapAdd) != 0 ||
		strings.Join(row.HostConfig.CapDrop, ",") != "ALL" || row.HostConfig.PidMode != "" ||
		strings.Join(row.HostConfig.SecurityOpt, ",") != "no-new-privileges" || row.HostConfig.NetworkMode != "bridge" ||
		row.HostConfig.PidsLimit != 256 || row.HostConfig.Memory != 512*1024*1024 {
		t.Fatalf("isolated PostgreSQL confinement changed: %+v", row.HostConfig)
	}
	wantTmpfs := map[string]struct {
		size int64
		mode string
	}{
		"/var/lib/postgresql/data": {size: 256 * 1024 * 1024, mode: "0700"},
		"/var/run/postgresql":      {size: 1024 * 1024, mode: "0750"},
		"/tmp":                     {size: 16 * 1024 * 1024, mode: "1777"},
	}
	if len(row.HostConfig.Tmpfs) != len(wantTmpfs) {
		t.Fatalf("isolated PostgreSQL tmpfs set changed: %v", row.HostConfig.Tmpfs)
	}
	for path, expected := range wantTmpfs {
		options := map[string]bool{}
		for _, option := range strings.Split(row.HostConfig.Tmpfs[path], ",") {
			options[option] = true
		}
		for _, option := range []string{"rw", "nosuid", "nodev", "noexec", "uid=" + strconv.Itoa(uid), "gid=" + strconv.Itoa(gid), "mode=" + expected.mode} {
			if !options[option] {
				t.Fatalf("isolated PostgreSQL tmpfs %s omits %q: %q", path, option, row.HostConfig.Tmpfs[path])
			}
		}
		size := int64(-1)
		for option := range options {
			if raw, ok := strings.CutPrefix(option, "size="); ok {
				size, err = dodTmpfsSizeBytes(raw)
				if err != nil {
					t.Fatalf("isolated PostgreSQL tmpfs %s has invalid size %q: %v", path, raw, err)
				}
			}
		}
		if size != expected.size {
			t.Fatalf("isolated PostgreSQL tmpfs %s size=%d, want %d: %q", path, size, expected.size, row.HostConfig.Tmpfs[path])
		}
		if len(options) != 8 {
			t.Fatalf("isolated PostgreSQL tmpfs %s has unreviewed options: %q", path, row.HostConfig.Tmpfs[path])
		}
	}
	bindings := row.HostConfig.PortBindings["5432/tcp"]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != strconv.Itoa(port) {
		t.Fatalf("isolated PostgreSQL is not bound only to exact host loopback: %+v", bindings)
	}
	if len(row.Mounts) != len(mountSources) {
		t.Fatalf("isolated PostgreSQL mount set changed: %+v", row.Mounts)
	}
	for _, mount := range row.Mounts {
		if mount.Type != "bind" || mount.RW || mountSources[mount.Destination] != mount.Source {
			t.Fatalf("isolated PostgreSQL private mount changed: %+v", row.Mounts)
		}
	}
	for _, required := range []string{
		"POSTGRES_USER=" + dodManagedKeyPostgresUser,
		"POSTGRES_DB=" + dodManagedKeyPostgresDatabase,
		"POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
		"PGDATA=/var/lib/postgresql/data/pgdata",
	} {
		if !dodContainsExact(row.Config.Env, required) {
			t.Fatalf("isolated PostgreSQL environment omits %q", required)
		}
	}
	for _, value := range row.Config.Env {
		if strings.HasPrefix(value, "POSTGRES_PASSWORD=") {
			t.Fatal("isolated PostgreSQL retained its password in container environment metadata")
		}
	}
}

func dodManagedKeyPostgresNSS(t *testing.T, dir string, uid, gid int) (string, string) {
	t.Helper()
	if uid <= 0 || gid < 0 || !filepath.IsAbs(dir) || strings.ContainsAny(dir, ":\r\n\x00") {
		t.Fatalf("invalid managed-key PostgreSQL NSS identity/path %d:%d %q", uid, gid, dir)
	}
	passwd := "root:x:0:0:root:/root:/usr/sbin/nologin\n" +
		fmt.Sprintf("dodpostgres:x:%d:%d:DoD managed-key PostgreSQL:/var/lib/postgresql:/usr/sbin/nologin\n", uid, gid)
	group := "root:x:0:\n"
	if gid != 0 {
		group += fmt.Sprintf("dodpostgres:x:%d:\n", gid)
	}
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatalf("create managed-key PostgreSQL %s: %v", name, err)
		}
		if _, err := file.WriteString(content); err != nil {
			_ = file.Close()
			t.Fatalf("write managed-key PostgreSQL %s: %v", name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			t.Fatalf("sync managed-key PostgreSQL %s: %v", name, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close managed-key PostgreSQL %s: %v", name, err)
		}
		return path
	}
	return write("postgres-passwd", passwd), write("postgres-group", group)
}

func dodContainsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func dodTmpfsSizeBytes(raw string) (int64, error) {
	if raw == "" {
		return 0, fmt.Errorf("empty tmpfs size")
	}
	multiplier := int64(1)
	suffix := raw[len(raw)-1]
	if suffix < '0' || suffix > '9' {
		switch suffix {
		case 'k', 'K':
			multiplier = 1024
		case 'm', 'M':
			multiplier = 1024 * 1024
		case 'g', 'G':
			multiplier = 1024 * 1024 * 1024
		default:
			return 0, fmt.Errorf("unsupported tmpfs size suffix %q", suffix)
		}
		raw = raw[:len(raw)-1]
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || value > (1<<63-1)/multiplier {
		return 0, fmt.Errorf("invalid tmpfs size")
	}
	return value * multiplier, nil
}

func TestDODManagedKeyTmpfsSizeParserIsClosed(t *testing.T) {
	for raw, want := range map[string]int64{
		"1048576": 1024 * 1024,
		"1024k":   1024 * 1024,
		"16m":     16 * 1024 * 1024,
		"1G":      1024 * 1024 * 1024,
	} {
		if got, err := dodTmpfsSizeBytes(raw); err != nil || got != want {
			t.Errorf("tmpfs size %q = %d err=%v, want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "0", "-1", "1t", "not-a-size", "9223372036854775807g"} {
		if got, err := dodTmpfsSizeBytes(raw); err == nil {
			t.Errorf("unsafe tmpfs size %q accepted as %d", raw, got)
		}
	}
}

func dodManagedKeySnapshotTree(root string) (map[string]dodManagedKeyFileState, error) {
	snapshot := map[string]dodManagedKeyFileState{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		snapshot[relative] = dodManagedKeyFileState{
			Mode: info.Mode(), Size: info.Size(), ModifiedNS: info.ModTime().UnixNano(),
		}
		return nil
	})
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	return snapshot, err
}

func dodManagedKeySnapshotsEqual(left, right map[string]dodManagedKeyFileState) bool {
	if len(left) != len(right) {
		return false
	}
	for path, state := range left {
		if right[path] != state {
			return false
		}
	}
	return true
}

func dodRunManagedKeyProvider(t *testing.T, artifacts dodManagedKeyArtifacts, entryID, provider string, external *proof.ExternalSubstrate, endpoint string) {
	t.Helper()
	control := proof.BuildShippedProcess(t, entryID, artifacts.licensePublicKey)
	runtime := &dodManagedKeyRuntime{
		t: t, entryID: entryID, provider: provider, external: external,
		artifacts: artifacts, dir: t.TempDir(), signerPort: dodFreePort(t), serverPort: dodFreePort(t), control: control,
	}
	runtime.containerName = "trstctl-dod-hsm-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	runtime.configure(endpoint)
	runtime.startSigner()
	t.Cleanup(runtime.close)
	defer runtime.close()
	if provider == config.ManagedKeyProviderTPM2 {
		runtime.installTPMForeignOperationCollision()
	}
	runtime.bootstrapToken()
	control.Start(runtime.dir, runtime.env)
	runtime.waitControlPlane()

	generateResponse := control.Do(dodManagedKeyRequestObject(runtime, http.MethodPost, "/api/v1/managed-keys", "generate", map[string]string{"algorithm": string(crypto.RSA2048)}))
	if status := proof.LaunchedResponseStatusCode(t, entryID, generateResponse); status/100 != 2 {
		t.Fatalf("initial managed-key route status=%d durable=%s", status, runtime.durableDiagnostics())
	}
	session := proof.StartResponse(t, entryID, generateResponse)
	generated := dodDecodeManagedKey(t, session.ResponseBody())
	dodRequireActiveManagedKey(t, generated)
	runtime.requireHardwareKeyID(generated.KeyID)
	if generated.Extractable {
		t.Fatal("managed key was reported extractable")
	}
	if provider == config.ManagedKeyProviderTPM2 {
		runtime.assertTPMForeignCollisionAndOperationTag(generated.KeyID)
	}
	// Same HTTP idempotency key must return the original provider handle.
	replayed := dodDecodeManagedKey(t, runtime.responseBody(dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys", "generate", map[string]string{"algorithm": string(crypto.RSA2048)})))
	runtime.requireHardwareKeyID(replayed.KeyID)
	if replayed.KeyID != generated.KeyID {
		t.Fatalf("HTTP idempotency replay minted %q after %q", replayed.KeyID, generated.KeyID)
	}
	runtime.approveManagedKeyAction(generated.KeyID, "rotate")

	// Stop the separate signer before submitting rotation. The API request has
	// already persisted its event/outbox intent; restart lets the dispatcher
	// redeliver to the same signer journal and provider state.
	preRestartTPM := runtime.stopSigner(generated)
	rotateResult := make(chan *http.Response, 1)
	go func() {
		rotateResult <- dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys/rotate", "rotate", map[string]string{"key_id": generated.KeyID})
	}()
	time.Sleep(750 * time.Millisecond)
	runtime.restartSigner(generated, preRestartTPM)
	var rotateResponse *http.Response
	select {
	case rotateResponse = <-rotateResult:
	case <-time.After(35 * time.Second):
		t.Fatal("managed-key outbox did not recover after signer restart")
	}
	rotated := dodDecodeManagedKey(t, runtime.responseBody(rotateResponse))
	dodRequireActiveManagedKey(t, rotated)
	runtime.requireHardwareKeyID(rotated.KeyID)
	if rotated.KeyID == generated.KeyID || bytes.Equal(rotated.PublicDER, generated.PublicDER) {
		t.Fatal("managed-key rotation did not create distinct provider material")
	}

	var signature, exportDenial []byte
	if provider == config.ManagedKeyProviderAWS || provider == config.ManagedKeyProviderAzureKeyVault || provider == config.ManagedKeyProviderGCPKMS {
		readback := runtime.cloudReadback(rotated.KeyID, "active")
		signature = dodDecodeBase64(t, readback.Signature)
		exportDenial = []byte(readback.ExportDenial)
	} else {
		signature = runtime.hardwareSignAndWitness(generated, rotated, false, false)
		exportDenial = []byte("denied: private key is non-exportable device custody")
	}

	runtime.approveManagedKeyAction(rotated.KeyID, "revoke")
	revoked := dodDecodeManagedKey(t, runtime.responseBody(dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys/revoke", "revoke", map[string]string{"key_id": rotated.KeyID})))
	runtime.requireHardwareKeyID(revoked.KeyID)
	if revoked.KeyID != rotated.KeyID || revoked.State != "revoked" {
		t.Fatalf("revoke state = %q", revoked.State)
	}
	if provider == config.ManagedKeyProviderAWS || provider == config.ManagedKeyProviderAzureKeyVault || provider == config.ManagedKeyProviderGCPKMS {
		runtime.cloudReadback(rotated.KeyID, "revoked")
	} else {
		runtime.assertHardwareRevoked(rotated.KeyID)
	}

	runtime.approveManagedKeyAction(rotated.KeyID, "zeroize")
	zeroized := dodDecodeManagedKey(t, runtime.responseBody(dodManagedKeyRequest(runtime, http.MethodPost, "/api/v1/managed-keys/zeroize", "zeroize", map[string]string{"key_id": rotated.KeyID})))
	runtime.requireHardwareKeyID(zeroized.KeyID)
	if zeroized.KeyID != rotated.KeyID || zeroized.State != "zeroized" {
		t.Fatalf("zeroize state = %q", zeroized.State)
	}
	if provider == config.ManagedKeyProviderAWS || provider == config.ManagedKeyProviderAzureKeyVault || provider == config.ManagedKeyProviderGCPKMS {
		runtime.cloudReadback(rotated.KeyID, "zeroized")
	} else {
		runtime.finishHardwareWitness(generated, rotated, signature)
	}

	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.HSMSign(proof.HSMSignProbe{
		Signature: signature, PublicKey: rotated.PublicDER,
		ExportDenial: exportDenial, ExecutionReceipt: executionReceipt,
	}))
}

func (r *dodManagedKeyRuntime) configure(endpoint string) {
	r.t.Helper()
	configResponse, err := http.Get(endpoint + "/dod/config")
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = configResponse.Body.Close() }()
	var substrate dodManagedKeySubstrateConfig
	if configResponse.StatusCode != http.StatusOK || json.NewDecoder(configResponse.Body).Decode(&substrate) != nil {
		r.t.Fatalf("invalid managed-key substrate config status=%d", configResponse.StatusCode)
	}
	controlEndpoint := endpoint
	if r.provider == config.ManagedKeyProviderAWS || r.provider == config.ManagedKeyProviderAzureKeyVault || r.provider == config.ManagedKeyProviderGCPKMS {
		// The parent broker publishes the emulator through Docker Desktop's
		// host.docker.internal seam. The shipped control plane intentionally
		// rejects that hostname for plaintext provider traffic. Keep its endpoint
		// on the runner's own loopback and relay only to this nonce-bound substrate.
		// The separate signer container retains its independent loopback relay.
		controlEndpoint = dodManagedKeyControlEndpoint(r.t, endpoint)
		r.controlProviderEndpoint = controlEndpoint
	}
	containerEndpoint := "http://127.0.0.1:" + strconv.Itoa(dodManagedKeyLoopbackProxyPort)
	signerConfig := config.ManagedKeys{Enabled: true, Provider: r.provider}
	control := map[string]string{}
	writeSecret := func(name, value string) (host, container string) {
		host = filepath.Join(r.dir, name)
		if err := os.WriteFile(host, []byte(value), 0o600); err != nil {
			r.t.Fatal(err)
		}
		return host, "/runtime/" + name
	}
	switch r.provider {
	case config.ManagedKeyProviderAWS:
		hostSecret, containerSecret := writeSecret("aws-secret", substrate.AWSSecretKey)
		signerConfig.AWS = config.ManagedKeysAWSKMS{Region: substrate.AWSRegion, Endpoint: containerEndpoint, AllowInsecureLoopback: true, AccessKeyID: substrate.AWSAccessKey, SecretAccessKeyFile: containerSecret, PrivateEgressCIDRs: []string{"127.0.0.0/8"}}
		control["TRSTCTL_MANAGED_KEYS_AWS_REGION"] = substrate.AWSRegion
		control["TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT"] = controlEndpoint
		control["TRSTCTL_MANAGED_KEYS_AWS_ALLOW_INSECURE_LOOPBACK"] = "true"
		control["TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID"] = substrate.AWSAccessKey
		control["TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE"] = hostSecret
		control["TRSTCTL_MANAGED_KEYS_AWS_PRIVATE_EGRESS_CIDRS"] = "127.0.0.0/8"
	case config.ManagedKeyProviderAzureKeyVault:
		hostToken, containerToken := writeSecret("azure-token", substrate.AzureToken)
		signerConfig.Azure = config.ManagedKeysAzureKV{VaultURL: "https://dod.managedhsm.azure.net", Endpoint: containerEndpoint, AllowInsecureLoopback: true, BearerTokenFile: containerToken, PrivateEgressCIDRs: []string{"127.0.0.0/8"}}
		control["TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL"] = "https://dod.managedhsm.azure.net"
		control["TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT"] = controlEndpoint
		control["TRSTCTL_MANAGED_KEYS_AZURE_ALLOW_INSECURE_LOOPBACK"] = "true"
		control["TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE"] = hostToken
		control["TRSTCTL_MANAGED_KEYS_AZURE_PRIVATE_EGRESS_CIDRS"] = "127.0.0.0/8"
	case config.ManagedKeyProviderGCPKMS:
		hostToken, containerToken := writeSecret("gcp-token", substrate.GCPToken)
		signerConfig.GCP = config.ManagedKeysGCPKMS{Parent: substrate.GCPParent, Endpoint: containerEndpoint + "/v1", AllowInsecureLoopback: true, BearerTokenFile: containerToken, PrivateEgressCIDRs: []string{"127.0.0.0/8"}}
		control["TRSTCTL_MANAGED_KEYS_GCP_PARENT"] = substrate.GCPParent
		control["TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT"] = controlEndpoint + "/v1"
		control["TRSTCTL_MANAGED_KEYS_GCP_ALLOW_INSECURE_LOOPBACK"] = "true"
		control["TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE"] = hostToken
		control["TRSTCTL_MANAGED_KEYS_GCP_PRIVATE_EGRESS_CIDRS"] = "127.0.0.0/8"
	case config.ManagedKeyProviderPKCS11:
		hostPIN, containerPIN := writeSecret("device-pin", "12345678")
		signerConfig.PKCS11 = config.ManagedKeysPKCS11HSM{ModulePath: "/runtime/libsofthsm2.so", TokenLabel: "trstctl-dod", UserPINFile: containerPIN, KeyLabelPrefix: "trstctl-pkcs11"}
		control["TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH"] = "/runtime/libsofthsm2.so"
		control["TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL"] = "trstctl-dod"
		control["TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE"] = hostPIN
	case config.ManagedKeyProviderTPM2:
		// Keep the transport socket on the container filesystem. Docker Desktop's
		// macOS bind mount rejects chmod(2) on Unix sockets; only the TPM state must
		// be durable across the signer stop/start and remains under /runtime.
		signerConfig.TPM2 = config.ManagedKeysTPM2{Path: "/tmp/swtpm.sock", PersistentHandleBase: 0x81010000}
		control["TRSTCTL_MANAGED_KEYS_TPM2_PATH"] = "/tmp/swtpm.sock"
		control["TRSTCTL_MANAGED_KEYS_TPM2_PERSISTENT_HANDLE_BASE"] = "2164326400"
	case config.ManagedKeyProviderYubiHSM2:
		hostPIN, containerPIN := writeSecret("device-pin", "12345678")
		signerConfig.YubiHSM2 = config.ManagedKeysPKCS11HSM{ModulePath: "/runtime/libsofthsm2.so", TokenLabel: "trstctl-dod", UserPINFile: containerPIN, KeyLabelPrefix: "trstctl-yubihsm2"}
		control["TRSTCTL_MANAGED_KEYS_YUBIHSM2_MODULE_PATH"] = "/runtime/libsofthsm2.so"
		control["TRSTCTL_MANAGED_KEYS_YUBIHSM2_TOKEN_LABEL"] = "trstctl-dod"
		control["TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN_FILE"] = hostPIN
	}
	rawConfig, err := json.Marshal(signerConfig)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "provider.json"), rawConfig, 0o600); err != nil {
		r.t.Fatal(err)
	}
	rawLicense, err := os.ReadFile(r.artifacts.licenseFile)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "license.json"), rawLicense, 0o600); err != nil {
		r.t.Fatal(err)
	}
	authSecretFile := filepath.Join(r.dir, "sign-auth.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authSecretFile)
	if err != nil {
		r.t.Fatal(err)
	}
	authorizer.Destroy()
	testExecutable, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	authCommand := filepath.Join(r.dir, "authorize-sign-intent")
	authScript := "#!/bin/sh\nexport " + dodManagedKeySignTokenHelperEnv + "=1\nexport " +
		dodManagedKeySignTokenSecretFileEnv + "=" + dodManagedKeyShellQuote(authSecretFile) + "\nexec " +
		dodManagedKeyShellQuote(testExecutable) + " -test.run '^TestDODManagedKeySignTokenHelper$'\n"
	if err := os.WriteFile(authCommand, []byte(authScript), 0o700); err != nil {
		r.t.Fatal(err)
	}
	control["TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND"] = authCommand
	control["TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER"] = "false"
	material, err := mtls.GenerateSignerPeerMaterial(r.dir, "trstctl-dod-signer", time.Hour)
	if err != nil {
		r.t.Fatal(err)
	}
	r.mtlsMaterial = material
	r.env = dodManagedKeyControlEnv(r, control)
}

func dodManagedKeyControlEnv(r *dodManagedKeyRuntime, providerEnv map[string]string) []string {
	signerAddress := dodManagedKeySignerAddress(r.t, r.signerPort)
	values := map[string]string{
		"TRSTCTL_SERVER_ADDR":     "127.0.0.1:" + strconv.Itoa(r.serverPort),
		"TRSTCTL_SERVER_TLS_MODE": "disabled", "TRSTCTL_DEV_ALLOW_PLAINTEXT": "true",
		"TRSTCTL_POSTGRES_MODE": "external", "TRSTCTL_POSTGRES_DSN": r.artifacts.postgresDSN,
		"TRSTCTL_NATS_MODE": "embedded", "TRSTCTL_NATS_STORE_DIR": filepath.Join(r.dir, "nats"),
		"TRSTCTL_LICENSE_FILE": r.artifacts.licenseFile, "TRSTCTL_MIGRATE_AUTO": "true",
		"TRSTCTL_RATE_LIMIT_ENABLED": "false", "TRSTCTL_TELEMETRY_ENABLED": "false",
		"TRSTCTL_AUDIT_SIGNING_KEY_FILE":  filepath.Join(r.dir, "audit.pem"),
		"TRSTCTL_SECRETS_KEK_FILE":        filepath.Join(r.dir, "control-kek.bin"),
		"TRSTCTL_CA_CERT_FILE":            filepath.Join(r.dir, "issuing-ca.pem"),
		"TRSTCTL_SIGNER_KEY_STORE_DIR":    filepath.Join(r.dir, "control-signer-keys"),
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE": filepath.Join(r.dir, "sign-auth.bin"),
		"TRSTCTL_SIGNER_MODE":             "external", "TRSTCTL_SIGNER_MTLS_ADDRESS": signerAddress,
		"TRSTCTL_SIGNER_MTLS_SERVER_NAME":  r.mtlsMaterial.ServerName,
		"TRSTCTL_SIGNER_MTLS_CERT_FILE":    r.mtlsMaterial.ControlPlane.CertFile,
		"TRSTCTL_SIGNER_MTLS_KEY_FILE":     r.mtlsMaterial.ControlPlane.KeyFile,
		"TRSTCTL_SIGNER_MTLS_PEER_CA_FILE": r.mtlsMaterial.ControlPlane.PeerCAFile,
		"TRSTCTL_SIGNER_MTLS_PEER_PIN":     r.mtlsMaterial.ControlPlane.PeerPinHex,
		"TRSTCTL_MANAGED_KEYS_ENABLED":     "true", "TRSTCTL_MANAGED_KEYS_PROVIDER": r.provider,
	}
	for key, value := range providerEnv {
		values[key] = value
	}
	base := make([]string, 0, len(os.Environ())+len(values))
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "TRSTCTL_") {
			base = append(base, item)
		}
	}
	for key, value := range values {
		base = append(base, key+"="+value)
	}
	return base
}

// dodRuntimeDockerHost is a closed routing seam for processes launched through
// the mounted Docker socket. Native tests reach published ports on loopback. The
// reviewed cross-host runner exports Docker Desktop's fixed host name. No URL,
// IP, arbitrary DNS name, whitespace variant, or port is accepted here.
func dodRuntimeDockerHost() (string, error) {
	value, ok := os.LookupEnv(dodRuntimeDockerHostEnv)
	if !ok || value == "" {
		return "127.0.0.1", nil
	}
	if value != strings.TrimSpace(value) {
		return "", fmt.Errorf("%s contains surrounding whitespace", dodRuntimeDockerHostEnv)
	}
	switch value {
	case "127.0.0.1", "host.docker.internal":
		return value, nil
	default:
		return "", fmt.Errorf("%s must be 127.0.0.1 or host.docker.internal", dodRuntimeDockerHostEnv)
	}
}

func dodManagedKeySignerAddress(t *testing.T, port int) string {
	t.Helper()
	host, err := dodRuntimeDockerHost()
	if err != nil {
		t.Fatal(err)
	}
	if port < 1 || port > 65535 {
		t.Fatalf("managed-key signer port %d is outside 1..65535", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// dodManagedKeyControlEndpoint gives the shipped control-plane process a real
// loopback endpoint without teaching production endpoint validation to trust a
// Docker-only hostname. The relay is bound to 127.0.0.1 and its sole upstream is
// the exact broker endpoint already selected for this nonce-bound proof run.
func dodManagedKeyControlEndpoint(t *testing.T, endpoint string) string {
	t.Helper()
	host, err := dodRuntimeDockerHost()
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := dodValidateManagedKeyRelayUpstream(endpoint, host)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for managed-key control relay: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		proxy.Transport.(*http.Transport).CloseIdleConnections()
	})
	return "http://" + listener.Addr().String()
}

func dodValidateManagedKeyRelayUpstream(endpoint, allowedHost string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse managed-key substrate endpoint: %w", err)
	}
	if parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() != allowedHost || parsed.Port() == "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("managed-key substrate endpoint %q is not an exact HTTP endpoint on %q", endpoint, allowedHost)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("managed-key substrate endpoint %q has an invalid port", endpoint)
	}
	parsed.Path = ""
	return parsed, nil
}

func TestDODManagedKeyControlEnvKeepsSignerStateInsideRuntimeDir(t *testing.T) {
	runtimeDir := t.TempDir()
	r := &dodManagedKeyRuntime{
		t: t, dir: runtimeDir, provider: config.ManagedKeyProviderAWS, signerPort: 19443,
		artifacts: dodManagedKeyArtifacts{licenseFile: filepath.Join(runtimeDir, "license.json"), postgresDSN: "postgres://dod"},
		mtlsMaterial: &mtls.SignerPeerMaterial{
			ServerName: "dod-signer",
			ControlPlane: mtls.SignerPeerConfig{
				CertFile: "control.crt", KeyFile: "control.key", PeerCAFile: "ca.pem", PeerPinHex: "00",
			},
		},
	}
	env := dodManagedKeyControlEnv(r, nil)
	values := map[string]string{}
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	want := map[string]string{
		"TRSTCTL_SIGNER_KEY_STORE_DIR":    filepath.Join(runtimeDir, "control-signer-keys"),
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE": filepath.Join(runtimeDir, "sign-auth.bin"),
		"TRSTCTL_SIGNER_MTLS_ADDRESS":     "127.0.0.1:19443",
	}
	for key, expected := range want {
		if got := values[key]; got != expected {
			t.Errorf("%s = %q, want runtime-scoped %q", key, got, expected)
		}
	}
}

func TestDODManagedKeyRuntimeDockerHostIsClosed(t *testing.T) {
	t.Setenv(dodRuntimeDockerHostEnv, "")
	if got, err := dodRuntimeDockerHost(); err != nil || got != "127.0.0.1" {
		t.Fatalf("native Docker host = %q err=%v", got, err)
	}
	t.Setenv(dodRuntimeDockerHostEnv, "host.docker.internal")
	if got, err := dodRuntimeDockerHost(); err != nil || got != "host.docker.internal" {
		t.Fatalf("cross-host Docker host = %q err=%v", got, err)
	}
	if got := dodManagedKeySignerAddress(t, 19443); got != "host.docker.internal:19443" {
		t.Fatalf("cross-host signer address = %q", got)
	}
	for _, invalid := range []string{"localhost", "127.0.0.2", "host.docker.internal:2375", " host.docker.internal", "host.docker.internal "} {
		t.Setenv(dodRuntimeDockerHostEnv, invalid)
		if got, err := dodRuntimeDockerHost(); err == nil {
			t.Errorf("accepted runtime Docker host %q as %q", invalid, got)
		}
	}
}

func TestDODManagedKeyControlEndpointRelaysThroughRunnerLoopback(t *testing.T) {
	type observedRequest struct {
		method, path, query, host, authorization, body string
	}
	observed := make(chan observedRequest, 1)
	upstreamListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observed <- observedRequest{
			method: request.Method, path: request.URL.Path, query: request.URL.RawQuery,
			host: request.Host, authorization: request.Header.Get("Authorization"), body: string(body),
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("relayed"))
	})}
	go func() {
		_ = upstreamServer.Serve(upstreamListener)
	}()
	defer func() { _ = upstreamServer.Close() }()
	upstreamEndpoint := "http://" + upstreamListener.Addr().String()
	parsedUpstream, err := url.Parse(upstreamEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(dodRuntimeDockerHostEnv, parsedUpstream.Hostname())
	relayEndpoint := dodManagedKeyControlEndpoint(t, upstreamEndpoint)
	parsedRelay, err := url.Parse(relayEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if parsedRelay.Scheme != "http" || parsedRelay.Hostname() != "127.0.0.1" || parsedRelay.Port() == "" {
		t.Fatalf("managed-key control relay endpoint = %q, want HTTP 127.0.0.1 with an allocated port", relayEndpoint)
	}
	request, err := http.NewRequest(http.MethodPost, relayEndpoint+"/v1/keys/key:rotate?proof=nonce", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer proof-token")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || string(body) != "relayed" {
		t.Fatalf("relay response status=%d body=%q", response.StatusCode, body)
	}
	got := <-observed
	want := observedRequest{
		method: http.MethodPost, path: "/v1/keys/key:rotate", query: "proof=nonce",
		host: parsedRelay.Host, authorization: "Bearer proof-token", body: "payload",
	}
	if got != want {
		t.Fatalf("relayed request = %+v, want %+v", got, want)
	}
}

func TestDODManagedKeyControlEndpointRejectsUnscopedUpstreams(t *testing.T) {
	for _, endpoint := range []string{
		"https://host.docker.internal:8443",
		"http://user@host.docker.internal:8443",
		"http://127.0.0.1:8443",
		"http://host.docker.internal",
		"http://host.docker.internal:0",
		"http://host.docker.internal:65536",
		"http://host.docker.internal:8443/provider",
		"http://host.docker.internal:8443?provider=aws",
		"http://host.docker.internal:8443#provider",
	} {
		t.Run(strings.NewReplacer(":", "_", "/", "_", "?", "_", "#", "_").Replace(endpoint), func(t *testing.T) {
			if parsed, err := dodValidateManagedKeyRelayUpstream(endpoint, "host.docker.internal"); err == nil {
				t.Fatalf("unscoped upstream %q accepted as %s", endpoint, parsed)
			}
		})
	}
	for _, endpoint := range []string{"http://host.docker.internal:8443", "http://host.docker.internal:8443/"} {
		if _, err := dodValidateManagedKeyRelayUpstream(endpoint, "host.docker.internal"); err != nil {
			t.Fatalf("exact upstream %q rejected: %v", endpoint, err)
		}
	}
}

func TestDODManagedKeyHardwareKeyIDsAreClosedBeforeDeviceExecution(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider string
		keyID    string
		valid    bool
	}{
		{name: "TPM owner first", provider: config.ManagedKeyProviderTPM2, keyID: "0x81000000", valid: true},
		{name: "TPM owner last", provider: config.ManagedKeyProviderTPM2, keyID: "0x817fffff", valid: true},
		{name: "TPM configured base", provider: config.ManagedKeyProviderTPM2, keyID: "0x81010000", valid: true},
		{name: "TPM transient", provider: config.ManagedKeyProviderTPM2, keyID: "0x80000000"},
		{name: "TPM platform", provider: config.ManagedKeyProviderTPM2, keyID: "0x81800000"},
		{name: "TPM uppercase", provider: config.ManagedKeyProviderTPM2, keyID: "0x8100000A"},
		{name: "TPM shell suffix", provider: config.ManagedKeyProviderTPM2, keyID: "0x81000000;true"},
		{name: "TPM newline", provider: config.ManagedKeyProviderTPM2, keyID: "0x81000000\ntouch /tmp/forged"},
		{name: "PKCS fixed ID", provider: config.ManagedKeyProviderPKCS11, keyID: strings.Repeat("0a", 16), valid: true},
		{name: "Yubi fixed ID", provider: config.ManagedKeyProviderYubiHSM2, keyID: strings.Repeat("f0", 16), valid: true},
		{name: "PKCS short", provider: config.ManagedKeyProviderPKCS11, keyID: strings.Repeat("0a", 15)},
		{name: "PKCS uppercase", provider: config.ManagedKeyProviderPKCS11, keyID: strings.Repeat("0A", 16)},
		{name: "PKCS non-hex", provider: config.ManagedKeyProviderPKCS11, keyID: strings.Repeat("0g", 16)},
		{name: "PKCS shell suffix", provider: config.ManagedKeyProviderPKCS11, keyID: strings.Repeat("0a", 16) + ";true"},
		{name: "cloud ID is not a device argv", provider: config.ManagedKeyProviderAWS, keyID: "emulator-key/id", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := dodValidateHardwareKeyID(test.provider, test.keyID)
			if test.valid && err != nil {
				t.Fatalf("valid identity rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatalf("unsafe identity %q accepted", test.keyID)
			}
		})
	}
}

func TestDODManagedKeyTPMRestartRequiresSamePublicObject(t *testing.T) {
	generated := []byte("api-public-der")
	valid := dodTPMPublicWitness{PublicDER: append([]byte(nil), generated...), Name: []byte("tpm-object-name")}
	if err := dodValidateTPMPublicSurvival(generated, valid, valid); err != nil {
		t.Fatalf("same TPM object rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		api    []byte
		before dodTPMPublicWitness
		after  dodTPMPublicWitness
	}{
		{name: "missing witness", api: generated, before: dodTPMPublicWitness{}, after: valid},
		{name: "pre-restart differs from API", api: []byte("different-api-key"), before: valid, after: valid},
		{name: "same handle changed public DER", api: generated, before: valid, after: dodTPMPublicWitness{PublicDER: []byte("replacement-public-der"), Name: valid.Name}},
		{name: "same handle changed object Name", api: generated, before: valid, after: dodTPMPublicWitness{PublicDER: valid.PublicDER, Name: []byte("replacement-object-name")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := dodValidateTPMPublicSurvival(test.api, test.before, test.after); err == nil {
				t.Fatal("changed TPM object passed restart custody validation")
			}
		})
	}
}

func (r *dodManagedKeyRuntime) startSigner() {
	r.t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid < 0 {
		r.t.Fatalf("managed-key verifier requires a non-root runtime owner, got %d:%d", uid, gid)
	}
	passwdFile, groupFile := dodManagedKeySignerNSS(r.t, r.dir, uid, gid)
	runtimeMountSource := proof.DockerHostMountSource(r.t, r.dir)
	passwdMountSource := proof.DockerHostMountSource(r.t, passwdFile)
	groupMountSource := proof.DockerHostMountSource(r.t, groupFile)
	args := []string{
		"run", "-d", "--name", r.containerName,
		"--platform", dodManagedKeyRuntimePlatform,
		"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL",
		"--network", r.artifacts.network,
		"-p", fmt.Sprintf("127.0.0.1:%d:9443", r.signerPort),
	}
	// Docker Desktop supplies a special host.docker.internal proxy. Overriding it
	// with Linux's host-gateway address points at the VM gateway instead of the
	// macOS host and makes the signer unable to reach the proof substrate.
	if goruntime.GOOS == "linux" {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	args = append(args,
		"--mount", "type=bind,src="+runtimeMountSource+",dst=/runtime",
		"--mount", "type=bind,src="+passwdMountSource+",dst=/etc/passwd,readonly",
		"--mount", "type=bind,src="+groupMountSource+",dst=/etc/group,readonly",
		"-e", "TRSTCTL_DOD_PROVIDER="+r.provider,
		"-e", "TRSTCTL_DOD_CLOUD_UPSTREAM=managed-key-emulator:8080",
		r.artifacts.runtimeImage,
		"--mtls-listen", ":9443", "--mtls-cert", "/runtime/signer.crt", "--mtls-key", "/runtime/signer.key",
		"--mtls-peer-ca", "/runtime/signer-ca.pem", "--mtls-peer-pin", r.mtlsMaterial.Signer.PeerPinHex,
		"--keystore", "/runtime/keystore", "--kek", "/runtime/signer-kek.bin",
		"--auth-secret", "/runtime/sign-auth.bin",
		"--license", "/runtime/license.json",
		"--managed-keys-config", "/runtime/provider.json",
	)
	dodRunCommand(r.t, "start separate managed-key signer", "docker", args...)
	r.waitSigner()
}

func dodManagedKeySignerNSS(t *testing.T, dir string, uid, gid int) (string, string) {
	t.Helper()
	if uid <= 0 || gid < 0 || !filepath.IsAbs(dir) || strings.ContainsAny(dir, ":\r\n\x00") {
		t.Fatalf("invalid managed-key signer NSS identity/path %d:%d %q", uid, gid, dir)
	}
	passwd := "root:x:0:0:root:/root:/usr/sbin/nologin\n" +
		fmt.Sprintf("dodsigner:x:%d:%d:DoD managed-key signer:/runtime:/usr/sbin/nologin\n", uid, gid)
	group := "root:x:0:\n"
	if gid != 0 {
		group += fmt.Sprintf("dodsigner:x:%d:\n", gid)
	}
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatalf("create managed-key signer %s: %v", name, err)
		}
		if _, err := file.WriteString(content); err != nil {
			_ = file.Close()
			t.Fatalf("write managed-key signer %s: %v", name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			t.Fatalf("sync managed-key signer %s: %v", name, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close managed-key signer %s: %v", name, err)
		}
		return path
	}
	return write("signer.passwd", passwd), write("signer.group", group)
}

func TestDODManagedKeySignerNSSIsScopedAndNonRoot(t *testing.T) {
	dir := t.TempDir()
	passwdFile, groupFile := dodManagedKeySignerNSS(t, dir, 501, 20)
	passwd, err := os.ReadFile(passwdFile)
	if err != nil {
		t.Fatal(err)
	}
	group, err := os.ReadFile(groupFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(passwd) != "root:x:0:0:root:/root:/usr/sbin/nologin\ndodsigner:x:501:20:DoD managed-key signer:/runtime:/usr/sbin/nologin\n" {
		t.Fatalf("signer passwd = %q", passwd)
	}
	if string(group) != "root:x:0:\ndodsigner:x:20:\n" {
		t.Fatalf("signer group = %q", group)
	}
	for _, path := range []string{passwdFile, groupFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("signer NSS mode = %04o, want 0600", info.Mode().Perm())
		}
	}
}

func dodManagedKeyShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (r *dodManagedKeyRuntime) stopSigner(key dodManagedKeyWire) *dodTPMPublicWitness {
	r.t.Helper()
	var before *dodTPMPublicWitness
	if r.provider == config.ManagedKeyProviderTPM2 {
		r.requireHardwareKeyID(key.KeyID)
		observed, ok := r.readTPMPublicWitness(key.KeyID, "before-restart")
		if !ok {
			r.t.Fatalf("TPM persistent handle %q is absent before signer restart", key.KeyID)
		}
		if err := dodValidateTPMPublicSurvival(key.PublicDER, observed, observed); err != nil {
			r.t.Fatalf("TPM public material before signer restart: %v", err)
		}
		before = &observed
		r.dockerExecTPM(true, "shutdown TPM emulator before signer restart", "tpm2_shutdown", "-c")
	}
	dodRunCommand(r.t, "stop managed-key signer for outbox redelivery", "docker", "stop", "-t", "2", r.containerName)
	return before
}

func (r *dodManagedKeyRuntime) restartSigner(key dodManagedKeyWire, before *dodTPMPublicWitness) {
	r.t.Helper()
	dodRunCommand(r.t, "restart managed-key signer", "docker", "start", r.containerName)
	r.waitSigner()
	if r.provider == config.ManagedKeyProviderTPM2 {
		if before == nil {
			r.t.Fatal("TPM restart proof omitted the pre-restart public witness")
		}
		after, ok := r.readTPMPublicWitness(key.KeyID, "after-restart")
		if !ok {
			r.t.Fatalf("TPM persistent handle %q did not survive signer restart", key.KeyID)
		}
		if err := dodValidateTPMPublicSurvival(key.PublicDER, *before, after); err != nil {
			r.t.Fatalf("TPM custody changed across signer restart: %v", err)
		}
		r.assertTPMPostRestartSignature(key)
	}
}

func (r *dodManagedKeyRuntime) waitSigner() {
	r.t.Helper()
	address := dodManagedKeySignerAddress(r.t, r.signerPort)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	logs := dodCommandOutput("docker", "logs", r.containerName)
	r.t.Fatalf("separate signer did not listen: %s", logs)
}

func (r *dodManagedKeyRuntime) bootstrapToken() {
	r.t.Helper()
	tenant := dodManagedKeyTenant(r.entryID)
	r.token = r.control.CreateToken(r.dir, r.env, "token", "create", "--tenant", tenant, "--tenant-name", "DoD managed keys", "--subject", "dod-hsm-operator", "--scopes", "keys:read,keys:write,keys:approve")
	if r.token == "" {
		r.t.Fatal("bootstrap returned an empty API token")
	}
	r.approvalSubjects = []string{"dod-hsm-custodian-one", "dod-hsm-custodian-two"}
	for index, subject := range r.approvalSubjects {
		token := r.control.CreateToken(r.dir, r.env, "token", "create", "--tenant", tenant, "--tenant-name", "DoD managed keys", "--subject", subject, "--scopes", "keys:approve")
		if token == "" {
			r.t.Fatalf("bootstrap returned an empty API token for approver %d", index+1)
		}
		r.approvalTokens = append(r.approvalTokens, token)
	}
}

func (r *dodManagedKeyRuntime) waitControlPlane() {
	r.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", r.serverPort))
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode/100 == 2 {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	r.t.Fatalf("control plane did not serve: signer_logs=%s control_logs=%s", dodCommandOutput("docker", "logs", r.containerName), r.control.Logs())
}

func dodManagedKeyRequestObject(r *dodManagedKeyRuntime, method, path, idempotency string, value any) *http.Request {
	return dodManagedKeyRequestObjectWithToken(r, r.token, method, path, idempotency, value)
}

func dodManagedKeyRequestObjectWithToken(r *dodManagedKeyRuntime, token, method, path, idempotency string, value any) *http.Request {
	r.t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		r.t.Fatal(err)
	}
	request, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", r.serverPort, path), bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", "dod-"+strings.ReplaceAll(r.entryID, ".", "-")+"-"+idempotency)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func dodManagedKeyRequest(r *dodManagedKeyRuntime, method, path, idempotency string, value any) *http.Response {
	return dodManagedKeyRequestWithToken(r, r.token, method, path, idempotency, value)
}

func dodManagedKeyRequestWithToken(r *dodManagedKeyRuntime, token, method, path, idempotency string, value any) *http.Response {
	r.t.Helper()
	request := dodManagedKeyRequestObjectWithToken(r, token, method, path, idempotency, value)
	client := &http.Client{Timeout: 35 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		r.t.Fatalf("managed-key %s: %v logs=%s", path, err, r.control.Logs())
	}
	return response
}

func (r *dodManagedKeyRuntime) approveManagedKeyAction(keyID, action string) {
	r.t.Helper()
	path := "/api/v1/managed-keys/" + action
	switch action {
	case "rotate", "revoke", "zeroize":
	default:
		r.t.Fatalf("unsupported managed-key approval action %q", action)
	}
	if len(r.approvalTokens) != 2 || len(r.approvalSubjects) != 2 {
		r.t.Fatalf("managed-key proof has %d approval tokens and %d subjects, want exactly two", len(r.approvalTokens), len(r.approvalSubjects))
	}

	r.requireManagedKeyCommandAbsent(action)
	denied := dodManagedKeyRequest(r, http.MethodPost, path, action, map[string]string{"key_id": keyID})
	deniedBody := r.readManagedKeyResponse(denied)
	if denied.StatusCode != http.StatusForbidden || !bytes.Contains(deniedBody, []byte("dual control")) {
		r.t.Fatalf("unapproved managed-key %s status=%d body=%s, want 403 dual-control denial", action, denied.StatusCode, deniedBody)
	}
	r.requireManagedKeyCommandAbsent(action)

	approval := map[string]string{"key_id": keyID, "action": action}
	self := dodManagedKeyRequest(r, http.MethodPost, "/api/v1/managed-keys/approvals", action+"-self-approval", approval)
	selfBody := r.readManagedKeyResponse(self)
	if self.StatusCode != http.StatusForbidden || !bytes.Contains(selfBody, []byte("cannot approve")) {
		r.t.Fatalf("managed-key %s self-approval status=%d body=%s, want 403", action, self.StatusCode, selfBody)
	}

	for index, token := range r.approvalTokens {
		response := dodManagedKeyRequestWithToken(r, token, http.MethodPost, "/api/v1/managed-keys/approvals",
			fmt.Sprintf("%s-approval-%d", action, index+1), approval)
		body := r.readManagedKeyResponse(response)
		if response.StatusCode != http.StatusOK {
			r.t.Fatalf("managed-key %s approval %d status=%d body=%s", action, index+1, response.StatusCode, body)
		}
		var recorded struct {
			Resource  string `json:"resource"`
			Action    string `json:"action"`
			Approver  string `json:"approver"`
			Approvals int    `json:"approvals"`
		}
		if err := json.Unmarshal(body, &recorded); err != nil {
			r.t.Fatalf("decode managed-key %s approval %d: %v body=%s", action, index+1, err, body)
		}
		if recorded.Resource != keyID || recorded.Action != "managedkey:"+action || recorded.Approver != r.approvalSubjects[index] || recorded.Approvals != index+1 {
			r.t.Fatalf("managed-key %s approval %d = %+v", action, index+1, recorded)
		}
		if index == 0 {
			oneApproval := dodManagedKeyRequest(r, http.MethodPost, path, action, map[string]string{"key_id": keyID})
			oneApprovalBody := r.readManagedKeyResponse(oneApproval)
			if oneApproval.StatusCode != http.StatusForbidden || !bytes.Contains(oneApprovalBody, []byte("dual control")) {
				r.t.Fatalf("managed-key %s after one approval status=%d body=%s, want 403", action, oneApproval.StatusCode, oneApprovalBody)
			}
			r.requireManagedKeyCommandAbsent(action)
		}
	}
	r.requireManagedKeyCommandAbsent(action)
}

func (r *dodManagedKeyRuntime) readManagedKeyResponse(response *http.Response) []byte {
	r.t.Helper()
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		r.t.Fatal(err)
	}
	return body
}

func (r *dodManagedKeyRuntime) requireManagedKeyCommandAbsent(idempotencySuffix string) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, r.artifacts.postgresDSN)
	if err != nil {
		r.t.Fatalf("connect for managed-key denial evidence: %v", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	var count int
	if err := connection.QueryRow(ctx,
		`SELECT count(*) FROM managed_key_operations WHERE tenant_id = $1 AND operation_id = $2`,
		dodManagedKeyTenant(r.entryID), dodManagedKeyOperationID(r.entryID, idempotencySuffix)).Scan(&count); err != nil {
		r.t.Fatalf("query managed-key denial evidence: %v", err)
	}
	if count != 0 {
		r.t.Fatalf("unapproved managed-key %s persisted %d provider commands", idempotencySuffix, count)
	}
}

func (r *dodManagedKeyRuntime) responseBody(response *http.Response) []byte {
	r.t.Helper()
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		r.t.Fatal(err)
	}
	if response.StatusCode/100 != 2 {
		r.t.Fatalf("managed-key response status=%d body=%s durable=%s", response.StatusCode, body, r.durableDiagnostics())
	}
	return body
}

func (r *dodManagedKeyRuntime) durableDiagnostics() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, r.artifacts.postgresDSN)
	if err != nil {
		return "connect=" + err.Error()
	}
	defer func() { _ = connection.Close(context.Background()) }()
	tenantID := dodManagedKeyTenant(r.entryID)
	rows, err := connection.Query(ctx,
		`SELECT id, status, attempts, COALESCE(last_error, ''), COALESCE(worker_id, '')
		   FROM outbox
		  WHERE tenant_id = $1 AND destination = $2
		  ORDER BY id`, tenantID, "managedkey.command")
	if err != nil {
		return "query-outbox=" + err.Error()
	}
	var out strings.Builder
	for rows.Next() {
		var id int64
		var statusValue, lastError, workerID string
		var attempts int
		if err := rows.Scan(&id, &statusValue, &attempts, &lastError, &workerID); err != nil {
			rows.Close()
			return "scan-outbox=" + err.Error()
		}
		fmt.Fprintf(&out, "outbox{id=%d status=%s attempts=%d worker=%s error=%q} ", id, statusValue, attempts, workerID, lastError)
	}
	rows.Close()
	operationRows, err := connection.Query(ctx,
		`SELECT operation_id, status, COALESCE(last_error, '')
		   FROM managed_key_operations
		  WHERE tenant_id = $1
		  ORDER BY created_at`, tenantID)
	if err != nil {
		return out.String() + "query-operations=" + err.Error()
	}
	defer operationRows.Close()
	for operationRows.Next() {
		var operationID, statusValue, lastError string
		if err := operationRows.Scan(&operationID, &statusValue, &lastError); err != nil {
			return out.String() + "scan-operations=" + err.Error()
		}
		fmt.Fprintf(&out, "operation{id=%s status=%s error=%q} ", operationID, statusValue, lastError)
	}
	if out.Len() == 0 {
		out.WriteString("no managed-key durable rows ")
	}
	journalFiles, _ := filepath.Glob(filepath.Join(r.dir, "keystore", "managed-key-operations", "*.json"))
	for _, journalFile := range journalFiles {
		raw, readErr := os.ReadFile(journalFile)
		if readErr == nil {
			switch filepath.Base(journalFile) {
			case "ownership.json":
				out.WriteString(dodManagedKeyOwnershipDiagnostic(raw))
			case "sign-authorization-nonces.json":
				out.WriteString(dodManagedKeyNonceDiagnostic(raw))
			default:
				out.WriteString(dodManagedKeyJournalDiagnostic(journalFile, raw))
			}
			out.WriteByte(' ')
		}
	}
	if r.controlProviderEndpoint != "" {
		fmt.Fprintf(&out, "emulator-direct=%q emulator-via-control-relay=%q ",
			dodManagedKeyHTTPDiagnostic(r.external.Endpoint()+"/dod/diagnostics"),
			dodManagedKeyHTTPDiagnostic(r.controlProviderEndpoint+"/dod/diagnostics"))
	}
	fmt.Fprintf(&out, "signer-top=%q signer-logs=%q signer-network=%q ",
		dodManagedKeyCompactDiagnostic(dodCommandOutput("docker", "top", r.containerName, "-eo", "pid,comm,args")),
		dodManagedKeyCompactDiagnostic(dodCommandOutput("docker", "logs", "--tail=80", r.containerName)),
		dodManagedKeyCompactDiagnostic(dodCommandOutput("docker", "network", "inspect", "--format={{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}", r.artifacts.network)))
	return out.String()
}

func dodManagedKeyHTTPDiagnostic(endpoint string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return "error=" + err.Error()
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return fmt.Sprintf("status=%d read=%v", response.StatusCode, err)
	}
	return fmt.Sprintf("status=%d body=%s", response.StatusCode, body)
}

func dodManagedKeyCompactDiagnostic(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 4096 {
		return value[:4096] + "..."
	}
	return value
}

func dodManagedKeyJournalDiagnostic(path string, raw []byte) string {
	type journal struct {
		Version int `json:"version"`
		Request struct {
			TenantID    string           `json:"tenant_id"`
			Provider    string           `json:"provider"`
			OperationID string           `json:"operation_id"`
			Action      int32            `json:"action"`
			KeyID       string           `json:"key_id"`
			Algorithm   crypto.Algorithm `json:"algorithm"`
		} `json:"request"`
		Status  string `json:"status"`
		Failure string `json:"failure"`
		Result  struct {
			Provider string `json:"provider"`
			KeyID    string `json:"key_id"`
			State    string `json:"state"`
		} `json:"result"`
	}
	name := filepath.Base(path)
	if len(raw) > 1<<20 {
		return fmt.Sprintf("signer-journal{name=%q invalid=oversize size=%d}", name, len(raw))
	}
	var value journal
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Sprintf("signer-journal{name=%q invalid=json size=%d}", name, len(raw))
	}
	return fmt.Sprintf("signer-journal{name=%q operation=%q action=%d status=%q failure=%q key=%q result_key=%q result_state=%q}",
		dodManagedKeyDiagnosticField(name), dodManagedKeyDiagnosticField(value.Request.OperationID), value.Request.Action,
		dodManagedKeyDiagnosticField(value.Status), dodManagedKeyDiagnosticField(value.Failure),
		dodManagedKeyDiagnosticField(value.Request.KeyID), dodManagedKeyDiagnosticField(value.Result.KeyID), dodManagedKeyDiagnosticField(value.Result.State))
}

func dodManagedKeyDiagnosticField(input string) string {
	if len(input) > 256 {
		input = input[:256]
	}
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, input)
}

func dodManagedKeyOwnershipDiagnostic(raw []byte) string {
	type owner struct {
		TenantID  string           `json:"tenant_id"`
		Provider  string           `json:"provider"`
		KeyID     string           `json:"key_id"`
		Algorithm crypto.Algorithm `json:"algorithm"`
		State     string           `json:"state"`
	}
	if len(raw) > 1<<20 {
		return fmt.Sprintf("signer-owners{invalid=oversize size=%d}", len(raw))
	}
	var owners []owner
	if err := json.Unmarshal(raw, &owners); err != nil {
		return fmt.Sprintf("signer-owners{invalid=json size=%d}", len(raw))
	}
	summaries := make([]string, 0, len(owners))
	for _, value := range owners {
		summaries = append(summaries, fmt.Sprintf("tenant=%q provider=%q key=%q algorithm=%q state=%q",
			dodManagedKeyDiagnosticField(value.TenantID), dodManagedKeyDiagnosticField(value.Provider),
			dodManagedKeyDiagnosticField(value.KeyID), value.Algorithm, dodManagedKeyDiagnosticField(value.State)))
	}
	sort.Strings(summaries)
	return fmt.Sprintf("signer-owners{count=%d %s}", len(summaries), strings.Join(summaries, ";"))
}

func dodManagedKeyNonceDiagnostic(raw []byte) string {
	if len(raw) > 1<<20 {
		return fmt.Sprintf("signer-nonces{invalid=oversize size=%d}", len(raw))
	}
	var nonces map[string]int64
	if err := json.Unmarshal(raw, &nonces); err != nil {
		return fmt.Sprintf("signer-nonces{invalid=json size=%d}", len(raw))
	}
	return fmt.Sprintf("signer-nonces{count=%d}", len(nonces))
}

func TestDODManagedKeyJournalDiagnosticIsClosedAndBounded(t *testing.T) {
	raw := []byte(`{"version":1,"request":{"tenant_id":"tenant-1","provider":"tpm2","operation_id":"managedkey:op-1","action":2,"key_id":"0x81010000","algorithm":"RSA-2048"},"status":"executing","result":{},"untrusted_secret":"must-not-appear"}`)
	diagnostic := dodManagedKeyJournalDiagnostic("/runtime/operation.json", raw)
	for _, required := range []string{`name="operation.json"`, `operation="managedkey:op-1"`, `action=2`, `status="executing"`, `key="0x81010000"`} {
		if !strings.Contains(diagnostic, required) {
			t.Fatalf("journal diagnostic %q omits %q", diagnostic, required)
		}
	}
	if strings.Contains(diagnostic, "must-not-appear") || len(diagnostic) > 2048 {
		t.Fatalf("journal diagnostic is not closed/bounded: %q", diagnostic)
	}
	owners := dodManagedKeyOwnershipDiagnostic([]byte(`[{"tenant_id":"tenant-1","provider":"tpm2","key_id":"0x81010000","algorithm":"RSA-2048","public_der":"c2VjcmV0LXB1YmxpYy1ieXRlcw==","state":"active"}]`))
	if !strings.Contains(owners, `count=1`) || !strings.Contains(owners, `key="0x81010000"`) || strings.Contains(owners, "c2VjcmV0") {
		t.Fatalf("ownership diagnostic is not closed: %q", owners)
	}
}

func (r *dodManagedKeyRuntime) cloudReadback(keyID, state string) dodManagedKeyReadback {
	r.t.Helper()
	query := url.Values{"key_id": []string{keyID}, "expect": []string{state}}
	response, err := http.Get(r.external.Endpoint() + "/dod/readback?" + query.Encode())
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var readback dodManagedKeyReadback
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&readback) != nil || readback.State != state {
		r.t.Fatalf("cloud managed-key readback state=%s status=%d", state, response.StatusCode)
	}
	return readback
}

func (r *dodManagedKeyRuntime) requireHardwareKeyID(keyID string) {
	r.t.Helper()
	if err := dodValidateHardwareKeyID(r.provider, keyID); err != nil {
		r.t.Fatalf("unsafe %s managed-key provider identity: %v", r.provider, err)
	}
}

func dodValidateHardwareKeyID(provider, keyID string) error {
	switch provider {
	case config.ManagedKeyProviderTPM2:
		if len(keyID) != 10 || !strings.HasPrefix(keyID, "0x") || keyID != strings.ToLower(keyID) {
			return fmt.Errorf("TPM handle %q is not canonical 0x plus eight lowercase hex digits", keyID)
		}
		handle, err := strconv.ParseUint(keyID[2:], 16, 32)
		if err != nil {
			return fmt.Errorf("TPM handle %q is not hexadecimal", keyID)
		}
		if handle < dodTPMOwnerPersistentFirst || handle > dodTPMOwnerPersistentLast {
			return fmt.Errorf("TPM handle %q is outside the owner-persistent range", keyID)
		}
	case config.ManagedKeyProviderPKCS11, config.ManagedKeyProviderYubiHSM2:
		if len(keyID) != dodPKCS11KeyIDHexLength || len(keyID)%2 != 0 || keyID != strings.ToLower(keyID) {
			return fmt.Errorf("PKCS#11 object ID %q is not exactly %d lowercase hex digits", keyID, dodPKCS11KeyIDHexLength)
		}
		decoded, err := hex.DecodeString(keyID)
		if err != nil || len(decoded) != dodPKCS11KeyIDHexLength/2 {
			return fmt.Errorf("PKCS#11 object ID %q is not canonical hexadecimal", keyID)
		}
	}
	return nil
}

func (r *dodManagedKeyRuntime) hardwareSignAndWitness(generated, rotated dodManagedKeyWire, revoked, zeroized bool) []byte {
	r.t.Helper()
	r.requireHardwareKeyID(generated.KeyID)
	r.requireHardwareKeyID(rotated.KeyID)
	messagePath := filepath.Join(r.dir, "device-message")
	if err := os.WriteFile(messagePath, []byte(dodManagedKeyProbe), 0o600); err != nil {
		r.t.Fatal(err)
	}
	generatedPresent := r.hardwarePresent(generated.KeyID)
	rotatedPresent := r.hardwarePresent(rotated.KeyID)
	signaturePath := filepath.Join(r.dir, "device-signature")
	if err := os.Remove(signaturePath); err != nil && !os.IsNotExist(err) {
		r.t.Fatal(err)
	}
	if r.provider == config.ManagedKeyProviderTPM2 {
		r.dockerExecTPM(true, "sign independent device message", "tpm2_sign", "-c", rotated.KeyID, "-g", "sha256", "-f", "plain", "-o", "/runtime/device-signature", "/runtime/device-message")
	} else {
		r.dockerExecPKCS11(true, "sign independent device message", "pkcs11-tool", "--module", "/runtime/libsofthsm2.so", "--login", "--pin", "12345678", "--sign", "--id", rotated.KeyID, "--mechanism", "SHA256-RSA-PKCS", "--input-file", "/runtime/device-message", "--output-file", "/runtime/device-signature")
	}
	signature, err := os.ReadFile(signaturePath)
	if err != nil || len(signature) == 0 {
		r.t.Fatalf("read independent device signature: %v", err)
	}
	_ = revoked
	_ = zeroized
	if !generatedPresent || !rotatedPresent {
		r.t.Fatal("independent device reader did not find both generated keys")
	}
	return signature
}

func (r *dodManagedKeyRuntime) hardwarePresent(keyID string) bool {
	r.t.Helper()
	r.requireHardwareKeyID(keyID)
	if r.provider == config.ManagedKeyProviderTPM2 {
		_, ok := r.dockerExecTPM(false, "read exact TPM public handle", "tpm2_readpublic", "-c", keyID)
		return ok
	}
	// OpenSC pkcs11-tool accepts --id with --list-objects but some modules still
	// enumerate every object in the token. With a predecessor key intentionally
	// left present after rotation, grepping that output therefore reports a false
	// positive after the successor has really been destroyed. Reading the public
	// object is an exact-ID lookup: it exits non-zero when that one object is gone.
	_, ok := r.dockerExecPKCS11(false, "read exact PKCS11 public object", "pkcs11-tool", "--module", "/runtime/libsofthsm2.so", "--login", "--pin", "12345678", "--read-object", "--type", "pubkey", "--id", keyID, "--output-file", "/dev/null")
	return ok
}

func (r *dodManagedKeyRuntime) readTPMPublicWitness(keyID, label string) (dodTPMPublicWitness, bool) {
	r.t.Helper()
	r.requireHardwareKeyID(keyID)
	if label == "" || strings.ContainsAny(label, "/\\\x00\r\n") {
		r.t.Fatalf("invalid TPM public witness label %q", label)
	}
	publicName := "tpm-public-" + label + ".der"
	objectName := "tpm-name-" + label + ".bin"
	publicPath := filepath.Join(r.dir, publicName)
	namePath := filepath.Join(r.dir, objectName)
	for _, path := range []string{publicPath, namePath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			r.t.Fatal(err)
		}
	}
	_, ok := r.dockerExecTPM(false, "read exact TPM public material "+label, "tpm2_readpublic", "-c", keyID, "-f", "der", "-o", "/runtime/"+publicName, "-n", "/runtime/"+objectName)
	if !ok {
		return dodTPMPublicWitness{}, false
	}
	publicDER, err := os.ReadFile(publicPath)
	if err != nil {
		r.t.Fatalf("read TPM public DER %s: %v", label, err)
	}
	name, err := os.ReadFile(namePath)
	if err != nil {
		r.t.Fatalf("read TPM object Name %s: %v", label, err)
	}
	return dodTPMPublicWitness{PublicDER: publicDER, Name: name}, true
}

func dodValidateTPMPublicSurvival(generatedDER []byte, before, after dodTPMPublicWitness) error {
	if len(generatedDER) == 0 || len(before.PublicDER) == 0 || len(before.Name) == 0 || len(after.PublicDER) == 0 || len(after.Name) == 0 {
		return fmt.Errorf("public witness is incomplete")
	}
	if !bytes.Equal(before.PublicDER, generatedDER) {
		return fmt.Errorf("device public DER does not match the API response")
	}
	if !bytes.Equal(after.PublicDER, before.PublicDER) {
		return fmt.Errorf("public DER changed at the same persistent handle")
	}
	if !bytes.Equal(after.Name, before.Name) {
		return fmt.Errorf("TPM object Name changed at the same persistent handle")
	}
	return nil
}

func (r *dodManagedKeyRuntime) assertTPMPostRestartSignature(key dodManagedKeyWire) {
	r.t.Helper()
	r.requireHardwareKeyID(key.KeyID)
	messagePath := filepath.Join(r.dir, "tpm-restart-message")
	signaturePath := filepath.Join(r.dir, "tpm-restart-signature")
	if err := os.WriteFile(messagePath, []byte(dodManagedKeyRestartProbe), 0o600); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Remove(signaturePath); err != nil && !os.IsNotExist(err) {
		r.t.Fatal(err)
	}
	r.dockerExecTPM(true, "sign with exact TPM key after restart", "tpm2_sign", "-c", key.KeyID, "-g", "sha256", "-f", "plain", "-o", "/runtime/tpm-restart-signature", "/runtime/tpm-restart-message")
	signature, err := os.ReadFile(signaturePath)
	if err != nil || len(signature) == 0 {
		r.t.Fatalf("read post-restart TPM signature: %v", err)
	}
	if err := crypto.VerifyMessage(key.PublicDER, []byte(dodManagedKeyRestartProbe), signature); err != nil {
		r.t.Fatalf("post-restart TPM signature did not verify against pre-restart API public key: %v", err)
	}
}

func (r *dodManagedKeyRuntime) installTPMForeignOperationCollision() {
	r.t.Helper()
	operationID := dodManagedKeyOperationID(r.entryID, "generate")
	tag, err := crypto.Digest(crypto.SHA256, []byte("trstctl:tpm2:managed-key:"+operationID))
	if err != nil {
		r.t.Fatal(err)
	}
	r.tpmGenerateOperationTag = hex.EncodeToString(tag)
	const (
		baseHandle = uint64(0x81010000)
		maxHandle  = uint64(0x817fffff)
	)
	minHandle := baseHandle + 0x100
	first := minHandle + (binary.BigEndian.Uint64(tag[:8]) % (maxHandle - minHandle + 1))
	r.tpmForeignHandle = fmt.Sprintf("0x%08x", uint32(first))
	foreignDir := filepath.Join(r.dir, "tpm-foreign")
	if err := os.RemoveAll(foreignDir); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Mkdir(foreignDir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	r.dockerExecTPM(true, "create foreign same-algorithm TPM collision", "tpm2_createprimary", "-C", "o", "-G", "rsa", "-g", "sha256", "-c", "/runtime/tpm-foreign/key.ctx")
	r.dockerExecTPM(true, "persist foreign same-algorithm TPM collision", "tpm2_evictcontrol", "-C", "o", "-c", "/runtime/tpm-foreign/key.ctx", r.tpmForeignHandle)
	r.dockerExecTPM(true, "flush foreign transient TPM context", "tpm2_flushcontext", "-t")
	r.dockerExecTPM(true, "read foreign persistent TPM collision", "tpm2_readpublic", "-c", r.tpmForeignHandle)
}

func (r *dodManagedKeyRuntime) assertTPMForeignCollisionAndOperationTag(generatedHandle string) {
	r.t.Helper()
	if generatedHandle == r.tpmForeignHandle {
		r.t.Fatalf("TPM operation bound the foreign same-algorithm first candidate %q", generatedHandle)
	}
	if !r.hardwarePresent(r.tpmForeignHandle) {
		r.t.Fatalf("TPM operation overwrote or removed foreign first candidate %q", r.tpmForeignHandle)
	}
	output, ok := r.dockerExecTPM(false, "read TPM durable operation tag", "tpm2_readpublic", "-c", generatedHandle)
	normalized := strings.ToLower(strings.Join(strings.Fields(string(output)), ""))
	if !ok || !strings.Contains(normalized, strings.ToLower(r.tpmGenerateOperationTag)) {
		r.t.Fatalf("TPM generated handle %q did not expose its exact durable operation tag through ReadPublic", generatedHandle)
	}
}

func (r *dodManagedKeyRuntime) assertHardwareRevoked(keyID string) {
	r.t.Helper()
	if r.provider == config.ManagedKeyProviderTPM2 {
		if r.hardwarePresent(keyID) {
			r.t.Fatal("TPM revoke left persistent signing handle present")
		}
		return
	}
	if err := os.Remove(filepath.Join(r.dir, "revoked-signature")); err != nil && !os.IsNotExist(err) {
		r.t.Fatal(err)
	}
	_, ok := r.dockerExecPKCS11(false, "attempt revoked PKCS11 signature", "pkcs11-tool", "--module", "/runtime/libsofthsm2.so", "--login", "--pin", "12345678", "--sign", "--id", keyID, "--mechanism", "SHA256-RSA-PKCS", "--input-file", "/runtime/device-message", "--output-file", "/runtime/revoked-signature")
	if ok {
		r.t.Fatal("revoked HSM key still produced a signature")
	}
}

func (r *dodManagedKeyRuntime) finishHardwareWitness(generated, rotated dodManagedKeyWire, signature []byte) {
	r.t.Helper()
	if r.hardwarePresent(rotated.KeyID) {
		r.t.Fatal("zeroized device key is still present")
	}
	witness := map[string]any{
		"generated_key": generated.KeyID, "rotated_key": rotated.KeyID,
		"public_der":        base64.StdEncoding.EncodeToString(rotated.PublicDER),
		"signature":         base64.StdEncoding.EncodeToString(signature),
		"message":           base64.StdEncoding.EncodeToString([]byte(dodManagedKeyProbe)),
		"generated_present": true, "rotated_present": true,
		"revoked_denied": true, "zeroized_absent": true,
	}
	body, _ := json.Marshal(witness)
	response, err := http.Post(r.external.Endpoint()+"/dod/witness", "application/json", bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		result, _ := io.ReadAll(response.Body)
		r.t.Fatalf("hardware witness rejected: status=%d body=%s", response.StatusCode, result)
	}
}

func (r *dodManagedKeyRuntime) dockerExec(requireSuccess bool, label, environment, command string, args ...string) ([]byte, bool) {
	r.t.Helper()
	dockerArgs := []string{"exec"}
	if environment != "" {
		dockerArgs = append(dockerArgs, "--env", environment)
	}
	dockerArgs = append(dockerArgs, r.containerName, command)
	dockerArgs = append(dockerArgs, args...)
	process := exec.Command("docker", dockerArgs...)
	output, err := process.CombinedOutput()
	if requireSuccess && err != nil {
		state := dodCommandOutput("docker", "inspect", "--format={{json .State}}", r.containerName)
		logs := dodCommandOutput("docker", "logs", "--tail=120", r.containerName)
		r.t.Fatalf("independent device command %q: %v output=%s state=%s logs=%s", label, err, output, state, logs)
	}
	return output, err == nil
}

func (r *dodManagedKeyRuntime) dockerExecTPM(requireSuccess bool, label, command string, args ...string) ([]byte, bool) {
	r.t.Helper()
	return r.dockerExec(requireSuccess, label, "TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321", command, args...)
}

func (r *dodManagedKeyRuntime) dockerExecPKCS11(requireSuccess bool, label, command string, args ...string) ([]byte, bool) {
	r.t.Helper()
	return r.dockerExec(requireSuccess, label, "SOFTHSM2_CONF=/runtime/softhsm2.conf", command, args...)
}

func (r *dodManagedKeyRuntime) close() {
	if r.closed {
		return
	}
	r.closed = true
	if r.control != nil {
		r.control.Stop()
	}
	_ = exec.Command("docker", "rm", "-f", r.containerName).Run()
}

func dodDecodeManagedKey(t *testing.T, body []byte) dodManagedKeyWire {
	t.Helper()
	var value dodManagedKeyWire
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode managed-key response: %v body=%s", err, body)
	}
	return value
}

func dodRequireActiveManagedKey(t *testing.T, value dodManagedKeyWire) {
	t.Helper()
	if value.KeyID == "" || value.Algorithm != crypto.RSA2048 || value.State != "active" || len(value.PublicDER) < 128 {
		t.Fatalf("invalid active managed key: %+v", value)
	}
}

func dodDecodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("decode base64 evidence: %v", err)
	}
	return decoded
}

func dodManagedKeyTenant(entryID string) string {
	digest, _ := crypto.Digest(crypto.SHA256, []byte(entryID))
	encoded := hex.EncodeToString(digest[:16])
	return encoded[0:8] + "-" + encoded[8:12] + "-4" + encoded[13:16] + "-8" + encoded[17:20] + "-" + encoded[20:32]
}

func dodManagedKeyOperationID(entryID, idempotencySuffix string) string {
	tenantID := dodManagedKeyTenant(entryID)
	rawKey := "dod-" + strings.ReplaceAll(entryID, ".", "-") + "-" + idempotencySuffix
	digest, _ := crypto.Digest(crypto.SHA256, []byte(tenantID+"\x00"+rawKey))
	return "managedkey:" + hex.EncodeToString(digest)
}

func dodContainerEndpoint(t *testing.T, endpoint string) string {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Port() == "" {
		t.Fatalf("invalid substrate endpoint %q", endpoint)
	}
	return "http://host.docker.internal:" + parsed.Port()
}

func dodFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func dodRunCommand(t *testing.T, label, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v output=%s", label, err, output)
	}
}

func dodRunCommandAt(t *testing.T, dir, label, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v output=%s", label, err, output)
	}
}

func dodBuiltImageID(t *testing.T, image, platform string) string {
	t.Helper()
	command := exec.Command("docker", "image", "inspect", "--format={{.Id}} {{.Os}}/{{.Architecture}}", image)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect built managed-key runtime image: %v output=%s", err, output)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[1] != platform {
		t.Fatalf("built managed-key runtime image inspect = %q, want image-id %s", strings.TrimSpace(string(output)), platform)
	}
	id, err := dodParseContentImageID(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func dodManagedKeyToolchainVersion(t *testing.T, repo string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		t.Fatalf("read managed-key toolchain version: %v", err)
	}
	fields := strings.Fields(string(raw))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != "toolchain" {
			continue
		}
		version := strings.TrimPrefix(fields[index+1], "go")
		if version == "" || strings.Trim(version, "0123456789.") != "" {
			t.Fatalf("go.mod toolchain %q is not an exact numeric Go version", fields[index+1])
		}
		return version
	}
	t.Fatal("go.mod has no exact toolchain directive for the signer builder")
	return ""
}

func dodPinnedBaseImage(t *testing.T, taggedImage, repository string) string {
	t.Helper()
	if repository == "" || strings.ContainsAny(repository, "@:\t\r\n ") {
		t.Fatalf("invalid pinned base repository %q", repository)
	}
	command := exec.Command("docker", "pull", "--platform", dodManagedKeyRuntimePlatform, taggedImage)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("pull exact-platform base for %s: %v output=%s", taggedImage, err, output)
	}
	command = exec.Command("docker", "image", "inspect", "--format={{json .RepoDigests}}", taggedImage)
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect immutable base for %s: %v output=%s", taggedImage, err, output)
	}
	var repoDigests []string
	if err := json.Unmarshal(bytes.TrimSpace(output), &repoDigests); err != nil {
		t.Fatalf("decode immutable base digests for %s: %v output=%s", taggedImage, err, output)
	}
	prefix := repository + "@"
	for _, reference := range repoDigests {
		if !strings.HasPrefix(reference, prefix) {
			continue
		}
		digest, parseErr := dodParseContentImageID(strings.TrimPrefix(reference, prefix))
		if parseErr == nil {
			return prefix + digest
		}
	}
	t.Fatalf("pulled base %s has no exact %s@sha256 RepoDigest: %v", taggedImage, repository, repoDigests)
	return ""
}

func dodParseContentImageID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	algorithm, digest, ok := strings.Cut(value, ":")
	decoded, err := hex.DecodeString(digest)
	if !ok || algorithm != "sha256" || err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) {
		return "", fmt.Errorf("managed-key runtime image id %q is not content-addressed sha256", value)
	}
	return value, nil
}

func TestDODManagedKeyContentAddressedImageID(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	if got, err := dodParseContentImageID("\n" + valid + "\n"); err != nil || got != valid {
		t.Fatalf("valid content image id = %q err=%v", got, err)
	}
	for _, invalid := range []string{"trstctl-managed-key-runtime:dod", "sha256:abc", "sha512:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if _, err := dodParseContentImageID(invalid); err == nil {
			t.Errorf("accepted mutable/invalid image reference %q", invalid)
		}
	}
}

func dodManagedKeyRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot locate repository root for managed-key runtime")
		}
		dir = parent
	}
}

func dodCommandOutput(name string, args ...string) string {
	output, _ := exec.Command(name, args...).CombinedOutput()
	return string(output)
}
