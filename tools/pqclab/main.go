// SPDX-License-Identifier: MPL-2.0

// Command pqclab runs the operator-facing, offline PQC rehearsal and archives
// evidence that is safe to hand to an auditor. Licensed mode delegates each
// stage to the exact shipped-binary DoD proof. Core mode launches a real
// trstctl_core binary and proves that Community honestly reports PQC execution
// as unavailable without attempting the proprietary mutation.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/config"
	internalcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	cardID                     = "I-b036ae4a"
	archiveSchemaVersion       = 1
	statusServed               = "served"
	statusUnavailableByEdition = "unavailable_by_edition"
	coreTenantID               = "d0d00000-0000-4000-8000-000000000607"
)

type licensedStage struct {
	ID          string
	Label       string
	Expectation string
}

var licensedStages = []licensedStage{
	{
		ID:          "pqc_end_to_end.pure_mldsa_leaf_stock_clients",
		Label:       "pure-ml-dsa-est",
		Expectation: "stock OpenSSL submits a pure ML-DSA EST enrollment to the shipped control plane",
	},
	{
		ID:          "pqc_end_to_end.multikey_spiffe_hybrid_svid",
		Label:       "hybrid-spiffe",
		Expectation: "the shipped Workload API returns the classical and post-quantum SVID pair",
	},
	{
		ID:          "pqc_end_to_end.automated_rollout_tls_findings",
		Label:       "cbom-migrate-rollback",
		Expectation: "a served CBOM finding is migrated, independently read back, and rolled back",
	},
}

type dodManifest struct {
	SchemaVersion   int        `json:"schema_version"`
	ManifestVersion int        `json:"manifest_version"`
	Entries         []dodEntry `json:"entries"`
}

type dodEntry struct {
	ID      string `json:"id"`
	Runtime struct {
		Method      string `json:"method"`
		Path        string `json:"path"`
		SubstrateID string `json:"substrate_id"`
	} `json:"runtime"`
}

type archiveManifest struct {
	SchemaVersion int            `json:"schema_version"`
	CardID        string         `json:"card_id"`
	Mode          string         `json:"mode"`
	Status        string         `json:"status"`
	Offline       bool           `json:"offline"`
	Revision      string         `json:"revision"`
	GeneratedAt   string         `json:"generated_at"`
	Source        manifestSource `json:"source_manifest"`
	Stages        []stageReceipt `json:"stages"`
}

type manifestSource struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	SchemaVersion   int    `json:"schema_version"`
	ManifestVersion int    `json:"manifest_version"`
}

type stageReceipt struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	Expectation       string `json:"expectation"`
	Method            string `json:"method,omitempty"`
	Path              string `json:"path,omitempty"`
	SubstrateID       string `json:"substrate_id,omitempty"`
	ReportSHA256      string `json:"report_sha256"`
	MutationAttempted *bool  `json:"mutation_attempted,omitempty"`
}

type coreReport struct {
	SchemaVersion      int          `json:"schema_version"`
	Status             string       `json:"status"`
	Edition            license.Info `json:"edition"`
	CBOMMethod         string       `json:"cbom_method"`
	CBOMPath           string       `json:"cbom_path"`
	CBOMStatusCode     int          `json:"cbom_status_code"`
	MutationAttempted  bool         `json:"mutation_attempted"`
	ExecutionAvailable bool         `json:"execution_available"`
	Explanation        string       `json:"explanation"`
}

type options struct {
	mode string
	out  string
	repo string
}

type commandKind uint8

const (
	commandGitRevision commandKind = iota + 1
	commandDODCensus
	commandCoreBuild
	commandCoreToken
	commandCoreServe
)

type commandRequest struct {
	kind   commandKind
	repo   string
	root   string
	output string
	stage  string
	pkg    string
	binary string
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pqc-operator-lab: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("pqc-operator-lab", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	mode := flags.String("mode", "licensed", "rehearsal mode: licensed or core")
	out := flags.String("out", "", "receipt archive path")
	repo := flags.String("repo", ".", "trstctl repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	opts := options{mode: strings.TrimSpace(*mode), out: strings.TrimSpace(*out), repo: strings.TrimSpace(*repo)}
	if opts.mode != "licensed" && opts.mode != "core" {
		return fmt.Errorf("--mode must be licensed or core, got %q", opts.mode)
	}
	if opts.out == "" {
		opts.out = filepath.Join(opts.repo, "dist", "pqc-operator-lab-"+opts.mode+".tar.gz")
	}
	repoAbs, err := filepath.Abs(opts.repo)
	if err != nil {
		return fmt.Errorf("resolve repo: %w", err)
	}
	opts.repo = repoAbs

	manifestPath := filepath.Join(opts.repo, "tools", "dodcensus", "manifest.json")
	sourceRaw, source, entries, err := loadDODManifest(manifestPath)
	if err != nil {
		return err
	}
	revision, err := gitRevision(ctx, opts.repo)
	if err != nil {
		return err
	}

	var files map[string][]byte
	var receipts []stageReceipt
	switch opts.mode {
	case "licensed":
		files, receipts, err = runLicensed(ctx, opts.repo, entries)
	case "core":
		files, receipts, err = runCore(ctx, opts.repo)
	}
	if err != nil {
		return err
	}
	runManifest := archiveManifest{
		SchemaVersion: archiveSchemaVersion,
		CardID:        cardID,
		Mode:          opts.mode,
		Status:        overallStatus(receipts),
		Offline:       true,
		Revision:      revision,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Source: manifestSource{
			Path:            "tools/dodcensus/manifest.json",
			SHA256:          checksumHex(sourceRaw),
			SchemaVersion:   source.SchemaVersion,
			ManifestVersion: source.ManifestVersion,
		},
		Stages: receipts,
	}
	files["manifest.json"] = mustJSON(runManifest)
	if err := writeArchive(opts.out, files); err != nil {
		return err
	}
	archiveRaw, err := os.ReadFile(opts.out)
	if err != nil {
		return fmt.Errorf("read completed archive: %w", err)
	}
	fmt.Printf("PQC operator rehearsal %s: %s\n", opts.mode, runManifest.Status)
	fmt.Printf("receipt: %s\n", opts.out)
	fmt.Printf("sha256: %s\n", checksumHex(archiveRaw))
	return nil
}

func loadDODManifest(path string) ([]byte, dodManifest, map[string]dodEntry, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
	if err != nil {
		return nil, dodManifest{}, nil, fmt.Errorf("read DoD manifest: %w", err)
	}
	var manifest dodManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, dodManifest{}, nil, fmt.Errorf("decode DoD manifest: %w", err)
	}
	entries := make(map[string]dodEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		entries[entry.ID] = entry
	}
	for _, stage := range licensedStages {
		if _, ok := entries[stage.ID]; !ok {
			return nil, dodManifest{}, nil, fmt.Errorf("DoD manifest no longer contains required stage %q", stage.ID)
		}
	}
	return raw, manifest, entries, nil
}

func gitRevision(ctx context.Context, repo string) (string, error) {
	cmd, err := newValidatedCommand(ctx, commandRequest{kind: commandGitRevision, repo: repo})
	if err != nil {
		return "", err
	}
	raw, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("read repository revision: %w", err)
	}
	revision := strings.TrimSpace(string(raw))
	if len(revision) != 40 {
		return "", fmt.Errorf("unexpected git revision %q", revision)
	}
	return revision, nil
}

func runLicensed(ctx context.Context, repo string, entries map[string]dodEntry) (map[string][]byte, []stageReceipt, error) {
	work, cleanup, err := privateWorkspace("", "trstctl-pqc-operator-licensed-")
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	files := map[string][]byte{}
	receipts := make([]stageReceipt, 0, len(licensedStages))
	cacheDir := filepath.Join(work, "gocache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create private DoD cache: %w", err)
	}
	for _, stage := range licensedStages {
		fmt.Printf(">> PQC rehearsal: %s\n", stage.Expectation)
		reportPath := filepath.Join(work, stage.Label+".json")
		cmd, err := newValidatedCommand(ctx, commandRequest{
			kind: commandDODCensus, repo: repo, root: work, output: reportPath, stage: stage.ID,
		})
		if err != nil {
			return nil, nil, err
		}
		cmd.Env = offlineGoEnvWithCache(os.Environ(), cacheDir)
		var censusLog bytes.Buffer
		cmd.Stdout = &censusLog
		cmd.Stderr = &censusLog
		if err := cmd.Run(); err != nil {
			return nil, nil, fmt.Errorf("stage %s: %w; census log=%s", stage.ID, err, sanitizeLog(censusLog.String()))
		}
		reportRaw, err := os.ReadFile(reportPath) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
		if err != nil {
			return nil, nil, fmt.Errorf("read stage %s report: %w", stage.ID, err)
		}
		if err := requireServedReport(reportRaw, stage.ID); err != nil {
			return nil, nil, err
		}
		entry := entries[stage.ID]
		receipt := stageReceipt{
			ID:           stage.ID,
			Status:       statusServed,
			Expectation:  stage.Expectation,
			Method:       entry.Runtime.Method,
			Path:         entry.Runtime.Path,
			SubstrateID:  entry.Runtime.SubstrateID,
			ReportSHA256: checksumHex(reportRaw),
		}
		files[filepath.ToSlash(filepath.Join("reports", stage.Label+".json"))] = appendNewline(reportRaw)
		files[filepath.ToSlash(filepath.Join("transcripts", stage.Label+".json"))] = mustJSON(receipt)
		receipts = append(receipts, receipt)
		fmt.Printf("<< PQC rehearsal: %s SERVED\n", stage.ID)
	}
	return files, receipts, nil
}

func requireServedReport(raw []byte, id string) error {
	var report struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("decode stage %s report: %w", id, err)
	}
	entry, ok := report.Entries[id]
	if !ok {
		return fmt.Errorf("stage report does not contain selected entry %q", id)
	}
	if entry.Status != statusServed {
		return fmt.Errorf("stage %s status = %q, want %q", id, entry.Status, statusServed)
	}
	return nil
}

func runCore(ctx context.Context, repo string) (map[string][]byte, []stageReceipt, error) {
	if err := requireLocalPostgresArtifact(); err != nil {
		return nil, nil, err
	}
	root, cleanup, err := privateWorkspace("/tmp", "trstctl-pqc-operator-core-")
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()

	controlBin := filepath.Join(root, "trstctl")
	signerBin := filepath.Join(root, "trstctl-signer")
	for _, build := range []struct {
		output string
		pkg    string
	}{
		{controlBin, "./cmd/trstctl"},
		{signerBin, "./cmd/trstctl-signer"},
	} {
		fmt.Printf(">> PQC core rehearsal: build %s with trstctl_core\n", build.pkg)
		cmd, err := newValidatedCommand(ctx, commandRequest{
			kind: commandCoreBuild, repo: repo, root: root, output: build.output, pkg: build.pkg,
		})
		if err != nil {
			return nil, nil, err
		}
		cmd.Env = offlineGoEnv(os.Environ())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, nil, fmt.Errorf("build core artifact %s: %w", build.pkg, err)
		}
	}

	serverPort, err := freePort()
	if err != nil {
		return nil, nil, err
	}
	postgresPort, err := freePort()
	if err != nil {
		return nil, nil, err
	}
	cfg := config.Default()
	cfg.Server.Addr = fmt.Sprintf("127.0.0.1:%d", serverPort)
	cfg.Server.TLS.Mode = config.TLSDisabled
	cfg.Server.TLS.AllowPlaintextDev = true
	cfg.Postgres.DataDir = filepath.Join(root, "postgres")
	cfg.Postgres.Port = postgresPort
	cfg.NATS.StoreDir = filepath.Join(root, "nats")
	cfg.AirGap.Enabled = true
	cfg.Telemetry.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "secrets-kek.bin")
	cfg.Signer.Socket = filepath.Join(root, "signer.sock")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "signer-auth.bin")
	cfg.Signer.AllowInsecureDevNonLinux = true
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.pem")
	configRaw, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("encode core rehearsal config: %w", err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write core rehearsal config: %w", err)
	}
	env := runtimeEnv(configPath)

	var tokenStdout bytes.Buffer
	var tokenStderr bytes.Buffer
	tokenCmd, err := newValidatedCommand(ctx, commandRequest{
		kind: commandCoreToken, root: root, binary: controlBin,
	})
	if err != nil {
		return nil, nil, err
	}
	tokenCmd.Env = env
	tokenCmd.Stdout = &tokenStdout
	tokenCmd.Stderr = &tokenStderr
	fmt.Println(">> PQC core rehearsal: bootstrap an isolated Community tenant")
	if err := tokenCmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("bootstrap Community token: %w; stderr=%s", err, strings.TrimSpace(tokenStderr.String()))
	}
	token := bytes.TrimSpace(tokenStdout.Bytes())
	defer secret.Wipe(token)
	if len(token) == 0 {
		return nil, nil, errors.New("bootstrap Community token was empty")
	}

	var serverLog bytes.Buffer
	serverCmd, err := newValidatedCommand(ctx, commandRequest{
		kind: commandCoreServe, root: root, binary: controlBin,
	})
	if err != nil {
		return nil, nil, err
	}
	serverCmd.Env = env
	serverCmd.Stdout = &serverLog
	serverCmd.Stderr = &serverLog
	if err := serverCmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start core control plane: %w", err)
	}
	serverProcess := &runningProcess{cmd: serverCmd, done: make(chan struct{})}
	go func() {
		serverProcess.err = serverCmd.Wait()
		close(serverProcess.done)
	}()
	defer serverProcess.stop()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", serverPort)
	client := netsec.InsecureLoopbackClient(10 * time.Second)
	fmt.Println(">> PQC core rehearsal: inspect served edition and CBOM read paths")
	if err := waitReady(ctx, client, baseURL, serverProcess); err != nil {
		return nil, nil, fmt.Errorf("%w; control-plane log=%s", err, sanitizeLog(serverLog.String()))
	}
	var editions license.Info
	if _, err := getJSON(ctx, client, baseURL+"/v1/editions", nil, &editions); err != nil {
		return nil, nil, err
	}
	report, err := coreEditionReceipt(editions)
	if err != nil {
		return nil, nil, err
	}
	auth := []byte("Bearer ")
	auth = append(auth, token...)
	defer secret.Wipe(auth)
	status, err := getJSON(ctx, client, baseURL+"/api/v1/cbom/assets", auth, nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("community CBOM read status = %d, want %d", status, http.StatusOK)
	}
	report.CBOMStatusCode = status

	reportRaw := mustJSON(report)
	notAttempted := false
	receipt := stageReceipt{
		ID:                "pqc_core.community_honest_degradation",
		Status:            statusUnavailableByEdition,
		Expectation:       "Community serves CBOM visibility, names PQC execution as unavailable by edition, and never calls the proprietary mutation",
		Method:            http.MethodGet,
		Path:              "/v1/editions + /api/v1/cbom/assets",
		SubstrateID:       "bundled-postgres-embedded-nats-core-binaries",
		ReportSHA256:      checksumHex(reportRaw),
		MutationAttempted: &notAttempted,
	}
	files := map[string][]byte{
		"reports/core-community.json":     reportRaw,
		"transcripts/core-community.json": mustJSON(receipt),
	}
	return files, []stageReceipt{receipt}, nil
}

func coreEditionReceipt(info license.Info) (coreReport, error) {
	if info.Tier != license.TierCommunity || info.State != license.StateCommunity {
		return coreReport{}, fmt.Errorf("core artifact reported tier/state %q/%q, want community/community", info.Tier, info.State)
	}
	var found bool
	for _, feature := range info.Features {
		if feature.Name != license.FeaturePQC {
			continue
		}
		found = true
		if feature.Licensed || feature.Mode != license.ModeOff {
			return coreReport{}, fmt.Errorf("community PQC feature reported licensed=%t mode=%q, want false/off", feature.Licensed, feature.Mode)
		}
	}
	if !found {
		return coreReport{}, errors.New("community editions response omitted the PQC feature")
	}
	return coreReport{
		SchemaVersion:      archiveSchemaVersion,
		Status:             statusUnavailableByEdition,
		Edition:            info,
		CBOMMethod:         http.MethodGet,
		CBOMPath:           "/api/v1/cbom/assets",
		MutationAttempted:  false,
		ExecutionAvailable: false,
		Explanation:        "PQC execution is unavailable in Community; CBOM visibility remains served and the rehearsal does not call an unserved proprietary mutation.",
	}, nil
}

func requireLocalPostgresArtifact() error {
	binary := filepath.Join(os.TempDir(), "trstctl-pg-bin", "bin", "postgres")
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		return fmt.Errorf("offline rehearsal requires the locally supplied bundled PostgreSQL artifact at %s; warm it through the verified supply-chain gate before disconnecting", binary)
	}
	return nil
}

// newValidatedCommand is the only process-creation boundary in pqclab. Callers
// choose a closed command kind; this function owns every executable and flag.
// Dynamic paths must remain inside the private workspace that this invocation
// created, and a stage/package must match the reviewed closed set.
func newValidatedCommand(ctx context.Context, request commandRequest) (*exec.Cmd, error) {
	var (
		name string
		args []string
		dir  string
	)
	switch request.kind {
	case commandGitRevision:
		if strings.TrimSpace(request.repo) == "" {
			return nil, errors.New("git revision command requires a repository")
		}
		name, args, dir = "git", []string{"rev-parse", "HEAD"}, request.repo
	case commandDODCensus:
		if !knownLicensedStage(request.stage) {
			return nil, fmt.Errorf("unreviewed DoD stage %q", request.stage)
		}
		if !pathWithin(request.root, request.output) {
			return nil, fmt.Errorf("DoD report path %q escapes private workspace %q", request.output, request.root)
		}
		name, dir = "go", request.repo
		args = []string{
			"run", "./tools/dodcensus",
			"--repo", ".",
			"--manifest", "tools/dodcensus/manifest.json",
			"--out", request.output,
			"--capability", request.stage,
		}
	case commandCoreBuild:
		if request.pkg != "./cmd/trstctl" && request.pkg != "./cmd/trstctl-signer" {
			return nil, fmt.Errorf("unreviewed core build package %q", request.pkg)
		}
		if !pathWithin(request.root, request.output) {
			return nil, fmt.Errorf("core build output %q escapes private workspace %q", request.output, request.root)
		}
		name, dir = "go", request.repo
		args = []string{"build", "-trimpath", "-tags", "trstctl_core", "-o", request.output, request.pkg}
	case commandCoreToken:
		if request.binary != filepath.Join(request.root, "trstctl") {
			return nil, fmt.Errorf("core token command binary %q is not the private control-plane artifact", request.binary)
		}
		name, dir = request.binary, request.root
		args = []string{
			"token", "create",
			"--tenant", coreTenantID,
			"--tenant-name", "PQC core operator rehearsal",
			"--subject", "pqc-core-rehearsal",
			"--scopes", "risk:read",
		}
	case commandCoreServe:
		if request.binary != filepath.Join(request.root, "trstctl") {
			return nil, fmt.Errorf("core serve command binary %q is not the private control-plane artifact", request.binary)
		}
		name, dir = request.binary, request.root
	default:
		return nil, fmt.Errorf("unreviewed command kind %d", request.kind)
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- developer tool running fixed toolchain commands over the repo (CWE-78)
	cmd.Dir = dir
	return cmd, nil
}

func knownLicensedStage(id string) bool {
	for _, stage := range licensedStages {
		if stage.ID == id {
			return true
		}
	}
	return false
}

func pathWithin(root, candidate string) bool {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(candidate) == "" {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func privateWorkspace(parent, prefix string) (string, func(), error) {
	root, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", nil, fmt.Errorf("create private rehearsal workspace: %w", err)
	}
	var once sync.Once
	return root, func() {
		once.Do(func() { _ = os.RemoveAll(root) })
	}, nil
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve loopback port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

type runningProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func waitReady(ctx context.Context, client *http.Client, baseURL string, process *runningProcess) error {
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/readyz", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return nil
			}
		}
		select {
		case <-process.done:
			return fmt.Errorf("core control plane exited before readiness: %w", process.err)
		case <-deadline.C:
			return errors.New("core control plane did not become ready within 2m")
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func getJSON(ctx context.Context, client *http.Client, url string, authorization []byte, dst any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build GET %s: %w", url, err)
	}
	if len(authorization) > 0 {
		request.Header.Set("Authorization", string(authorization))
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return response.StatusCode, fmt.Errorf("read GET %s: %w", url, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("GET %s status=%d body=%s", url, response.StatusCode, sanitizeLog(string(raw)))
	}
	if dst != nil {
		if err := json.Unmarshal(raw, dst); err != nil {
			return response.StatusCode, fmt.Errorf("decode GET %s: %w", url, err)
		}
	}
	return response.StatusCode, nil
}

func (process *runningProcess) stop() {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return
	}
	select {
	case <-process.done:
		return
	default:
	}
	_ = process.cmd.Process.Signal(os.Interrupt)
	select {
	case <-process.done:
		return
	case <-time.After(30 * time.Second):
		_ = process.cmd.Process.Kill()
		<-process.done
	}
}

func runtimeEnv(configPath string) []string {
	env := make([]string, 0, len(os.Environ())+5)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TRSTCTL_") {
			env = append(env, value)
		}
	}
	return append(env,
		"TRSTCTL_CONFIG_FILE="+configPath,
		"TRSTCTL_AIRGAP_ENABLED=true",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
	)
}

func offlineGoEnv(base []string) []string {
	env := make([]string, 0, len(base)+3)
	for _, value := range base {
		if strings.HasPrefix(value, "GOPROXY=") || strings.HasPrefix(value, "GOSUMDB=") || strings.HasPrefix(value, "GOTOOLCHAIN=") {
			continue
		}
		env = append(env, value)
	}
	return append(env, "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
}

func offlineGoEnvWithCache(base []string, cacheDir string) []string {
	env := make([]string, 0, len(base)+5)
	for _, value := range base {
		if strings.HasPrefix(value, "GOCACHE=") || strings.HasPrefix(value, "TRSTCTL_DOD_GOCACHE=") {
			continue
		}
		env = append(env, value)
	}
	return append(offlineGoEnv(env), "GOCACHE="+cacheDir, "TRSTCTL_DOD_GOCACHE="+cacheDir)
}

func overallStatus(receipts []stageReceipt) string {
	if len(receipts) == 0 {
		return "failed"
	}
	for _, receipt := range receipts {
		if receipt.Status != statusServed && receipt.Status != statusUnavailableByEdition {
			return "failed"
		}
	}
	return "passed"
}

func writeArchive(path string, files map[string][]byte) error {
	if len(files) == 0 {
		return errors.New("refuse to write an empty rehearsal archive")
	}
	clean := make(map[string][]byte, len(files)+1)
	names := make([]string, 0, len(files))
	for name, body := range files {
		normalized := filepath.ToSlash(filepath.Clean(name))
		if normalized == "." || normalized == "SHA256SUMS" || strings.HasPrefix(normalized, "../") || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe archive entry %q", name)
		}
		if err := validateArchivePayload(normalized, body); err != nil {
			return err
		}
		clean[normalized] = body
		names = append(names, normalized)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%s  %s\n", checksumHex(clean[name]), name)
	}
	clean["SHA256SUMS"] = []byte(sums.String())
	names = append(names, "SHA256SUMS")
	sort.Strings(names)

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil { // #nosec G301 -- developer tool writing repo/dist artifacts; the mode is intentional (CWE-276)
		return fmt.Errorf("create archive directory: %w", err)
	}
	tmp, err := os.CreateTemp(parent, ".pqc-operator-lab-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set archive mode: %w", err)
	}
	gz, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("create gzip writer: %w", err)
	}
	gz.ModTime = time.Unix(0, 0).UTC()
	gz.OS = 255
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := clean[name]
		header := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(body)),
			ModTime: time.Unix(0, 0).UTC(),
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(header); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = tmp.Close()
			return fmt.Errorf("write archive header %s: %w", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = tmp.Close()
			return fmt.Errorf("write archive entry %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = tmp.Close()
		return fmt.Errorf("close tar archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("close gzip archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish archive: %w", err)
	}
	return nil
}

func validateArchivePayload(name string, body []byte) error {
	lower := strings.ToLower(string(body))
	for _, marker := range []string{
		"-----begin private key-----",
		"-----begin rsa private key-----",
		"-----begin ec private key-----",
		"authorization: bearer ",
		`"authorization":"bearer `,
		"trst_",
	} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("refuse to archive secret-shaped material in %s", name)
		}
	}
	var decoded any
	if json.Unmarshal(body, &decoded) == nil {
		if key := sensitiveJSONValue(decoded); key != "" {
			return fmt.Errorf("refuse to archive non-empty sensitive field %q in %s", key, name)
		}
	}
	return nil
}

func sensitiveJSONValue(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if sensitiveField(normalized) && nonEmptyJSONValue(child) {
				return key
			}
			if nested := sensitiveJSONValue(child); nested != "" {
				return nested
			}
		}
	case []any:
		for _, child := range typed {
			if nested := sensitiveJSONValue(child); nested != "" {
				return nested
			}
		}
	}
	return ""
}

func sensitiveField(key string) bool {
	for _, exact := range []string{
		"token",
		"password",
		"passwd",
		"secret",
		"secret_value",
		"client_secret",
		"auth_secret",
		"private_key",
		"client_assertion",
	} {
		if key == exact {
			return true
		}
	}
	for _, suffix := range []string{"_token", "_password", "_passwd", "_secret_value", "_client_secret", "_auth_secret", "_private_key", "_client_assertion"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func nonEmptyJSONValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func sanitizeLog(raw string) string {
	lines := strings.Split(raw, "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	safe := strings.Join(lines, "\n")
	if strings.Contains(strings.ToLower(safe), "trst_") {
		return "[log withheld: token-shaped material detected]"
	}
	return strings.TrimSpace(safe)
}

func mustJSON(value any) []byte {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(raw, '\n')
}

func appendNewline(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	return append(raw, '\n')
}

func checksumHex(raw []byte) string {
	return internalcrypto.SHA256Hex(raw)
}
