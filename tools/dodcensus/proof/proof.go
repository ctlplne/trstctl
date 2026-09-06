// SPDX-License-Identifier: MPL-2.0

// Package proof writes nonce-bound runtime receipts for the repository-native
// Definition-of-Done census. Evidence is sealed: callers can choose one of the
// fixed domain probes below, but cannot mint a generic "passed" value from a
// bool, log line, or arbitrary observation map.
package proof

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

const maxEvidenceBody = 1 << 20

// RuntimeTempDir is the gate-owned short alias for the private receipt mount.
// Linux Unix-domain socket paths are limited to 108 bytes; host receipt paths
// can be much longer and remain mounted separately for parent receipt access.
const RuntimeTempDir = "/dod-tmp"

// RuntimeExecDir is a bounded, private, executable tmpfs owned by the dropped
// runtime UID. Compiler output never lands here: BuildShippedProcess copies
// already-validated bytes from the noexec /tmp staging area into this mount,
// then arms the mutation watcher. Keeping executable publication off Docker
// Desktop's host bind prevents delayed VirtioFS events from crossing the watch
// boundary without weakening post-publication mutation detection.
const RuntimeExecDir = "/dod-exec"

const (
	HostReceiptRootEnv = "TRSTCTL_DOD_HOST_RECEIPT_ROOT"
	RuntimeTempRootEnv = "TRSTCTL_DOD_RUNTIME_TEMP_ROOT"
	RuntimeExecRootEnv = "TRSTCTL_DOD_RUNTIME_EXEC_ROOT"
	// ShippedGoCacheEnv is issued by the census runner after it validates the
	// gate-private cache mount. Keeping compiled packages there prevents every
	// nonce-bound receipt mount from copying another complete Go cache tree.
	ShippedGoCacheEnv = "TRSTCTL_DOD_SHIPPED_GOCACHE"
)

// DockerHostMountSource translates a path under RuntimeTempDir back to the
// same private receipt path visible to the parent Docker daemon. Callers cannot
// translate arbitrary paths: both mounted roots and the selected object must
// be the same inode, and symlink/traversal paths fail closed.
func DockerHostMountSource(t *testing.T, candidate string) string {
	t.Helper()
	hostRoot := os.Getenv(HostReceiptRootEnv)
	aliasRoot := os.Getenv(RuntimeTempRootEnv)
	if aliasRoot != RuntimeTempDir {
		t.Fatalf("DOD-CENSUS: runtime temporary root %q is not gate-owned %q", aliasRoot, RuntimeTempDir)
	}
	hostSource, err := translateMountSuffix(hostRoot, aliasRoot, candidate)
	if err != nil {
		t.Fatalf("DOD-CENSUS: translate Docker host mount source: %v", err)
	}
	if err := validateMountTranslationIdentity(hostRoot, aliasRoot, hostSource, candidate); err != nil {
		t.Fatalf("DOD-CENSUS: validate Docker host mount source: %v", err)
	}
	return hostSource
}

func translateMountSuffix(hostRoot, aliasRoot, candidate string) (string, error) {
	for label, path := range map[string]string{"host receipt root": hostRoot, "runtime alias root": aliasRoot, "candidate": candidate} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, ",\r\n\x00") {
			return "", fmt.Errorf("%s %q is not a clean absolute mount path", label, path)
		}
	}
	relative, err := filepath.Rel(aliasRoot, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("candidate %q is not a scoped child of %q", candidate, aliasRoot)
	}
	hostSource := filepath.Join(hostRoot, relative)
	hostRelative, err := filepath.Rel(hostRoot, hostSource)
	if err != nil || hostRelative != relative || hostRelative == "." || strings.HasPrefix(hostRelative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("translated host mount escaped its private receipt root")
	}
	return hostSource, nil
}

func validateMountTranslationIdentity(hostRoot, aliasRoot, hostSource, candidate string) error {
	inspect := func(label, path string, requireDirectory bool) (os.FileInfo, error) {
		info, err := os.Lstat(path) // #nosec G703 -- developer tool probing repo/toolchain paths, not a served binary (CWE-22)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", label, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || (requireDirectory && !info.IsDir()) {
			return nil, fmt.Errorf("%s is a symlink or not a directory", label)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return nil, fmt.Errorf("%s contains a symlink: %w", label, err)
		}
		return info, nil
	}
	hostRootInfo, err := inspect("host receipt root", hostRoot, true)
	if err != nil {
		return err
	}
	aliasRootInfo, err := inspect("runtime alias root", aliasRoot, true)
	if err != nil {
		return err
	}
	if !os.SameFile(hostRootInfo, aliasRootInfo) {
		return fmt.Errorf("host receipt and runtime alias roots are not the same mount")
	}
	hostInfo, err := inspect("translated host source", hostSource, false)
	if err != nil {
		return err
	}
	candidateInfo, err := inspect("runtime candidate", candidate, false)
	if err != nil {
		return err
	}
	if hostInfo.IsDir() != candidateInfo.IsDir() || !os.SameFile(hostInfo, candidateInfo) {
		return fmt.Errorf("translated host source and runtime candidate are not the same object")
	}
	return nil
}

func validSHA256Digest(value string) bool {
	algorithm, encoded, ok := strings.Cut(value, ":")
	digest, err := hex.DecodeString(encoded)
	return ok && algorithm == "sha256" && err == nil && len(digest) == 32 && encoded == strings.ToLower(encoded)
}

var sentinelFragments = [][]byte{
	[]byte("not configured"),
	[]byte("not implemented"),
	[]byte("unrouted"),
	[]byte(`"status":"stub"`),
	[]byte(`"status": "stub"`),
}

type expectation struct {
	SchemaVersion         int               `json:"schema_version"`
	Repo                  string            `json:"repo"`
	Nonce                 string            `json:"nonce"`
	ID                    string            `json:"id"`
	BuildProfile          string            `json:"build_profile"`
	Method                string            `json:"method"`
	Path                  string            `json:"path"`
	RuntimeMode           string            `json:"runtime_mode"`
	SubstrateID           string            `json:"substrate_id"`
	SubstrateKind         string            `json:"substrate_kind"`
	SubstrateIdentity     string            `json:"substrate_identity"`
	ContractDigest        string            `json:"contract_digest"`
	Verifier              string            `json:"verifier"`
	Execution             string            `json:"execution"`
	Command               []string          `json:"command,omitempty"`
	Image                 string            `json:"image,omitempty"`
	ReceiptFile           string            `json:"receipt_file"`
	EvidenceFile          string            `json:"evidence_file"`
	RuntimeRunnerIdentity string            `json:"runtime_runner_identity"`
	RuntimeRunnerImage    string            `json:"runtime_runner_image,omitempty"`
	RuntimeTestPackage    string            `json:"runtime_test_package"`
	RuntimeCGOEnabled     string            `json:"runtime_cgo_enabled"`
	RuntimeGOOS           string            `json:"runtime_goos"`
	RuntimeGOARCH         string            `json:"runtime_goarch"`
	RuntimeTags           []string          `json:"runtime_tags,omitempty"`
	LaunchedModulePath    string            `json:"launched_module_path"`
	LaunchedBinaryPackage string            `json:"launched_binary_package"`
	LaunchedCompanions    []string          `json:"launched_companions,omitempty"`
	LaunchedCGOEnabled    string            `json:"launched_cgo_enabled"`
	LaunchedGOOS          string            `json:"launched_goos"`
	LaunchedGOARCH        string            `json:"launched_goarch"`
	LaunchedTags          []string          `json:"launched_tags,omitempty"`
	BrokerEndpoint        string            `json:"broker_endpoint"`
	BrokerToken           string            `json:"broker_token"`
	Required              map[string]string `json:"required_observations"`
}

type receipt struct {
	SchemaVersion         int                     `json:"schema_version"`
	Nonce                 string                  `json:"nonce"`
	ID                    string                  `json:"id"`
	BuildProfile          string                  `json:"build_profile"`
	Method                string                  `json:"method"`
	Path                  string                  `json:"path"`
	RuntimeMode           string                  `json:"runtime_mode"`
	SubstrateID           string                  `json:"substrate_id"`
	SubstrateKind         string                  `json:"substrate_kind"`
	SubstrateIdentity     string                  `json:"substrate_identity"`
	ContractDigest        string                  `json:"contract_digest"`
	Verifier              string                  `json:"verifier"`
	Passed                bool                    `json:"passed"`
	Skipped               bool                    `json:"skipped"`
	Observations          map[string]string       `json:"observations"`
	ExecutionReceipt      json.RawMessage         `json:"execution_receipt"`
	RuntimeRunnerIdentity string                  `json:"runtime_runner_identity"`
	RuntimeRunnerImage    string                  `json:"runtime_runner_image,omitempty"`
	LaunchedProcess       *launchedProcessReceipt `json:"launched_process,omitempty"`
	MAC                   string                  `json:"mac"`
}

type launchedProcessReceipt struct {
	PID                     int      `json:"pid"`
	ProcessStartTicks       string   `json:"process_start_ticks"`
	ProcessMode             string   `json:"process_mode"`
	BinaryModulePath        string   `json:"binary_module_path"`
	BinaryPackage           string   `json:"binary_package"`
	BinaryCGOEnabled        string   `json:"binary_cgo_enabled"`
	BinaryGOOS              string   `json:"binary_goos"`
	BinaryGOARCH            string   `json:"binary_goarch"`
	BinaryTags              []string `json:"binary_tags,omitempty"`
	BinaryDigest            string   `json:"binary_digest"`
	BinaryDevice            string   `json:"binary_device"`
	BinaryInode             string   `json:"binary_inode"`
	InterpreterDigest       string   `json:"interpreter_digest,omitempty"`
	InterpreterDevice       string   `json:"interpreter_device,omitempty"`
	InterpreterInode        string   `json:"interpreter_inode,omitempty"`
	Address                 string   `json:"address"`
	ListenerInode           string   `json:"listener_inode"`
	AcceptedConnectionInode string   `json:"accepted_connection_inode"`
}

// Evidence is intentionally sealed by the unexported dodEvidence method. Code
// outside this package cannot implement it.
type Evidence interface {
	dodEvidence() evidencePayload
}

type evidencePayload struct {
	kind         string
	observations map[string]string
	execution    []byte
	err          error
}

type sealedEvidence struct{ payload evidencePayload }

func (e sealedEvidence) dodEvidence() evidencePayload { return e.payload }

// Session owns one exact expected route and one unique receipt filename.
type Session struct {
	t          *testing.T
	expect     expectation
	statusCode int
	body       []byte
	launched   *launchedProcessReceipt
	once       sync.Once
}

// ExternalSubstrate is a gate-configured, out-of-process emulator or verifier.
// Tests cannot choose its executable/image: those values come from the manifest
// expectation. The process must echo a nonce-bound READY record and later a final
// action receipt from the same PID.
type ExternalSubstrate struct {
	t                *testing.T
	expect           expectation
	cmd              *exec.Cmd
	decoder          *json.Decoder
	endpoint         string
	pid              int
	runtimeIdentity  string
	mu               sync.Mutex
	receiptRequested bool
	stopOnce         sync.Once
	stopErr          error
	waitOnce         sync.Once
	waitDone         chan struct{}
	waitErr          error
	receiptDoneOnce  sync.Once
	receiptDone      chan struct{}
	broker           bool
	brokerEndpoint   string
	brokerToken      string
}

type brokerStartRequest struct {
	Token      string            `json:"token"`
	ID         string            `json:"id"`
	RuntimeEnv map[string]string `json:"runtime_env,omitempty"`
}

type brokerStartResponse struct {
	Endpoint string `json:"endpoint"`
	PID      int    `json:"pid"`
}

type brokerStopRequest struct {
	Token string `json:"token"`
	ID    string `json:"id"`
}

type brokerStopResponse struct {
	Receipt json.RawMessage `json:"receipt"`
}

type substrateReady struct {
	SchemaVersion   int    `json:"schema_version"`
	Challenge       string `json:"challenge"`
	EntryID         string `json:"entry_id"`
	Identity        string `json:"identity"`
	ContractDigest  string `json:"contract_digest"`
	PID             int    `json:"pid"`
	Ready           bool   `json:"ready"`
	Endpoint        string `json:"endpoint"`
	RuntimeIdentity string `json:"runtime_identity,omitempty"`
}

// StartCommand launches the exact digest-bound command from the manifest.
func StartCommand(t *testing.T, id string) *ExternalSubstrate {
	t.Helper()
	expected := expectationFor(t, id)
	if expected.Execution != "command" && expected.Execution != "remote" {
		t.Fatalf("DOD-CENSUS: %s substrate execution is %q, not command/remote", id, expected.Execution)
	}
	if expected.Repo == "" || len(expected.Command) == 0 {
		t.Fatalf("DOD-CENSUS: %s command expectation is incomplete", id)
	}
	if expected.BrokerEndpoint != "" && expected.BrokerToken != "" {
		return startBrokerExternal(t, expected)
	}
	commandPath := filepath.Join(expected.Repo, filepath.FromSlash(expected.Command[0]))
	cmd := exec.Command(commandPath, expected.Command[1:]...) // #nosec G204 -- developer tool running fixed toolchain commands over the repo (CWE-78)
	cmd.Dir = expected.Repo
	cmd.Env = substrateEnvironment(expected)
	return startExternal(t, expected, cmd, true)
}

// OnlyExpectation returns the one selected ID when a parent gate gives a shared
// runtime test exactly one expectation, and returns empty when it selected the
// full group. The envelope still fails closed when missing or malformed.
func OnlyExpectation(t *testing.T) string {
	t.Helper()
	expected := loadExpectations(t)
	if len(expected) == 1 {
		return expected[0].ID
	}
	return ""
}

// StartContainer launches the exact digest-pinned image from the manifest.
func StartContainer(t *testing.T, id string) *ExternalSubstrate {
	t.Helper()
	expected := expectationFor(t, id)
	if expected.Execution != "container" || expected.Image == "" {
		t.Fatalf("DOD-CENSUS: %s container expectation is incomplete", id)
	}
	if expected.BrokerEndpoint != "" && expected.BrokerToken != "" {
		return startBrokerExternal(t, expected)
	}
	args := []string{"run", "--rm", "-i"}
	for _, item := range substrateEnvironmentPairs(expected) {
		args = append(args, "-e", item)
	}
	args = append(args, expected.Image)
	cmd := exec.Command("docker", args...)
	cmd.Dir = expected.Repo
	cmd.Env = cleanEnvironment(os.Environ())
	return startExternal(t, expected, cmd, false)
}

func startBrokerExternal(t *testing.T, expected expectation) *ExternalSubstrate {
	t.Helper()
	dynamic := map[string]string{}
	for _, name := range brokerDynamicEnvironmentNames(expected) {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			dynamic[name] = value
		}
	}
	payload := brokerStartRequest{Token: expected.BrokerToken, ID: expected.ID, RuntimeEnv: dynamic}
	var ready brokerStartResponse
	brokerRequest(t, expected.BrokerEndpoint+"/start", payload, &ready)
	parsed, err := url.Parse(ready.Endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || ready.PID <= 0 {
		t.Fatal("DOD-CENSUS: parent broker returned invalid substrate READY")
	}
	external := &ExternalSubstrate{
		t: t, expect: expected, endpoint: ready.Endpoint, pid: ready.PID,
		broker: true, brokerEndpoint: expected.BrokerEndpoint, brokerToken: expected.BrokerToken,
		receiptDone: make(chan struct{}), waitDone: make(chan struct{}),
	}
	t.Cleanup(external.cleanup)
	return external
}

func brokerDynamicEnvironmentNames(expected expectation) []string {
	if expected.SubstrateID == "managed_key_custody" {
		return []string{"TRSTCTL_HSM_PROOF_IMAGE", "TRSTCTL_HSM_PROOF_NETWORK"}
	}
	switch expected.ID {
	case "external_ca.adcs":
		return []string{
			"TRSTCTL_ADCS_TLS_SERVER_CERT_FILE",
			"TRSTCTL_ADCS_TLS_SERVER_KEY_FILE",
		}
	case "external_ca.entrust":
		return []string{
			"TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE",
			"TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE",
			"TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE",
		}
	case "code_signing.default":
		return []string{"TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE"}
	default:
		return nil
	}
}

func brokerRequest(t *testing.T, endpoint string, requestValue, responseValue any) {
	t.Helper()
	encoded, err := json.Marshal(requestValue)
	if err != nil {
		t.Fatalf("DOD-CENSUS: encode parent broker request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("DOD-CENSUS: create parent broker request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 40 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("DOD-CENSUS: parent broker request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatalf("DOD-CENSUS: parent broker status=%d body=%s", response.StatusCode, body)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxEvidenceBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(responseValue); err != nil {
		t.Fatalf("DOD-CENSUS: decode parent broker response: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("DOD-CENSUS: parent broker response has trailing JSON")
	}
}

func startExternal(t *testing.T, expected expectation, cmd *exec.Cmd, requireHostPID bool) *ExternalSubstrate {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("DOD-CENSUS: substrate stdout: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("DOD-CENSUS: start substrate: %v", err)
	}
	decoder := json.NewDecoder(bufio.NewReader(stdout))
	readyChannel := make(chan struct {
		value substrateReady
		err   error
	}, 1)
	go func() {
		var ready substrateReady
		err := decoder.Decode(&ready)
		readyChannel <- struct {
			value substrateReady
			err   error
		}{ready, err}
	}()
	var ready substrateReady
	select {
	case result := <-readyChannel:
		if result.err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("DOD-CENSUS: decode substrate READY: %v; stderr=%s", result.err, stderr.String())
		}
		ready = result.value
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("DOD-CENSUS: substrate did not emit READY within 10 seconds; stderr=%s", stderr.String())
	}
	parsedEndpoint, endpointErr := url.Parse(ready.Endpoint)
	if ready.SchemaVersion != 1 || ready.Challenge != expected.Nonce || ready.EntryID != expected.ID || ready.Identity != expected.SubstrateIdentity || ready.ContractDigest != expected.ContractDigest || !ready.Ready || ready.PID <= 0 || endpointErr != nil || (parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") || parsedEndpoint.Host == "" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("DOD-CENSUS: substrate READY failed nonce/identity/contract/PID/endpoint validation")
	}
	if !runtimeIdentityMatches(expected.SubstrateID, ready.RuntimeIdentity) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("DOD-CENSUS: substrate READY has missing, mutable, or unexpected runtime image identity")
	}
	if requireHostPID && ready.PID != cmd.Process.Pid {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("DOD-CENSUS: READY pid %d is not launched command pid %d", ready.PID, cmd.Process.Pid)
	}
	external := &ExternalSubstrate{
		t: t, expect: expected, cmd: cmd, decoder: decoder, endpoint: ready.Endpoint, pid: ready.PID,
		runtimeIdentity: ready.RuntimeIdentity,
		waitDone:        make(chan struct{}), receiptDone: make(chan struct{}),
	}
	// Register immediately after READY validation. Any later assertion failure
	// (including t.Fatal before StopAndReceipt) gives the substrate a bounded
	// SIGINT grace period so its own container/process cleanup runs, then kills
	// and reaps it as a fail-safe.
	t.Cleanup(external.cleanup)
	return external
}

// Endpoint is the validated address emitted by the external READY record.
func (s *ExternalSubstrate) Endpoint() string { return s.endpoint }

// StopAndReceipt terminates the same process and returns its final nonce-bound
// action receipt. Session.Complete validates and hashes these bytes.
func (s *ExternalSubstrate) StopAndReceipt() []byte {
	s.t.Helper()
	s.mu.Lock()
	if s.receiptRequested {
		s.mu.Unlock()
		s.t.Fatal("DOD-CENSUS: substrate stopped more than once")
	}
	s.receiptRequested = true
	s.mu.Unlock()
	defer s.finishReceipt()
	if s.broker {
		var stopped brokerStopResponse
		brokerRequest(s.t, s.brokerEndpoint+"/stop", brokerStopRequest{Token: s.brokerToken, ID: s.expect.ID}, &stopped)
		if len(stopped.Receipt) == 0 || len(stopped.Receipt) > maxEvidenceBody {
			s.t.Fatal("DOD-CENSUS: parent broker returned an invalid receipt size")
		}
		return append([]byte(nil), stopped.Receipt...)
	}
	if err := s.signalStop(); err != nil {
		s.t.Fatalf("DOD-CENSUS: stop substrate: %v", err)
	}
	resultChannel := make(chan struct {
		value substrateExecutionReceipt
		err   error
	}, 1)
	go func() {
		var receipt substrateExecutionReceipt
		err := s.decoder.Decode(&receipt)
		resultChannel <- struct {
			value substrateExecutionReceipt
			err   error
		}{receipt, err}
	}()
	var receipt substrateExecutionReceipt
	select {
	case result := <-resultChannel:
		if result.err != nil {
			s.t.Fatalf("DOD-CENSUS: decode final substrate receipt: %v", result.err)
		}
		receipt = result.value
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		_, _ = s.waitProcess(2 * time.Second)
		s.t.Fatal("DOD-CENSUS: substrate did not emit final receipt within 10 seconds")
	}
	waitErr, reaped := s.waitProcess(10 * time.Second)
	if !reaped {
		_ = s.cmd.Process.Kill()
		_, _ = s.waitProcess(2 * time.Second)
		s.t.Fatal("DOD-CENSUS: substrate did not exit within 10 seconds after its final receipt")
	}
	if waitErr != nil {
		if !receipt.Passed {
			s.t.Fatalf("DOD-CENSUS: substrate %s reported passed=false and exited unsuccessfully: %v", receipt.EntryID, waitErr)
		}
		s.t.Fatalf("DOD-CENSUS: substrate exit: %v", waitErr)
	}
	if receipt.PID != s.pid {
		s.t.Fatalf("DOD-CENSUS: final receipt pid %d differs from READY pid %d", receipt.PID, s.pid)
	}
	if receipt.RuntimeIdentity != s.runtimeIdentity || !runtimeIdentityMatches(s.expect.SubstrateID, receipt.RuntimeIdentity) {
		s.t.Fatal("DOD-CENSUS: final receipt runtime image identity differs from READY or is mutable")
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		s.t.Fatalf("DOD-CENSUS: encode final receipt: %v", err)
	}
	return raw
}

func (s *ExternalSubstrate) signalStop() error {
	s.stopOnce.Do(func() {
		s.stopErr = s.cmd.Process.Signal(os.Interrupt)
	})
	return s.stopErr
}

func (s *ExternalSubstrate) waitProcess(timeout time.Duration) (error, bool) {
	s.waitOnce.Do(func() {
		go func() {
			err := s.cmd.Wait()
			s.mu.Lock()
			s.waitErr = err
			s.mu.Unlock()
			close(s.waitDone)
		}()
	})
	select {
	case <-s.waitDone:
		s.mu.Lock()
		err := s.waitErr
		s.mu.Unlock()
		return err, true
	case <-time.After(timeout):
		return nil, false
	}
}

func (s *ExternalSubstrate) finishReceipt() {
	s.receiptDoneOnce.Do(func() { close(s.receiptDone) })
}

func (s *ExternalSubstrate) cleanup() {
	if s.broker {
		s.mu.Lock()
		requested := s.receiptRequested
		if !requested {
			s.receiptRequested = true
		}
		s.mu.Unlock()
		if !requested {
			request := brokerStopRequest{Token: s.brokerToken, ID: s.expect.ID}
			encoded, _ := json.Marshal(request)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			httpRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.brokerEndpoint+"/stop", bytes.NewReader(encoded))
			httpRequest.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 3 * time.Second}
			response, err := client.Do(httpRequest)
			if err == nil {
				_ = response.Body.Close()
			}
		}
		return
	}
	s.mu.Lock()
	receiptRequested := s.receiptRequested
	s.mu.Unlock()
	if receiptRequested {
		select {
		case <-s.receiptDone:
		case <-time.After(12 * time.Second):
			// A concurrent/aborted receipt read exceeded its own ten-second
			// bound. Fall through to the kill-and-reap safety net.
		}
	}
	select {
	case <-s.waitDone:
		return
	default:
	}
	_ = s.signalStop()
	if _, reaped := s.waitProcess(10 * time.Second); reaped {
		return
	}
	_ = s.cmd.Process.Kill()
	_, _ = s.waitProcess(5 * time.Second)
}

func expectationFor(t *testing.T, id string) expectation {
	t.Helper()
	expectations := loadExpectations(t)
	var found *expectation
	for index := range expectations {
		if expectations[index].ID == id {
			if found != nil {
				t.Fatalf("DOD-CENSUS: duplicate expectation for %s", id)
			}
			found = &expectations[index]
		}
	}
	if found == nil {
		t.Fatalf("DOD-CENSUS: no gate-issued expectation for %s", id)
	}
	return *found
}

func substrateEnvironment(expected expectation) []string {
	return append(cleanEnvironment(os.Environ()), substrateEnvironmentPairs(expected)...)
}

func substrateEnvironmentPairs(expected expectation) []string {
	return []string{
		"TRSTCTL_DOD_CHALLENGE=" + expected.Nonce,
		"TRSTCTL_DOD_ENTRY_ID=" + expected.ID,
		"TRSTCTL_DOD_SUBSTRATE_IDENTITY=" + expected.SubstrateIdentity,
		"TRSTCTL_DOD_CONTRACT_DIGEST=" + expected.ContractDigest,
	}
}

func cleanEnvironment(base []string) []string {
	out := make([]string, 0, len(base))
	for _, item := range base {
		if !strings.HasPrefix(item, "TRSTCTL_DOD_") {
			out = append(out, item)
		}
	}
	return out
}

// Start executes the actual assembled handler. The id, route, profile,
// substrate, nonce, and receipt filename come from the census process's isolated
// environment; the test cannot substitute those values.
func Start(t *testing.T, id string, handler http.Handler, request *http.Request) *Session {
	t.Helper()
	if handler == nil || request == nil {
		t.Fatalf("DOD-CENSUS: %s has nil assembled handler/request", id)
	}
	expectations := loadExpectations(t)
	var expected *expectation
	for index := range expectations {
		if expectations[index].ID == id {
			if expected != nil {
				t.Fatalf("DOD-CENSUS: duplicate expectation for %s", id)
			}
			expected = &expectations[index]
		}
	}
	if expected == nil {
		t.Fatalf("DOD-CENSUS: no gate-issued expectation for %s", id)
	}
	if expected.RuntimeMode != "assembled-handler" {
		t.Fatalf("DOD-CENSUS: %s launched-binary expectation cannot use an in-process Handler", id)
	}
	if expected.SchemaVersion != 1 || expected.Nonce == "" || expected.BuildProfile == "" || expected.RuntimeMode == "" || expected.SubstrateID == "" || expected.SubstrateIdentity == "" || expected.ContractDigest == "" || expected.Verifier == "" || expected.ReceiptFile == "" || expected.EvidenceFile == "" || expected.RuntimeRunnerIdentity == "" || !validSHA256Digest(expected.RuntimeRunnerImage) || !runtimeProfileExpectationComplete(*expected) || expected.BrokerEndpoint == "" || expected.BrokerToken == "" {
		t.Fatalf("DOD-CENSUS: expectation for %s is incomplete", id)
	}
	if request.Method != expected.Method || request.URL == nil || request.URL.Path != expected.Path {
		t.Fatalf("DOD-CENSUS: request %s %s does not match gate route %s %s", request.Method, request.URL.Path, expected.Method, expected.Path)
	}
	capture := &responseCapture{header: make(http.Header), status: http.StatusOK}
	handler.ServeHTTP(capture, request)
	if err := responseIsServed(capture.status, capture.body.Bytes()); err != nil {
		t.Fatalf("DOD-CENSUS: %s assembled route is not served: %v body=%q", id, err, boundedResponseDiagnostic(capture.body.Bytes()))
	}
	return &Session{t: t, expect: *expected, statusCode: capture.status, body: append([]byte(nil), capture.body.Bytes()...)}
}

func runtimeProfileExpectationComplete(expected expectation) bool {
	return strings.HasPrefix(expected.RuntimeTestPackage, "./") && !strings.Contains(expected.RuntimeTestPackage, "..") &&
		(expected.RuntimeCGOEnabled == "0" || expected.RuntimeCGOEnabled == "1") && expected.RuntimeGOOS != "" && expected.RuntimeGOARCH != ""
}

// LaunchedResponseStatusCode exposes only the status needed to attach a
// subsystem-specific failure diagnostic before StartResponse fails the proof.
// It does not expose or construct a response, witness, session, or receipt;
// successful proofs must still pass through StartResponse and Complete.
func LaunchedResponseStatusCode(t *testing.T, id string, launched *launchedResponse) int {
	t.Helper()
	if launched == nil || launched.response == nil || launched.id != id {
		t.Fatalf("DOD-CENSUS: %s has no matching gate-owned launched response", id)
	}
	return launched.response.StatusCode
}

// StartResponse accepts only the opaque result of ShippedProcess.Do. The result
// binds the HTTP bytes to the gate-built cmd/trstctl executable and to a LISTEN
// socket owned by that exact live PID.
func StartResponse(t *testing.T, id string, launched *launchedResponse) *Session {
	t.Helper()
	if launched == nil || launched.response == nil || launched.id != id {
		t.Fatalf("DOD-CENSUS: %s has no matching gate-owned launched response", id)
	}
	response := launched.response
	if response == nil || response.Request == nil || response.Request.URL == nil {
		t.Fatalf("DOD-CENSUS: %s has nil launched-binary response/request", id)
	}
	expected := expectationFor(t, id)
	if expected.RuntimeMode != "launched-binary" || launched.witness.PID <= 0 ||
		launched.witness.BinaryModulePath != expected.LaunchedModulePath ||
		launched.witness.BinaryPackage != expected.LaunchedBinaryPackage ||
		launched.witness.BinaryCGOEnabled != expected.LaunchedCGOEnabled ||
		launched.witness.BinaryGOOS != expected.LaunchedGOOS || launched.witness.BinaryGOARCH != expected.LaunchedGOARCH ||
		!slices.Equal(launched.witness.BinaryTags, expected.LaunchedTags) ||
		!strings.HasPrefix(launched.witness.BinaryDigest, "sha256:") ||
		launched.witness.Address != response.Request.URL.Host ||
		!validLaunchedWitnessShape(launched.witness) {
		t.Fatalf("DOD-CENSUS: %s launched process witness does not match gate expectation/response", id)
	}
	if response.Request.Method != expected.Method || response.Request.URL.Path != expected.Path {
		t.Fatalf("DOD-CENSUS: launched response route %s %s does not match %s %s", response.Request.Method, response.Request.URL.Path, expected.Method, expected.Path)
	}
	var body []byte
	if response.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(response.Body, maxEvidenceBody+1))
		if err != nil {
			t.Fatalf("DOD-CENSUS: read launched response: %v", err)
		}
		_ = response.Body.Close()
		response.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := responseIsServed(response.StatusCode, body); err != nil {
		t.Fatalf("DOD-CENSUS: %s launched route is not served: %v body=%q", id, err, boundedResponseDiagnostic(body))
	}
	witness := launched.witness
	return &Session{
		t: t, expect: expected, statusCode: response.StatusCode, body: append([]byte(nil), body...),
		launched: &witness,
	}
}

func boundedResponseDiagnostic(body []byte) string {
	type problem struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Code   string `json:"code"`
	}
	var value problem
	if json.Unmarshal(body, &value) != nil || (value.Type == "" && value.Title == "" && value.Detail == "" && value.Code == "") {
		return fmt.Sprintf("non-problem body size=%d sha256:%s", len(body), internalcrypto.SHA256Hex(body))
	}
	sanitize := func(input string) string {
		const limit = 512
		if len(input) > limit {
			input = input[:limit]
		}
		return strings.Map(func(character rune) rune {
			switch {
			case character == '\n' || character == '\r' || character == '\t':
				return ' '
			case character < 0x20 || character == 0x7f:
				return -1
			default:
				return character
			}
		}, input)
	}
	return fmt.Sprintf("type=%q title=%q status=%d code=%q detail=%q",
		sanitize(value.Type), sanitize(value.Title), value.Status, sanitize(value.Code), sanitize(value.Detail))
}

func validLaunchedWitnessShape(witness launchedProcessReceipt) bool {
	positiveDecimal := func(value string) bool {
		parsed, err := strconv.ParseUint(value, 10, 64)
		return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
	}
	if witness.BinaryModulePath == "" || witness.BinaryPackage == "" ||
		(witness.BinaryCGOEnabled != "0" && witness.BinaryCGOEnabled != "1") || witness.BinaryGOOS == "" || witness.BinaryGOARCH == "" ||
		!positiveDecimal(witness.ProcessStartTicks) || !positiveDecimal(witness.BinaryDevice) || !positiveDecimal(witness.BinaryInode) ||
		!positiveDecimal(witness.ListenerInode) || !positiveDecimal(witness.AcceptedConnectionInode) ||
		witness.ListenerInode == witness.AcceptedConnectionInode || !validSHA256Digest(witness.BinaryDigest) {
		return false
	}
	switch witness.ProcessMode {
	case processModeNative:
		return witness.InterpreterDigest == "" && witness.InterpreterDevice == "" && witness.InterpreterInode == ""
	case processModeBinfmt:
		return validSHA256Digest(witness.InterpreterDigest) && positiveDecimal(witness.InterpreterDevice) && positiveDecimal(witness.InterpreterInode)
	default:
		return false
	}
}

func loadExpectations(t *testing.T) []expectation {
	t.Helper()
	raw := os.Getenv("TRSTCTL_DOD_EXPECTATIONS")
	if raw == "" {
		t.Fatal("DOD-CENSUS: gate-issued TRSTCTL_DOD_EXPECTATIONS is missing")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var expectations []expectation
	if err := decoder.Decode(&expectations); err != nil {
		t.Fatalf("DOD-CENSUS: decode gate expectations: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("DOD-CENSUS: gate expectations contain trailing JSON")
	}
	return expectations
}

// StatusCode and ResponseBody let a domain test add assertions without replacing
// the response used by the gate.
func (s *Session) StatusCode() int { return s.statusCode }

func (s *Session) ResponseBody() []byte { return append([]byte(nil), s.body...) }

// Complete accepts only sealed evidence and atomically creates the unique JSON
// receipt. A second completion or a stale/pre-existing file fails closed.
func (s *Session) Complete(evidence Evidence) {
	s.t.Helper()
	if evidence == nil {
		s.t.Fatal("DOD-CENSUS: nil sealed evidence")
	}
	payload := evidence.dodEvidence()
	if payload.err != nil {
		s.t.Fatalf("DOD-CENSUS: invalid %s evidence: %v", payload.kind, payload.err)
	}
	if payload.kind != s.expect.Verifier {
		s.t.Fatalf("DOD-CENSUS: evidence verifier %q does not match substrate verifier %q", payload.kind, s.expect.Verifier)
	}
	executionDigest, err := s.validateExecutionReceipt(payload.execution)
	if err != nil {
		s.t.Fatalf("DOD-CENSUS: external execution receipt: %v", err)
	}
	payload.observations["execution_receipt_digest"] = executionDigest
	if payload.kind == "notification" && payload.observations["contract_digest"] != s.expect.ContractDigest {
		s.t.Fatalf("DOD-CENSUS: notification probe did not exercise the pinned substrate contract")
	}
	for name, want := range s.expect.Required {
		if got, exists := payload.observations[name]; exists && got != want {
			s.t.Fatalf("DOD-CENSUS: sealed evidence observation %s does not match gate-issued value", name)
		}
		payload.observations[name] = want
	}
	completed := false
	s.once.Do(func() {
		completed = true
		r := receipt{
			SchemaVersion: 1, Nonce: s.expect.Nonce, ID: s.expect.ID,
			BuildProfile: s.expect.BuildProfile, Method: s.expect.Method, Path: s.expect.Path, RuntimeMode: s.expect.RuntimeMode,
			SubstrateID: s.expect.SubstrateID, SubstrateKind: s.expect.SubstrateKind,
			SubstrateIdentity: s.expect.SubstrateIdentity, ContractDigest: s.expect.ContractDigest,
			Verifier: s.expect.Verifier, Passed: true, Skipped: false,
			Observations: payload.observations, ExecutionReceipt: append(json.RawMessage(nil), payload.execution...),
			RuntimeRunnerIdentity: s.expect.RuntimeRunnerIdentity, RuntimeRunnerImage: s.expect.RuntimeRunnerImage,
			LaunchedProcess: s.launched,
		}
		file, err := os.OpenFile(s.expect.EvidenceFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			s.t.Fatalf("DOD-CENSUS: create unique unsigned evidence envelope: %v", err)
		}
		encoder := json.NewEncoder(file)
		if err := encoder.Encode(r); err != nil {
			_ = file.Close()
			s.t.Fatalf("DOD-CENSUS: encode unsigned evidence envelope: %v", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			s.t.Fatalf("DOD-CENSUS: sync receipt: %v", err)
		}
		if err := file.Close(); err != nil {
			s.t.Fatalf("DOD-CENSUS: close receipt: %v", err)
		}
	})
	if !completed {
		s.t.Fatal("DOD-CENSUS: Session.Complete called more than once")
	}
}

type substrateExecutionReceipt struct {
	SchemaVersion   int    `json:"schema_version"`
	Challenge       string `json:"challenge"`
	EntryID         string `json:"entry_id"`
	Identity        string `json:"identity"`
	ContractDigest  string `json:"contract_digest"`
	PID             int    `json:"pid"`
	Passed          bool   `json:"passed"`
	RuntimeIdentity string `json:"runtime_identity,omitempty"`
}

func (s *Session) validateExecutionReceipt(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > maxEvidenceBody {
		return "", fmt.Errorf("receipt size %d is invalid", len(raw))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt substrateExecutionReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", fmt.Errorf("trailing data")
	}
	if receipt.SchemaVersion != 1 || receipt.Challenge != s.expect.Nonce || receipt.EntryID != s.expect.ID || receipt.Identity != s.expect.SubstrateIdentity || receipt.ContractDigest != s.expect.ContractDigest || receipt.PID <= 0 || receipt.PID == os.Getpid() || !receipt.Passed {
		return "", fmt.Errorf("nonce/identity/contract/PID/pass mismatch")
	}
	if !runtimeIdentityMatches(s.expect.SubstrateID, receipt.RuntimeIdentity) {
		return "", fmt.Errorf("runtime image identity is missing, mutable, or unexpected")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	return "sha256:" + internalcrypto.SHA256Hex(canonical), nil
}

func runtimeIdentityMatches(substrateID, value string) bool {
	if substrateID != "managed_key_custody" {
		return value == ""
	}
	algorithm, digest, ok := strings.Cut(value, ":")
	decoded, err := hex.DecodeString(digest)
	return ok && algorithm == "sha256" && err == nil && len(decoded) == 32 && digest == strings.ToLower(digest)
}

type responseCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *responseCapture) Header() http.Header { return r.header }

func (r *responseCapture) WriteHeader(status int) { r.status = status }

func (r *responseCapture) Write(body []byte) (int, error) {
	if r.body.Len()+len(body) > maxEvidenceBody+1 {
		return 0, fmt.Errorf("response evidence exceeds %d bytes", maxEvidenceBody)
	}
	return r.body.Write(body)
}

func responseIsServed(status int, body []byte) error {
	if status < http.StatusOK || status >= http.StatusBadRequest {
		return fmt.Errorf("non-success HTTP status %d", status)
	}
	if len(body) > maxEvidenceBody {
		return fmt.Errorf("response evidence exceeds %d bytes", maxEvidenceBody)
	}
	lower := bytes.ToLower(body)
	for _, fragment := range sentinelFragments {
		if bytes.Contains(lower, fragment) {
			return fmt.Errorf("sentinel response contains %q", fragment)
		}
	}
	return nil
}

// ExternalWriteProbe proves bytes crossed an external boundary and were read
// back from that boundary. ExecutionReceipt is the out-of-process emulator or
// real-system transcript, not a test log line.
type ExternalWriteProbe struct {
	Destination      []byte
	Written          []byte
	ReadBack         []byte
	ExecutionReceipt []byte
}

func ExternalWrite(probe ExternalWriteProbe) Evidence {
	if err := requireBytes("destination", probe.Destination, "written", probe.Written, "readback", probe.ReadBack, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("external-write", err)
	}
	if !bytes.Equal(probe.Written, probe.ReadBack) {
		return invalidEvidence("external-write", fmt.Errorf("external readback differs from written bytes"))
	}
	return observedExecution("external-write", probe.ExecutionReceipt, map[string][]byte{
		"destination_digest": probe.Destination, "write_digest": probe.Written,
		"readback_digest": probe.ReadBack,
	})
}

type CredentialLifecycleProbe struct {
	Issued            []byte
	Rotated           []byte
	RevocationReceipt []byte
	Exported          []byte
	ExecutionReceipt  []byte
}

func CredentialLifecycle(probe CredentialLifecycleProbe) Evidence {
	if err := requireBytes("issued", probe.Issued, "rotated", probe.Rotated, "revocation receipt", probe.RevocationReceipt, "export", probe.Exported, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("credential-lifecycle", err)
	}
	if bytes.Equal(probe.Issued, probe.Rotated) {
		return invalidEvidence("credential-lifecycle", fmt.Errorf("rotation did not change the credential"))
	}
	return observedExecution("credential-lifecycle", probe.ExecutionReceipt, map[string][]byte{
		"issued_digest": probe.Issued, "rotated_digest": probe.Rotated,
		"revocation_receipt_digest": probe.RevocationReceipt, "export_digest": probe.Exported,
	})
}

type CAIssueChainProbe struct {
	Leaf             []byte
	Chain            []byte
	Verification     []byte
	ExecutionReceipt []byte
}

func CAIssueChain(probe CAIssueChainProbe) Evidence {
	if err := requireBytes("leaf", probe.Leaf, "chain", probe.Chain, "verification", probe.Verification, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("ca-issue-chain", err)
	}
	return observedExecution("ca-issue-chain", probe.ExecutionReceipt, map[string][]byte{
		"leaf_digest": probe.Leaf, "chain_digest": probe.Chain,
		"verification_digest": probe.Verification,
	})
}

type TLSDeployProbe struct {
	Deployed         []byte
	Config           []byte
	ReloadReceipt    []byte
	ReadBack         []byte
	ExecutionReceipt []byte
}

func TLSDeploy(probe TLSDeployProbe) Evidence {
	if err := requireBytes("deployed", probe.Deployed, "config", probe.Config, "reload receipt", probe.ReloadReceipt, "readback", probe.ReadBack, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("tls-deploy", err)
	}
	if !bytes.Equal(probe.Deployed, probe.ReadBack) {
		return invalidEvidence("tls-deploy", fmt.Errorf("TLS readback differs from deployed certificate"))
	}
	return observedExecution("tls-deploy", probe.ExecutionReceipt, map[string][]byte{
		"deployed_digest": probe.Deployed, "config_digest": probe.Config,
		"reload_receipt_digest": probe.ReloadReceipt, "readback_digest": probe.ReadBack,
	})
}

type NotificationProbe struct {
	Contract         []byte
	Acceptance       []byte
	Delivery         []byte
	ExecutionReceipt []byte
}

func Notification(probe NotificationProbe) Evidence {
	if err := requireBytes("contract", probe.Contract, "acceptance", probe.Acceptance, "delivery", probe.Delivery, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("notification", err)
	}
	return observedExecution("notification", probe.ExecutionReceipt, map[string][]byte{
		"contract_digest": probe.Contract, "acceptance_digest": probe.Acceptance,
		"delivery_digest": probe.Delivery,
	})
}

type HSMSignProbe struct {
	Signature        []byte
	PublicKey        []byte
	ExportDenial     []byte
	ExecutionReceipt []byte
}

func HSMSign(probe HSMSignProbe) Evidence {
	if err := requireBytes("signature", probe.Signature, "public key", probe.PublicKey, "export denial", probe.ExportDenial, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("hsm-sign", err)
	}
	lower := bytes.ToLower(probe.ExportDenial)
	if !bytes.Contains(lower, []byte("denied")) && !bytes.Contains(lower, []byte("non-export")) {
		return invalidEvidence("hsm-sign", fmt.Errorf("HSM probe did not observe an explicit non-export denial"))
	}
	return observedExecution("hsm-sign", probe.ExecutionReceipt, map[string][]byte{
		"signature_digest": probe.Signature, "public_key_digest": probe.PublicKey,
		"export_denial_digest": probe.ExportDenial,
	})
}

type IndependentInteropProbe struct {
	ClientIdentity      []byte
	Transcript          []byte
	IndependentVerifier []byte
	ExecutionReceipt    []byte
}

func IndependentInterop(probe IndependentInteropProbe) Evidence {
	if err := requireBytes("client identity", probe.ClientIdentity, "transcript", probe.Transcript, "independent verifier", probe.IndependentVerifier, "execution receipt", probe.ExecutionReceipt); err != nil {
		return invalidEvidence("interop", err)
	}
	return observedExecution("interop", probe.ExecutionReceipt, map[string][]byte{
		"client_identity_digest": probe.ClientIdentity, "transcript_digest": probe.Transcript,
		"independent_verifier_digest": probe.IndependentVerifier,
	})
}

func requireBytes(items ...any) error {
	for index := 0; index+1 < len(items); index += 2 {
		name, _ := items[index].(string)
		value, _ := items[index+1].([]byte)
		if len(value) < 16 {
			return fmt.Errorf("%s observation is only %d bytes; literal/sentinel bytes are not domain evidence", name, len(value))
		}
	}
	return nil
}

func observed(kind string, raw map[string][]byte) Evidence {
	observations := make(map[string]string, len(raw))
	for name, value := range raw {
		observations[name] = "sha256:" + internalcrypto.SHA256Hex(value)
	}
	return sealedEvidence{payload: evidencePayload{kind: kind, observations: observations}}
}

func observedExecution(kind string, execution []byte, raw map[string][]byte) Evidence {
	sealed := observed(kind, raw).(sealedEvidence)
	sealed.payload.execution = append([]byte(nil), execution...)
	return sealed
}

func invalidEvidence(kind string, err error) Evidence {
	return sealedEvidence{payload: evidencePayload{kind: kind, err: err}}
}
