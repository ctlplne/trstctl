// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

var dockerObjectNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

const maxBrokerDynamicFileBytes = 1 << 20

var brokerSecretFileInputs = map[string]bool{
	"TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE":    true,
	"TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE": true,
}

type substrateBroker struct {
	repo       string
	receiptDir string
	token      string
	crossHost  bool
	listener   net.Listener
	server     *http.Server
	mu         sync.Mutex
	expect     map[string]runtimeExpectation
	sessions   map[string]*brokerSubstrate
	receipts   map[string][]byte
	endpoint   string
}

type brokerSubstrate struct {
	expected runtimeExpectation
	cmd      *exec.Cmd
	decoder  *json.Decoder
	pid      int
	stderr   *bytes.Buffer
	stopped  bool
}

type brokerReady struct {
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

type brokerReceipt struct {
	SchemaVersion   int    `json:"schema_version"`
	Challenge       string `json:"challenge"`
	EntryID         string `json:"entry_id"`
	Identity        string `json:"identity"`
	ContractDigest  string `json:"contract_digest"`
	PID             int    `json:"pid"`
	Passed          bool   `json:"passed"`
	RuntimeIdentity string `json:"runtime_identity,omitempty"`
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

func startSubstrateBroker(repo, receiptDir string, crossHost bool) (*substrateBroker, error) {
	tokenBytes, err := internalRandomBytes(32)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for parent-owned substrate broker: %w", err)
	}
	broker := &substrateBroker{
		repo: repo, receiptDir: receiptDir, token: fmt.Sprintf("%x", tokenBytes), crossHost: crossHost,
		listener: listener, expect: map[string]runtimeExpectation{}, sessions: map[string]*brokerSubstrate{}, receipts: map[string][]byte{},
	}
	broker.endpoint = fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", broker.handleHealth)
	mux.HandleFunc("POST /start", broker.handleStart)
	mux.HandleFunc("POST /stop", broker.handleStop)
	broker.server = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = broker.server.Serve(listener) }()
	return broker, nil
}

func (b *substrateBroker) handleHealth(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+b.token {
		http.Error(response, "unauthorized substrate broker health probe", http.StatusUnauthorized)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func internalRandomBytes(size int) ([]byte, error) {
	value, err := internalcrypto.RandomBytes(size)
	if err != nil {
		return nil, fmt.Errorf("generate substrate broker token: %w", err)
	}
	return value, nil
}

func (b *substrateBroker) configure(expectations map[string]runtimeExpectation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, expected := range expectations {
		b.expect[id] = expected
	}
}

func (b *substrateBroker) clientEndpoint() string {
	if b.listener == nil {
		return b.endpoint
	}
	port := b.listener.Addr().(*net.TCPAddr).Port
	if b.crossHost {
		return fmt.Sprintf("http://host.docker.internal:%d", port)
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func newInMemorySubstrateBroker(repo, receiptDir string) *substrateBroker {
	return &substrateBroker{
		repo: repo, receiptDir: receiptDir, token: strings.Repeat("f", 64), endpoint: "http://127.0.0.1:1",
		expect: map[string]runtimeExpectation{}, sessions: map[string]*brokerSubstrate{}, receipts: map[string][]byte{},
	}
}

func (b *substrateBroker) handleStart(response http.ResponseWriter, request *http.Request) {
	var body brokerStartRequest
	if !decodeBrokerJSON(response, request, &body) {
		return
	}
	b.mu.Lock()
	expected, ok := b.expect[body.ID]
	_, alreadyStarted := b.sessions[body.ID]
	b.mu.Unlock()
	if !ok || body.Token != b.token || alreadyStarted {
		http.Error(response, "unauthorized or duplicate substrate start", http.StatusConflict)
		return
	}
	session, ready, err := b.launch(request.Context(), expected, body.RuntimeEnv)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadGateway)
		return
	}
	b.mu.Lock()
	b.sessions[body.ID] = session
	b.mu.Unlock()
	endpoint := ready.Endpoint
	if b.crossHost {
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed.Port() == "" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost") {
			_ = session.cmd.Process.Kill()
			http.Error(response, "substrate emitted a non-loopback endpoint", http.StatusBadGateway)
			return
		}
		parsed.Host = net.JoinHostPort("host.docker.internal", parsed.Port())
		endpoint = parsed.String()
	}
	writeBrokerJSON(response, brokerStartResponse{Endpoint: endpoint, PID: ready.PID})
}

func (b *substrateBroker) launch(ctx context.Context, expected runtimeExpectation, dynamic map[string]string) (*brokerSubstrate, brokerReady, error) {
	if expected.Execution != "command" || len(expected.Command) == 0 {
		return nil, brokerReady{}, fmt.Errorf("parent broker only accepts committed command substrates")
	}
	commandPath, err := safeRepoPath(b.repo, expected.Command[0])
	if err != nil {
		return nil, brokerReady{}, err
	}
	if err := validateBrokerCommand(commandPath, expected.Command); err != nil {
		return nil, brokerReady{}, err
	}
	if err := b.validateDynamicInputs(ctx, expected, dynamic); err != nil {
		return nil, brokerReady{}, err
	}
	cmd := exec.Command(commandPath, expected.Command[1:]...)
	cmd.Dir = b.repo
	cmd.Env = brokerEnvironment(expected, b.receiptDir, dynamic)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, brokerReady{}, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, brokerReady{}, fmt.Errorf("start parent-owned substrate: %w", err)
	}
	decoder := json.NewDecoder(bufio.NewReader(stdout))
	readyChannel := make(chan struct {
		value brokerReady
		err   error
	}, 1)
	go func() {
		var ready brokerReady
		readyChannel <- struct {
			value brokerReady
			err   error
		}{ready, decoder.Decode(&ready)}
	}()
	var ready brokerReady
	select {
	case result := <-readyChannel:
		if result.err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, brokerReady{}, fmt.Errorf("decode parent-owned substrate READY: %w: %s", result.err, stderr.String())
		}
		ready = result.value
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, brokerReady{}, fmt.Errorf("parent-owned substrate READY timed out: %s", stderr.String())
	}
	if ready.SchemaVersion != 1 || ready.Challenge != expected.Nonce || ready.EntryID != expected.ID || ready.Identity != expected.SubstrateIdentity || ready.ContractDigest != expected.ContractDigest || ready.PID != cmd.Process.Pid || !ready.Ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, brokerReady{}, fmt.Errorf("parent-owned substrate READY identity/PID mismatch")
	}
	parsed, err := url.Parse(ready.Endpoint)
	if err != nil || parsed.Port() == "" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, brokerReady{}, fmt.Errorf("parent-owned substrate READY endpoint is not loopback")
	}
	return &brokerSubstrate{expected: expected, cmd: cmd, decoder: decoder, pid: ready.PID, stderr: stderr}, ready, nil
}

func (b *substrateBroker) validateDynamicInputs(ctx context.Context, expected runtimeExpectation, dynamic map[string]string) error {
	names := brokerDynamicInputNames(expected)
	if len(dynamic) != len(names) {
		return fmt.Errorf("substrate %s requires exactly %d reviewed dynamic runtime inputs", expected.ID, len(names))
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
		if strings.TrimSpace(dynamic[name]) == "" {
			return fmt.Errorf("substrate %s is missing reviewed dynamic runtime input %s", expected.ID, name)
		}
	}
	for name := range dynamic {
		if !allowed[name] {
			return fmt.Errorf("substrate %s supplied unreviewed dynamic runtime input %s", expected.ID, name)
		}
	}
	if expected.SubstrateID != "managed_key_custody" {
		for _, name := range names {
			if err := validateBrokerDynamicFile(b.receiptDir, name, dynamic[name]); err != nil {
				return err
			}
		}
		return nil
	}
	image := dynamic["TRSTCTL_HSM_PROOF_IMAGE"]
	network := dynamic["TRSTCTL_HSM_PROOF_NETWORK"]
	if _, err := parseContentImageID(image); err != nil || !dockerObjectNamePattern.MatchString(network) {
		return fmt.Errorf("managed-key dynamic image/network input is invalid")
	}
	inspected := runHostCommand(ctx, b.repo, "docker", "image", "inspect", "--format={{.Id}} {{.Os}}/{{.Architecture}}", image)
	fields := strings.Fields(inspected.Stdout)
	if inspected.Err != nil || len(fields) != 2 || fields[0] != image || fields[1] != managedKeyRuntimePlatform {
		return fmt.Errorf("managed-key dynamic image is not the exact local %s content ID", managedKeyRuntimePlatform)
	}
	inspected = runHostCommand(ctx, b.repo, "docker", "network", "inspect", network)
	if inspected.Err != nil {
		return fmt.Errorf("managed-key dynamic network does not exist")
	}
	return nil
}

func brokerDynamicInputNames(expected runtimeExpectation) []string {
	if expected.SubstrateID == "managed_key_custody" {
		return []string{"TRSTCTL_HSM_PROOF_IMAGE", "TRSTCTL_HSM_PROOF_NETWORK"}
	}
	switch expected.ID {
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

func validateBrokerDynamicFile(receiptDir, name, path string) error {
	if !filepath.IsAbs(receiptDir) || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
		return fmt.Errorf("dynamic runtime input %s is not an absolute scoped file", name)
	}
	root, err := filepath.EvalSymlinks(filepath.Clean(receiptDir))
	if err != nil {
		return fmt.Errorf("resolve execution receipt directory for %s: %w", name, err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve dynamic runtime input %s: %w", name, err)
	}
	if !pathWithin(root, resolved) {
		return fmt.Errorf("dynamic runtime input %s is outside the execution receipt directory", name)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect dynamic runtime input %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("dynamic runtime input %s is not a non-symlink regular file", name)
	}
	if info.Size() <= 0 || info.Size() > maxBrokerDynamicFileBytes {
		return fmt.Errorf("dynamic runtime input %s size %d is outside 1..%d bytes", name, info.Size(), maxBrokerDynamicFileBytes)
	}
	perm := info.Mode().Perm()
	if perm&0o400 == 0 || perm&0o111 != 0 || perm&0o022 != 0 {
		return fmt.Errorf("dynamic runtime input %s mode %04o is not bounded read-only material", name, perm)
	}
	if brokerSecretFileInputs[name] && perm&0o077 != 0 {
		return fmt.Errorf("dynamic runtime secret input %s mode %04o is not owner-only", name, perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return fmt.Errorf("dynamic runtime input %s is not a single-link file owned by the gate", name)
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateBrokerCommand(commandPath string, argv []string) error {
	if len(argv) == 0 || commandPath == "" {
		return fmt.Errorf("parent broker command is empty")
	}
	info, err := os.Lstat(commandPath)
	if err != nil {
		return fmt.Errorf("inspect parent broker command: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("parent broker command is not a non-symlink executable regular file")
	}
	for _, arg := range argv {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("parent broker command contains an unsafe argument")
		}
	}
	return nil
}

func brokerEnvironment(expected runtimeExpectation, receiptDir string, dynamic map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+8)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(name, "TRSTCTL_") || name == "TMPDIR" {
			continue
		}
		out = append(out, item)
	}
	out = append(out,
		"TMPDIR="+receiptDir,
		"TRSTCTL_DOD_CHALLENGE="+expected.Nonce,
		"TRSTCTL_DOD_ENTRY_ID="+expected.ID,
		"TRSTCTL_DOD_SUBSTRATE_IDENTITY="+expected.SubstrateIdentity,
		"TRSTCTL_DOD_CONTRACT_DIGEST="+expected.ContractDigest,
	)
	for _, name := range brokerDynamicInputNames(expected) {
		if value := dynamic[name]; value != "" {
			out = append(out, name+"="+value)
		}
	}
	return out
}

func (b *substrateBroker) handleStop(response http.ResponseWriter, request *http.Request) {
	var body brokerStopRequest
	if !decodeBrokerJSON(response, request, &body) {
		return
	}
	b.mu.Lock()
	session := b.sessions[body.ID]
	if body.Token != b.token || session == nil || session.stopped {
		b.mu.Unlock()
		http.Error(response, "unauthorized, missing, or duplicate substrate stop", http.StatusConflict)
		return
	}
	session.stopped = true
	b.mu.Unlock()
	raw, err := stopBrokerSubstrate(session)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadGateway)
		return
	}
	b.mu.Lock()
	b.receipts[body.ID] = append([]byte(nil), raw...)
	b.mu.Unlock()
	writeBrokerJSON(response, brokerStopResponse{Receipt: raw})
}

func stopBrokerSubstrate(session *brokerSubstrate) ([]byte, error) {
	if err := session.cmd.Process.Signal(os.Interrupt); err != nil {
		return nil, fmt.Errorf("stop parent-owned substrate: %w", err)
	}
	receiptChannel := make(chan struct {
		value brokerReceipt
		err   error
	}, 1)
	go func() {
		var value brokerReceipt
		receiptChannel <- struct {
			value brokerReceipt
			err   error
		}{value, session.decoder.Decode(&value)}
	}()
	var receipt brokerReceipt
	select {
	case result := <-receiptChannel:
		if result.err != nil {
			_ = session.cmd.Process.Kill()
			_ = session.cmd.Wait()
			return nil, fmt.Errorf("decode parent-owned substrate receipt: %w: %s", result.err, session.stderr.String())
		}
		receipt = result.value
	case <-time.After(15 * time.Second):
		_ = session.cmd.Process.Kill()
		_ = session.cmd.Wait()
		return nil, fmt.Errorf("parent-owned substrate receipt timed out")
	}
	if err := session.cmd.Wait(); err != nil {
		return nil, fmt.Errorf("parent-owned substrate exit: %w: %s", err, session.stderr.String())
	}
	expected := session.expected
	if receipt.SchemaVersion != 1 || receipt.Challenge != expected.Nonce || receipt.EntryID != expected.ID || receipt.Identity != expected.SubstrateIdentity || receipt.ContractDigest != expected.ContractDigest || receipt.PID != session.pid || !receipt.Passed {
		return nil, fmt.Errorf("parent-owned substrate final identity/PID/pass mismatch")
	}
	if expected.SubstrateID == "managed_key_custody" {
		if _, err := parseContentImageID(receipt.RuntimeIdentity); err != nil {
			return nil, fmt.Errorf("managed-key parent receipt has mutable runtime identity")
		}
	} else if receipt.RuntimeIdentity != "" {
		return nil, fmt.Errorf("ordinary parent receipt added an unexpected runtime identity")
	}
	return json.Marshal(receipt)
}

func (b *substrateBroker) receipt(id string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.receipts[id]...)
}

func (b *substrateBroker) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	sessions := make([]*brokerSubstrate, 0, len(b.sessions))
	for _, session := range b.sessions {
		if !session.stopped {
			session.stopped = true
			sessions = append(sessions, session)
		}
	}
	b.mu.Unlock()
	for _, session := range sessions {
		_ = session.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func(value *brokerSubstrate) { _ = value.cmd.Wait(); close(done) }(session)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = session.cmd.Process.Kill()
			<-done
		}
	}
	if b.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = b.server.Shutdown(ctx)
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
}

func decodeBrokerJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(response, "invalid broker request", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(response, "trailing broker request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeBrokerJSON(response http.ResponseWriter, value any) {
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		return
	}
}
