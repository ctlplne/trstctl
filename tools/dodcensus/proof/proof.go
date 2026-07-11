// SPDX-License-Identifier: MPL-2.0

// Package proof writes nonce-bound runtime receipts for the repository-native
// Definition-of-Done census. Evidence is sealed: callers can choose one of the
// fixed domain probes below, but cannot mint a generic "passed" value from a
// bool, log line, or arbitrary observation map.
package proof

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

const maxEvidenceBody = 1 << 20

var sentinelFragments = [][]byte{
	[]byte("not configured"),
	[]byte("not implemented"),
	[]byte("unrouted"),
	[]byte(`"status":"stub"`),
	[]byte(`"status": "stub"`),
}

type expectation struct {
	SchemaVersion     int               `json:"schema_version"`
	Repo              string            `json:"repo"`
	Nonce             string            `json:"nonce"`
	ID                string            `json:"id"`
	BuildProfile      string            `json:"build_profile"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	SubstrateID       string            `json:"substrate_id"`
	SubstrateKind     string            `json:"substrate_kind"`
	SubstrateIdentity string            `json:"substrate_identity"`
	ContractDigest    string            `json:"contract_digest"`
	Verifier          string            `json:"verifier"`
	Execution         string            `json:"execution"`
	Command           []string          `json:"command,omitempty"`
	Image             string            `json:"image,omitempty"`
	ReceiptFile       string            `json:"receipt_file"`
	Required          map[string]string `json:"required_observations"`
}

type receipt struct {
	SchemaVersion     int               `json:"schema_version"`
	Nonce             string            `json:"nonce"`
	ID                string            `json:"id"`
	BuildProfile      string            `json:"build_profile"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	SubstrateID       string            `json:"substrate_id"`
	SubstrateKind     string            `json:"substrate_kind"`
	SubstrateIdentity string            `json:"substrate_identity"`
	ContractDigest    string            `json:"contract_digest"`
	Verifier          string            `json:"verifier"`
	Passed            bool              `json:"passed"`
	Skipped           bool              `json:"skipped"`
	Observations      map[string]string `json:"observations"`
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
	once       sync.Once
}

// ExternalSubstrate is a gate-configured, out-of-process emulator or verifier.
// Tests cannot choose its executable/image: those values come from the manifest
// expectation. The process must echo a nonce-bound READY record and later a final
// action receipt from the same PID.
type ExternalSubstrate struct {
	t        *testing.T
	expect   expectation
	cmd      *exec.Cmd
	decoder  *json.Decoder
	endpoint string
	pid      int
	stopped  bool
}

type substrateReady struct {
	SchemaVersion  int    `json:"schema_version"`
	Challenge      string `json:"challenge"`
	Identity       string `json:"identity"`
	ContractDigest string `json:"contract_digest"`
	PID            int    `json:"pid"`
	Ready          bool   `json:"ready"`
	Endpoint       string `json:"endpoint"`
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
	commandPath := filepath.Join(expected.Repo, filepath.FromSlash(expected.Command[0]))
	cmd := exec.Command(commandPath, expected.Command[1:]...)
	cmd.Dir = expected.Repo
	cmd.Env = substrateEnvironment(expected)
	return startExternal(t, expected, cmd, true)
}

// StartContainer launches the exact digest-pinned image from the manifest.
func StartContainer(t *testing.T, id string) *ExternalSubstrate {
	t.Helper()
	expected := expectationFor(t, id)
	if expected.Execution != "container" || expected.Image == "" {
		t.Fatalf("DOD-CENSUS: %s container expectation is incomplete", id)
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
		t.Fatal("DOD-CENSUS: substrate did not emit READY within 10 seconds")
	}
	parsedEndpoint, endpointErr := url.Parse(ready.Endpoint)
	if ready.SchemaVersion != 1 || ready.Challenge != expected.Nonce || ready.Identity != expected.SubstrateIdentity || ready.ContractDigest != expected.ContractDigest || !ready.Ready || ready.PID <= 0 || endpointErr != nil || (parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") || parsedEndpoint.Host == "" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("DOD-CENSUS: substrate READY failed nonce/identity/contract/PID/endpoint validation")
	}
	if requireHostPID && ready.PID != cmd.Process.Pid {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("DOD-CENSUS: READY pid %d is not launched command pid %d", ready.PID, cmd.Process.Pid)
	}
	return &ExternalSubstrate{t: t, expect: expected, cmd: cmd, decoder: decoder, endpoint: ready.Endpoint, pid: ready.PID}
}

// Endpoint is the validated address emitted by the external READY record.
func (s *ExternalSubstrate) Endpoint() string { return s.endpoint }

// StopAndReceipt terminates the same process and returns its final nonce-bound
// action receipt. Session.Complete validates and hashes these bytes.
func (s *ExternalSubstrate) StopAndReceipt() []byte {
	s.t.Helper()
	if s.stopped {
		s.t.Fatal("DOD-CENSUS: substrate stopped more than once")
	}
	s.stopped = true
	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
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
		s.t.Fatal("DOD-CENSUS: substrate did not emit final receipt within 10 seconds")
	}
	if err := s.cmd.Wait(); err != nil {
		s.t.Fatalf("DOD-CENSUS: substrate exit: %v", err)
	}
	if receipt.PID != s.pid {
		s.t.Fatalf("DOD-CENSUS: final receipt pid %d differs from READY pid %d", receipt.PID, s.pid)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		s.t.Fatalf("DOD-CENSUS: encode final receipt: %v", err)
	}
	return raw
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
	if expected.SchemaVersion != 1 || expected.Nonce == "" || expected.BuildProfile == "" || expected.SubstrateID == "" || expected.SubstrateIdentity == "" || expected.ContractDigest == "" || expected.Verifier == "" || expected.ReceiptFile == "" {
		t.Fatalf("DOD-CENSUS: expectation for %s is incomplete", id)
	}
	if request.Method != expected.Method || request.URL == nil || request.URL.Path != expected.Path {
		t.Fatalf("DOD-CENSUS: request %s %s does not match gate route %s %s", request.Method, request.URL.Path, expected.Method, expected.Path)
	}
	capture := &responseCapture{header: make(http.Header), status: http.StatusOK}
	handler.ServeHTTP(capture, request)
	if err := responseIsServed(capture.status, capture.body.Bytes()); err != nil {
		t.Fatalf("DOD-CENSUS: %s assembled route is not served: %v", id, err)
	}
	return &Session{t: t, expect: *expected, statusCode: capture.status, body: append([]byte(nil), capture.body.Bytes()...)}
}

// StartResponse binds evidence to a response returned by an independently
// launched shipped binary (for example the control plane talking to the separate
// signer process). It is the multi-process counterpart to Start's in-package
// handler path.
func StartResponse(t *testing.T, id string, response *http.Response) *Session {
	t.Helper()
	if response == nil || response.Request == nil || response.Request.URL == nil {
		t.Fatalf("DOD-CENSUS: %s has nil launched-binary response/request", id)
	}
	expected := expectationFor(t, id)
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
		t.Fatalf("DOD-CENSUS: %s launched route is not served: %v", id, err)
	}
	return &Session{t: t, expect: expected, statusCode: response.StatusCode, body: append([]byte(nil), body...)}
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
			BuildProfile: s.expect.BuildProfile, Method: s.expect.Method, Path: s.expect.Path,
			SubstrateID: s.expect.SubstrateID, SubstrateKind: s.expect.SubstrateKind,
			SubstrateIdentity: s.expect.SubstrateIdentity, ContractDigest: s.expect.ContractDigest,
			Verifier: s.expect.Verifier, Passed: true, Skipped: false,
			Observations: payload.observations,
		}
		file, err := os.OpenFile(s.expect.ReceiptFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			s.t.Fatalf("DOD-CENSUS: create unique receipt: %v", err)
		}
		encoder := json.NewEncoder(file)
		if err := encoder.Encode(r); err != nil {
			_ = file.Close()
			s.t.Fatalf("DOD-CENSUS: encode receipt: %v", err)
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
	SchemaVersion  int    `json:"schema_version"`
	Challenge      string `json:"challenge"`
	Identity       string `json:"identity"`
	ContractDigest string `json:"contract_digest"`
	PID            int    `json:"pid"`
	Passed         bool   `json:"passed"`
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
	if receipt.SchemaVersion != 1 || receipt.Challenge != s.expect.Nonce || receipt.Identity != s.expect.SubstrateIdentity || receipt.ContractDigest != s.expect.ContractDigest || receipt.PID <= 0 || receipt.PID == os.Getpid() || !receipt.Passed {
		return "", fmt.Errorf("nonce/identity/contract/PID/pass mismatch")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	return "sha256:" + internalcrypto.SHA256Hex(canonical), nil
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
