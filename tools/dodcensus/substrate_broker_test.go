// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dodproof "trstctl.com/trstctl/tools/dodcensus/proof"
)

func TestBrokerDynamicInputAllowlistsAreExact(t *testing.T) {
	tests := []struct {
		expected runtimeExpectation
		want     string
	}{
		{runtimeExpectation{ID: "external_ca.entrust"}, "TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE,TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE,TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"},
		{runtimeExpectation{ID: "code_signing.default"}, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE"},
		{runtimeExpectation{ID: "hsm_kms.tpm2", SubstrateID: "managed_key_custody"}, "TRSTCTL_HSM_PROOF_IMAGE,TRSTCTL_HSM_PROOF_NETWORK"},
		{runtimeExpectation{ID: "connector.nginx"}, ""},
	}
	for _, test := range tests {
		if got := strings.Join(brokerDynamicInputNames(test.expected), ","); got != test.want {
			t.Errorf("dynamic inputs for %s = %q, want %q", test.expected.ID, got, test.want)
		}
	}
}

func TestBrokerDynamicFilesStayInsideReceiptBoundary(t *testing.T) {
	receiptDir := privateBrokerTestDir(t)
	privateFile := writeBrokerTestFile(t, receiptDir, "nested/private.pem", 0o600, []byte("private"))
	publicFile := writeBrokerTestFile(t, receiptDir, "nested/cert.pem", 0o644, []byte("certificate"))
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", privateFile); err != nil {
		t.Fatalf("valid private input rejected: %v", err)
	}
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE", publicFile); err != nil {
		t.Fatalf("valid public input rejected: %v", err)
	}

	outside := writeBrokerTestFile(t, t.TempDir(), "outside.pem", 0o600, []byte("outside"))
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", outside); err == nil {
		t.Fatal("outside dynamic input passed")
	}
	link := filepath.Join(receiptDir, "linked.pem")
	if err := os.Symlink(privateFile, link); err != nil {
		t.Fatal(err)
	}
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", link); err == nil {
		t.Fatal("symlink dynamic input passed")
	}
	insecure := writeBrokerTestFile(t, receiptDir, "insecure.pem", 0o644, []byte("secret"))
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", insecure); err == nil {
		t.Fatal("world-readable secret dynamic input passed")
	}
	empty := writeBrokerTestFile(t, receiptDir, "empty.pem", 0o600, nil)
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", empty); err == nil {
		t.Fatal("empty dynamic input passed")
	}
	hardLink := filepath.Join(receiptDir, "hard-linked.pem")
	if err := os.Link(privateFile, hardLink); err != nil {
		t.Fatal(err)
	}
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", privateFile); err == nil {
		t.Fatal("multiply linked dynamic input passed")
	}
}

func TestBrokerTranslatesExactRuntimeTempFilesToReceiptDirectory(t *testing.T) {
	receiptDir := privateBrokerTestDir(t)
	hostFile := writeBrokerTestFile(t, receiptDir, "TestCodeSigning/001/rekor.pem", 0o600, []byte("private key"))
	runtimeFile := filepath.Join(dodproof.RuntimeTempDir, "TestCodeSigning", "001", "rekor.pem")
	dynamic := map[string]string{"TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE": runtimeFile}
	broker := newInMemorySubstrateBroker(t.TempDir(), receiptDir)
	broker.crossHost = true

	validated, err := broker.validatedDynamicInputs(context.Background(), runtimeExpectation{ID: "code_signing.default"}, dynamic)
	if err != nil {
		t.Fatalf("exact runtime temporary path rejected: %v", err)
	}
	if got := validated["TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE"]; got != hostFile {
		t.Fatalf("translated Rekor key = %q, want %q", got, hostFile)
	}
	if dynamic["TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE"] != runtimeFile {
		t.Fatal("broker mutated the child-owned request map")
	}
	environment := strings.Join(brokerEnvironment(runtimeExpectation{ID: "code_signing.default"}, receiptDir, validated), "\n")
	if !strings.Contains(environment, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE="+hostFile) || strings.Contains(environment, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE="+dodproof.RuntimeTempDir) {
		t.Fatalf("parent substrate environment did not receive only the translated host path:\n%s", environment)
	}

	entrustFiles := map[string]struct {
		relative string
		mode     os.FileMode
	}{
		"TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE": {relative: "TestEntrust/001/server.pem", mode: 0o644},
		"TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE":  {relative: "TestEntrust/001/server-key.pem", mode: 0o600},
		"TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE":   {relative: "TestEntrust/001/client-ca.pem", mode: 0o644},
	}
	entrustDynamic := make(map[string]string, len(entrustFiles))
	entrustHost := make(map[string]string, len(entrustFiles))
	for name, file := range entrustFiles {
		entrustHost[name] = writeBrokerTestFile(t, receiptDir, file.relative, file.mode, []byte(name))
		entrustDynamic[name] = filepath.Join(dodproof.RuntimeTempDir, filepath.FromSlash(file.relative))
	}
	validatedEntrust, err := broker.validatedDynamicInputs(context.Background(), runtimeExpectation{ID: "external_ca.entrust"}, entrustDynamic)
	if err != nil {
		t.Fatalf("exact Entrust runtime temporary paths rejected: %v", err)
	}
	for name, want := range entrustHost {
		if got := validatedEntrust[name]; got != want {
			t.Errorf("translated %s = %q, want %q", name, got, want)
		}
	}
}

func TestBrokerRuntimeTempTranslationRejectsAlternateRootsAndTraversal(t *testing.T) {
	receiptDir := privateBrokerTestDir(t)
	hostFile := writeBrokerTestFile(t, receiptDir, "nested/key.pem", 0o600, []byte("key"))
	broker := newInMemorySubstrateBroker(t.TempDir(), receiptDir)
	broker.crossHost = true
	expected := runtimeExpectation{ID: "code_signing.default"}

	for _, supplied := range []string{
		dodproof.RuntimeTempDir,
		dodproof.RuntimeTempDir + "-other/nested/key.pem",
		dodproof.RuntimeTempDir + "/nested/../nested/key.pem",
		hostFile,
		"relative/key.pem",
	} {
		err := broker.validateDynamicInputs(context.Background(), expected, map[string]string{"TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE": supplied})
		if err == nil {
			t.Errorf("unsafe cross-host dynamic path %q passed", supplied)
		}
	}
}

func TestBrokerDynamicFileRejectsSymlinkedAndWritablePathComponents(t *testing.T) {
	receiptDir := privateBrokerTestDir(t)
	hostFile := writeBrokerTestFile(t, receiptDir, "private/key.pem", 0o600, []byte("key"))
	linkDir := filepath.Join(receiptDir, "linked")
	if err := os.Symlink(filepath.Dir(hostFile), linkDir); err != nil {
		t.Fatal(err)
	}
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", filepath.Join(linkDir, "key.pem")); err == nil {
		t.Fatal("dynamic input beneath a symlinked directory passed")
	}

	if err := os.Chmod(filepath.Dir(hostFile), 0o722); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", hostFile); err == nil {
		t.Fatal("dynamic input beneath a group/world-writable directory passed")
	}
	if err := os.Chmod(filepath.Dir(hostFile), 0o700); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := os.Chmod(receiptDir, 0o755); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := validateBrokerDynamicFile(receiptDir, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", hostFile); err == nil {
		t.Fatal("dynamic input beneath a non-private receipt root passed")
	}
}

func TestBrokerValidatesEntrustAndRekorInputsBeforeLaunch(t *testing.T) {
	receiptDir := privateBrokerTestDir(t)
	inputs := map[string]string{
		"TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE": writeBrokerTestFile(t, receiptDir, "server.pem", 0o644, []byte("cert")),
		"TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE":  writeBrokerTestFile(t, receiptDir, "server-key.pem", 0o600, []byte("key")),
		"TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE":   writeBrokerTestFile(t, receiptDir, "client-ca.pem", 0o644, []byte("ca")),
	}
	broker := newInMemorySubstrateBroker(t.TempDir(), receiptDir)
	expected := runtimeExpectation{ID: "external_ca.entrust"}
	if err := broker.validateDynamicInputs(context.Background(), expected, inputs); err != nil {
		t.Fatalf("valid Entrust inputs rejected: %v", err)
	}
	delete(inputs, "TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE")
	if err := broker.validateDynamicInputs(context.Background(), expected, inputs); err == nil {
		t.Fatal("incomplete Entrust input set passed")
	}
	inputs["TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"] = writeBrokerTestFile(t, receiptDir, "client-ca-2.pem", 0o644, []byte("ca"))
	inputs["TRSTCTL_ARBITRARY_FILE"] = filepath.Join(receiptDir, "server.pem")
	if err := broker.validateDynamicInputs(context.Background(), expected, inputs); err == nil {
		t.Fatal("extra Entrust input passed")
	}

	rekor := map[string]string{
		"TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE": writeBrokerTestFile(t, receiptDir, "rekor.pem", 0o600, []byte("key")),
	}
	if err := broker.validateDynamicInputs(context.Background(), runtimeExpectation{ID: "code_signing.default"}, rekor); err != nil {
		t.Fatalf("valid Rekor input rejected: %v", err)
	}
	if err := broker.validateDynamicInputs(context.Background(), runtimeExpectation{ID: "connector.nginx"}, rekor); err == nil {
		t.Fatal("ordinary substrate accepted dynamic input")
	}
}

func TestBrokerEnvironmentForwardsOnlyReviewedNames(t *testing.T) {
	t.Setenv("OPENSSL_CONF", "/tmp/ambient-openssl.cnf")
	expected := runtimeExpectation{ID: "code_signing.default"}
	environment := strings.Join(brokerEnvironment(expected, t.TempDir(), map[string]string{
		"TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE": "/approved/key",
		"TRSTCTL_ARBITRARY_FILE":                  "/etc/passwd",
	}), "\n")
	if !strings.Contains(environment, "TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE=/approved/key") {
		t.Fatal("reviewed dynamic input was not forwarded")
	}
	if strings.Contains(environment, "TRSTCTL_ARBITRARY_FILE") {
		t.Fatal("unreviewed dynamic input was forwarded")
	}
	if strings.Count(environment, "OPENSSL_CONF=") != 1 || !strings.Contains(environment, "OPENSSL_CONF=/dev/null") || strings.Contains(environment, "/tmp/ambient-openssl.cnf") {
		t.Fatalf("parent substrate did not receive the one pinned empty OpenSSL profile:\n%s", environment)
	}
}

func TestBrokerHealthRequiresExactBearerToken(t *testing.T) {
	broker := newInMemorySubstrateBroker(t.TempDir(), t.TempDir())
	for _, test := range []struct {
		token string
		want  int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"Bearer " + broker.token, http.StatusNoContent},
	} {
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		request.Header.Set("Authorization", test.token)
		response := httptest.NewRecorder()
		broker.handleHealth(response, request)
		if response.Code != test.want {
			t.Errorf("health token %q status = %d, want %d", test.token, response.Code, test.want)
		}
	}
}

func TestBrokerCommandBoundaryRejectsLinksAndUnsafeArgv(t *testing.T) {
	dir := t.TempDir()
	command := writeBrokerTestFile(t, dir, "substrate.py", 0o700, []byte("#!/usr/bin/env python3\n"))
	if err := validateBrokerCommand(command, []string{"tools/dodcensus/substrates/substrate.py", "serve"}); err != nil {
		t.Fatalf("reviewed command rejected: %v", err)
	}
	if err := validateBrokerCommand(command, []string{"substrate.py", "unsafe\nargument"}); err == nil {
		t.Fatal("unsafe command argument passed")
	}
	link := filepath.Join(dir, "linked.py")
	if err := os.Symlink(command, link); err != nil {
		t.Fatal(err)
	}
	if err := validateBrokerCommand(link, []string{"linked.py"}); err == nil {
		t.Fatal("symlink broker command passed")
	}
}

func writeBrokerTestFile(t *testing.T, root, name string, mode os.FileMode, body []byte) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateBrokerTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- fixture mode in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	return dir
}
