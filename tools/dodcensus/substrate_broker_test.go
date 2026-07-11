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
	receiptDir := t.TempDir()
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
}

func TestBrokerValidatesEntrustAndRekorInputsBeforeLaunch(t *testing.T) {
	receiptDir := t.TempDir()
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
