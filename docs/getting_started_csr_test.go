// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestGettingStartedOpenSSLCSRPassesIssuanceParser(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL is required to execute the documented first-certificate command")
	}

	lines := strings.Split(read(t, "getting-started.md"), "\n")
	var command []string
	for i, line := range lines {
		if !strings.HasPrefix(line, "openssl req -new -newkey ec ") {
			continue
		}
		for ; i < len(lines); i++ {
			command = append(command, lines[i])
			if !strings.HasSuffix(strings.TrimSpace(lines[i]), "\\") {
				break
			}
		}
		break
	}
	if len(command) == 0 {
		t.Fatal("getting-started.md has no first-certificate OpenSSL CSR command")
	}
	documentedArgs := strings.Fields(strings.ReplaceAll(strings.Join(command, " "), "\\", ""))
	for i := range documentedArgs {
		documentedArgs[i] = strings.Trim(documentedArgs[i], "'")
	}
	wantArgs := []string{
		"openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-pkeyopt", "ec_param_enc:named_curve", "-nodes", "-keyout", "payments.key",
		"-out", "payments.csr", "-subj", "/CN=payments.svc", "-addext", "subjectAltName=DNS:payments.svc",
	}
	if !slices.Equal(documentedArgs, wantArgs) {
		t.Fatalf("documented CSR command changed: got %q, want %q", documentedArgs, wantArgs)
	}

	dir := t.TempDir()
	cmd := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-pkeyopt", "ec_param_enc:named_curve", "-nodes", "-keyout", "payments.key", "-out", "payments.csr",
		"-subj", "/CN=payments.svc", "-addext", "subjectAltName=DNS:payments.svc")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("documented CSR command failed: %v: %s", err, output)
	}

	inspect := exec.Command("openssl", "req", "-in", "payments.csr", "-outform", "PEM")
	inspect.Dir = dir
	csr, err := inspect.CombinedOutput()
	if err != nil {
		t.Fatalf("read generated public CSR: %v: %s", err, csr)
	}
	_, info, err := crypto.ParsePublicCSRPEM(csr)
	if err != nil {
		t.Fatalf("documented CSR cannot pass the issuance parser: %v", err)
	}
	if info.KeyAlgorithm != "ECDSA" || info.KeyBits != 256 || info.CommonName != "payments.svc" || !slices.Equal(info.DNSNames, []string{"payments.svc"}) {
		t.Fatalf("documented CSR lost its intended key or DNS identity: %+v", info)
	}
	key, err := os.Stat(filepath.Join(dir, "payments.key"))
	if err != nil {
		t.Fatal(err)
	}
	if key.Mode().Perm()&0o077 != 0 {
		t.Fatalf("documented private key is readable outside its owner: %v", key.Mode().Perm())
	}
}

func TestRequestWizardOpenSSLCSRIncludesDNSIdentity(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL is required to execute the request wizard command")
	}
	source, err := os.ReadFile("../web/src/i18n/messages.ts")
	if err != nil {
		t.Fatal(err)
	}
	key := `"source.openssl.req.new.newkey.ec.pkeyopt.ec.param.c1a1d7efe2"`
	_, message, ok := strings.Cut(string(source), key)
	if !ok {
		t.Fatal("request wizard OpenSSL command message is missing")
	}
	_, message, ok = strings.Cut(message, "defaultMessage:")
	if !ok {
		t.Fatal("request wizard command has no default message")
	}
	message = strings.SplitN(strings.TrimSpace(message), "\n", 2)[0]
	message = strings.Trim(message, "',")
	message = strings.ReplaceAll(message, "{value1}", "gui.payments.svc")
	args := strings.Fields(message)
	for i := range args {
		args[i] = strings.Trim(args[i], `"`)
	}
	wantArgs := []string{
		"openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-pkeyopt", "ec_param_enc:named_curve", "-nodes", "-keyout", "gui.payments.svc.key",
		"-out", "gui.payments.svc.csr", "-subj", "/CN=gui.payments.svc", "-addext", "subjectAltName=DNS:gui.payments.svc",
	}
	if !slices.Equal(args, wantArgs) {
		t.Fatalf("wizard OpenSSL command changed: got %q, want %q", args, wantArgs)
	}
	dir := t.TempDir()
	cmd := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-pkeyopt", "ec_param_enc:named_curve", "-nodes", "-keyout", "gui.payments.svc.key",
		"-out", "gui.payments.svc.csr", "-subj", "/CN=gui.payments.svc", "-addext", "subjectAltName=DNS:gui.payments.svc")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wizard OpenSSL command failed: %v: %s", err, output)
	}
	inspect := exec.Command("openssl", "req", "-in", "gui.payments.svc.csr", "-outform", "PEM")
	inspect.Dir = dir
	csr, err := inspect.CombinedOutput()
	if err != nil {
		t.Fatalf("read wizard public CSR: %v: %s", err, csr)
	}
	_, info, err := crypto.ParsePublicCSRPEM(csr)
	if err != nil {
		t.Fatalf("wizard CSR cannot pass issuance parser: %v", err)
	}
	if info.CommonName != "gui.payments.svc" || !slices.Equal(info.DNSNames, []string{"gui.payments.svc"}) {
		t.Fatalf("wizard CSR lost requested DNS identity: %+v", info)
	}
}
