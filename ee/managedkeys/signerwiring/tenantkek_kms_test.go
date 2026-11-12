// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/ee/managedkeys/signerwiring"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// writeCountingKMSAdapter is a stand-in for trstctl-kms-wrap: it "wraps" by
// reversing the bytes under a fixed prefix, refuses while the disabled file
// exists, and appends each operation to the log file, so a test counts the
// KMS calls the signer makes.
func writeCountingKMSAdapter(t *testing.T, dir string) (command, logFile, disabledFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the counting KMS adapter is a POSIX script")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is needed for the KMS adapter stand-in")
	}
	logFile = filepath.Join(dir, "kms-calls.log")
	disabledFile = filepath.Join(dir, "kms-key-disabled")
	command = filepath.Join(dir, "kms-wrap.py")
	body := `#!/usr/bin/env python3
import os
import sys

op, provider, key_ref = sys.argv[1:4]
data = sys.stdin.buffer.read()
with open("` + logFile + `", "a") as log:
    log.write(op + "\n")
if provider != "awskms" or not key_ref.startswith("arn:aws:kms:"):
    sys.stderr.write("bad provider or key ref")
    sys.exit(2)
if os.path.exists("` + disabledFile + `"):
    sys.stderr.write("the KMS key is disabled")
    sys.exit(5)
if op == "wrap":
    sys.stdout.buffer.write(b"kmswrap:" + data[::-1])
elif op == "unwrap":
    if not data.startswith(b"kmswrap:"):
        sys.stderr.write("bad envelope")
        sys.exit(3)
    sys.stdout.buffer.write(data[len(b"kmswrap:"):][::-1])
else:
    sys.exit(4)
`
	if err := os.WriteFile(command, []byte(body), 0o700); err != nil { // #nosec G306 -- fixture script in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	return command, logFile, disabledFile
}

func kmsCalls(t *testing.T, logFile string) (wraps, unwraps int) {
	t.Helper()
	raw, err := os.ReadFile(logFile) // #nosec G304 -- the fixture adapter's log in the test tempdir (CWE-22)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		switch line {
		case "wrap":
			wraps++
		case "unwrap":
			unwraps++
		}
	}
	return wraps, unwraps
}

// OD-10 (A200-L4): the signer's tenant KEK custody keeps a tenant domain KEK
// under a wrapper key that a cloud KMS key wraps, through the signer's KMS
// wrap adapter. The first start creates the wrapper key through the KMS and
// writes only its wrapped form (0600). With kms_cache_seconds unset every
// data-key operation calls the KMS; with a time limit the signer calls it
// once however many data keys it wraps and unwraps, and closing the custody
// (shutdown) wipes the key, so the next use after a restart calls the KMS
// again. A restart reuses the wrapped key file and still opens what it
// sealed, and a disabled KMS key makes the wrapper unavailable.
func TestSignerTenantKEKUnderACloudKMSKeyOD10(t *testing.T) {
	dir := t.TempDir()
	command, logFile, disabledFile := writeCountingKMSAdapter(t, dir)
	wrappedFile := filepath.Join(dir, "tenant-kek-kms-a.wrapped")
	write := func(cacheSeconds int) string {
		t.Helper()
		path := filepath.Join(dir, "tenant-kek.json")
		body := `{"kms_wrap_command":"` + command + `","kms_wrappers":[{"id":"kms-a","provider":"awskms","key_ref":"arn:aws:kms:us-east-1:111122223333:key/tenant-kek","wrapped_key_file":"` + wrappedFile + `"}],"kms_cache_seconds":` + strconv.Itoa(cacheSeconds) + `}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ctx := context.Background()
	binding := []byte("tenant=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;domain=11111111-1111-4111-8111-111111111111;generation=1")

	// First start, cache off: the wrapper key is created and probed.
	option, closeCustody, err := signerwiring.TenantKEKOption(write(0))
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	info, err := os.Stat(wrappedFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("wrapped key file = %v, %v; want 0600", info, err)
	}
	if wraps, _ := kmsCalls(t, logFile); wraps != 1 {
		t.Fatalf("creating the wrapper key made %d KMS wraps, want 1", wraps)
	}
	srv := signing.NewServer(option)
	created, err := srv.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: "kms-a", Binding: binding})
	if err != nil {
		t.Fatalf("create a domain KEK: %v", err)
	}
	wrappedKEK := created.GetWrappedDomainKek()
	_, before := kmsCalls(t, logFile)
	dek, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	var wrappedDEK []byte
	for i := 0; i < 3; i++ {
		out, err := srv.WrapTenantDataKey(ctx, &signerpb.WrapTenantDataKeyRequest{WrapperId: "kms-a", WrappedDomainKek: wrappedKEK, Binding: binding, DataKey: dek})
		if err != nil {
			t.Fatalf("wrap %d: %v", i, err)
		}
		wrappedDEK = out.GetWrappedDataKey()
	}
	if _, after := kmsCalls(t, logFile); after-before != 3 {
		t.Fatalf("cache off: three data-key wraps made %d KMS unwraps, want 3", after-before)
	}
	if err := closeCustody(); err != nil {
		t.Fatal(err)
	}

	// Restart with a ten-minute limit: the same wrapped key file, one KMS
	// call for any number of data-key operations.
	option, closeCustody, err = signerwiring.TenantKEKOption(write(600))
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if wraps, _ := kmsCalls(t, logFile); wraps != 1 {
		t.Fatalf("a restart created another wrapper key: %d KMS wraps", wraps)
	}
	srv = signing.NewServer(option)
	_, before = kmsCalls(t, logFile)
	for i := 0; i < 5; i++ {
		back, err := srv.UnwrapTenantDataKey(ctx, &signerpb.UnwrapTenantDataKeyRequest{WrapperId: "kms-a", WrappedDomainKek: wrappedKEK, Binding: binding, WrappedDataKey: wrappedDEK})
		if err != nil || !bytes.Equal(back.GetDataKey(), dek) {
			t.Fatalf("unwrap %d after the restart: %v", i, err)
		}
	}
	if _, after := kmsCalls(t, logFile); after != before {
		t.Fatalf("cache on: data-key unwraps called the KMS %d more times; the startup probe held the key", after-before)
	}
	// Shutdown wipes the held key: the custody refuses, and calls nothing.
	if err := closeCustody(); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.UnwrapTenantDataKey(ctx, &signerpb.UnwrapTenantDataKeyRequest{WrapperId: "kms-a", WrappedDomainKek: wrappedKEK, Binding: binding, WrappedDataKey: wrappedDEK}); err == nil {
		t.Fatal("a closed custody still unwrapped")
	}
	if _, after := kmsCalls(t, logFile); after != before {
		t.Fatal("a closed custody called the KMS")
	}

	// A disabled KMS key stops the next start, naming the KMS.
	if err := os.WriteFile(disabledFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := signerwiring.TenantKEKOption(write(0)); err == nil || !strings.Contains(err.Error(), "kms-a") {
		t.Fatalf("a start against a disabled KMS key = %v", err)
	}
}

// OD-10: malformed KMS wrapper configuration is refused before any KMS call.
func TestTenantKEKOptionRefusesMalformedKMSWrappersOD10(t *testing.T) {
	dir := t.TempDir()
	command, logFile, _ := writeCountingKMSAdapter(t, dir)
	write := func(body string) string {
		t.Helper()
		path := filepath.Join(dir, "tenant-kek.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	abs := filepath.Join(dir, "k.wrapped")
	kms := func(id, file string) string {
		return `{"id":"` + id + `","provider":"awskms","key_ref":"arn:aws:kms:us-east-1:111122223333:key/k","wrapped_key_file":"` + file + `"}`
	}
	cmd := `"kms_wrap_command":"` + command + `",`
	for name, body := range map[string]string{
		"no adapter command":          `{"kms_wrappers":[` + kms("kms-a", abs) + `]}`,
		"a relative adapter":          `{"kms_wrap_command":"kms-wrap.py","kms_wrappers":[` + kms("kms-a", abs) + `]}`,
		"an adapter with no wrappers": `{` + cmd + `"wrappers":[{"id":"hsm-a","key_label":"a"}]}`,
		"a relative wrapped file":     `{` + cmd + `"kms_wrappers":[` + kms("kms-a", "k.wrapped") + `]}`,
		"a cache beyond 24 hours":     `{` + cmd + `"kms_wrappers":[` + kms("kms-a", abs) + `],"kms_cache_seconds":86401}`,
		"a negative cache":            `{` + cmd + `"kms_wrappers":[` + kms("kms-a", abs) + `],"kms_cache_seconds":-1}`,
		"a timeout beyond 5 minutes":  `{` + cmd + `"kms_wrappers":[` + kms("kms-a", abs) + `],"kms_timeout_seconds":301}`,
		"a cache with no KMS":         `{"wrappers":[{"id":"hsm-a","key_label":"a"}],"kms_cache_seconds":60}`,
		"a repeated KMS wrapper":      `{` + cmd + `"kms_wrappers":[` + kms("kms-a", abs) + `,` + kms("kms-a", abs) + `]}`,
		"an ID both HSM and KMS":      `{` + cmd + `"wrappers":[{"id":"shared","key_label":"a"}],"kms_wrappers":[` + kms("shared", abs) + `]}`,
		"no provider":                 `{` + cmd + `"kms_wrappers":[{"id":"kms-a","key_ref":"arn:aws:kms:us-east-1:1:key/k","wrapped_key_file":"` + abs + `"}]}`,
		"an unknown KMS field":        `{` + cmd + `"kms_wrappers":[` + kms("kms-a", abs) + `],"kms_cache":true}`,
	} {
		if _, _, err := signerwiring.TenantKEKOption(write(body)); err == nil {
			t.Errorf("%s: the config was accepted", name)
		}
	}
	if wraps, unwraps := kmsCalls(t, logFile); wraps != 0 || unwraps != 0 {
		t.Fatalf("refused configs called the KMS: %d wraps, %d unwraps", wraps, unwraps)
	}
}
