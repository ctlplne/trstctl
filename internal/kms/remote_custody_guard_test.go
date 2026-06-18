package kms

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemoteKeyLifecycleInterfaceStaysProviderHeldAndContextBound(t *testing.T) {
	src := readSource(t, "../crypto/backend.go")
	file := parseSource(t, "../crypto/backend.go")
	iface := findInterface(t, file, "RemoteKeyLifecycle")

	assertInterfaceMethod(t, iface, "GenerateManagedKey",
		[]string{"context.Context", "Algorithm"},
		[]string{"Signer", "KeyRef", "error"})
	assertInterfaceMethod(t, iface, "RotateKey",
		[]string{"context.Context", "KeyRef"},
		[]string{"Signer", "KeyRef", "error"})
	assertInterfaceMethod(t, iface, "RevokeKey",
		[]string{"context.Context", "KeyRef"},
		[]string{"error"})
	assertInterfaceMethod(t, iface, "ZeroizeKey",
		[]string{"context.Context", "KeyRef"},
		[]string{"error"})

	assertContains(t, "crypto backend custody comment", src,
		"type KeyRef struct",
		"without exposing\n// any private material",
		"keys live OUTSIDE this process",
		"private key never materializes in the control-plane address space",
		"Each method takes a context so the remote round-trip is cancelable/deadline-\n// bound",
		"ZeroizeKey schedules/performs destruction of ref's key material in the backend")
}

func TestAWSKMSRemoteLifecycleStaysProviderOwned(t *testing.T) {
	src := readSource(t, "awskms/awskms_lifecycle.go")
	file := parseSource(t, "awskms/awskms_lifecycle.go")

	assertContains(t, "aws remote lifecycle implementation", src,
		"var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)",
		"const pendingDeletionWindowDays = 7",
		"signer, err := b.GenerateKeyContext(ctx, alg)",
		"crypto.KeyRef{ID: ks.keyID, Algorithm: alg}",
		"return b.GenerateManagedKey(ctx, ref.Algorithm)",
		"b.opContext(ctx)",
		"TrentService.DisableKey",
		"TrentService.ScheduleKeyDeletion",
		"private material never leaves KMS")

	assertMethodSignature(t, file, "Backend", "GenerateManagedKey",
		[]string{"context.Context", "crypto.Algorithm"},
		[]string{"crypto.Signer", "crypto.KeyRef", "error"})
	assertMethodSignature(t, file, "Backend", "RotateKey",
		[]string{"context.Context", "crypto.KeyRef"},
		[]string{"crypto.Signer", "crypto.KeyRef", "error"})
	assertMethodSignature(t, file, "Backend", "RevokeKey",
		[]string{"context.Context", "crypto.KeyRef"},
		[]string{"error"})
	assertMethodSignature(t, file, "Backend", "ZeroizeKey",
		[]string{"context.Context", "crypto.KeyRef"},
		[]string{"error"})

	testSrc := readSource(t, "awskms/awskms_lifecycle_test.go")
	assertContains(t, "aws remote lifecycle regression test", testSrc,
		"TestAWSKMSRemoteKeyLifecycle",
		"var lc crypto.RemoteKeyLifecycle = b",
		"lc.GenerateManagedKey",
		"lc.RotateKey",
		"lc.RevokeKey",
		"lc.ZeroizeKey",
		"a revoked (disabled) KMS key still signed",
		"a zeroized (pending-deletion) KMS key still signed",
		"successor key broke after retiring the predecessor")
}

func TestCloudKMSProviderCallsStayContextBound(t *testing.T) {
	cases := []struct {
		name     string
		rel      string
		snippets []string
	}{
		{
			name: "aws-kms",
			rel:  "awskms/awskms.go",
			snippets: []string{
				"_ crypto.ContextKeyGenerator = (*Backend)(nil)",
				"_ crypto.ContextSigner       = (*kmsSigner)(nil)",
				"return b.GenerateKeyContext(context.Background(), alg)",
				"func (b *Backend) GenerateKeyContext(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, error)",
				"ctx, cancel := b.opContext(ctx)",
				"func (s *kmsSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error)",
				"return s.SignContext(context.Background(), message, opts)",
				"func (s *kmsSigner) SignContext(ctx context.Context, message []byte, opts crypto.SignOptions) ([]byte, error)",
				"\"KeyId\":            s.keyID",
				"TrentService.Sign",
				"the private key never leaves KMS",
			},
		},
		{
			name: "azure-key-vault",
			rel:  "azurekv/azurekv.go",
			snippets: []string{
				"_ crypto.ContextKeyGenerator = (*Backend)(nil)",
				"_ crypto.ContextSigner       = (*kvSigner)(nil)",
				"return b.GenerateKeyContext(context.Background(), alg)",
				"func (b *Backend) GenerateKeyContext(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, error)",
				"ctx, cancel := b.opContext(ctx)",
				"func (s *kvSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error)",
				"return s.SignContext(context.Background(), message, opts)",
				"func (s *kvSigner) SignContext(ctx context.Context, message []byte, opts crypto.SignOptions) ([]byte, error)",
				"path := keyPath(s.name, s.version) + \"/sign\"",
				"the private key never leaves the vault",
			},
		},
		{
			name: "gcp-kms",
			rel:  "gcpkms/gcpkms.go",
			snippets: []string{
				"_ crypto.ContextKeyGenerator = (*Backend)(nil)",
				"_ crypto.ContextSigner       = (*kmsSigner)(nil)",
				"return b.GenerateKeyContext(context.Background(), alg)",
				"func (b *Backend) GenerateKeyContext(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, error)",
				"ctx, cancel := b.opContext(ctx)",
				"func (s *kmsSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error)",
				"return s.SignContext(context.Background(), message, opts)",
				"func (s *kmsSigner) SignContext(ctx context.Context, message []byte, opts crypto.SignOptions) ([]byte, error)",
				"s.versionName+\":asymmetricSign\"",
				"the private key never leaves KMS",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := readSource(t, tc.rel)
			assertContains(t, tc.name, src, tc.snippets...)
			assertNotContains(t, tc.name, src,
				"GenerateLockedKey(",
				"NewLockedSigner",
				"secret.Buffer")
		})
	}
}

func TestDeviceBackendsKeepOnlyOpaqueSignerHandles(t *testing.T) {
	cases := []struct {
		name     string
		rel      string
		snippets []string
	}{
		{
			name: "pkcs11",
			rel:  "pkcs11/pkcs11.go",
			snippets: []string{
				"type Session interface",
				"GenerateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)",
				"SignDigest(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)",
				"handle, publicDER, err := b.session.GenerateKey(alg)",
				"handle  string",
				"s.session.SignDigest(s.handle, digest, opts)",
				"the private key never leaves the HSM",
			},
		},
		{
			name: "tpm",
			rel:  "tpm/tpm.go",
			snippets: []string{
				"type Device interface",
				"CreateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)",
				"Sign(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)",
				"handle, pubDER, err := b.dev.CreateKey(alg)",
				"handle string",
				"s.dev.Sign(s.handle, digest, opts)",
				"the private key never leaves the device",
			},
		},
		{
			name: "yubihsm",
			rel:  "yubihsm/yubihsm.go",
			snippets: []string{
				"type Connector interface",
				"GenerateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)",
				"SignDigest(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)",
				"handle, publicDER, err := b.conn.GenerateKey(alg)",
				"handle string",
				"s.conn.SignDigest(s.handle, digest, opts)",
				"private key never leaves the YubiHSM",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := readSource(t, tc.rel)
			assertContains(t, tc.name, src, tc.snippets...)
			assertNotContains(t, tc.name, src,
				"GenerateLockedKey(",
				"NewLockedSigner",
				"secret.Buffer",
				"privateDER",
				"privateKeyDER")
		})
	}
}

func readSource(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(sourcePath(t, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

func parseSource(t *testing.T, rel string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, sourcePath(t, rel), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return file
}

func sourcePath(t *testing.T, rel string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path: runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(filename), rel)
}

func findInterface(t *testing.T, file *ast.File, name string) *ast.InterfaceType {
	t.Helper()
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != name {
				continue
			}
			iface, ok := ts.Type.(*ast.InterfaceType)
			if !ok {
				t.Fatalf("%s is %T, want interface", name, ts.Type)
			}
			return iface
		}
	}
	t.Fatalf("interface %s not found", name)
	return nil
}

func assertInterfaceMethod(t *testing.T, iface *ast.InterfaceType, method string, params, results []string) {
	t.Helper()
	for _, field := range iface.Methods.List {
		if len(field.Names) != 1 || field.Names[0].Name != method {
			continue
		}
		fn, ok := field.Type.(*ast.FuncType)
		if !ok {
			t.Fatalf("%s is %T, want function", method, field.Type)
		}
		assertSignature(t, method, fn, params, results)
		return
	}
	t.Fatalf("method %s not found", method)
}

func assertMethodSignature(t *testing.T, file *ast.File, recvName, method string, params, results []string) {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != method {
			continue
		}
		if receiverName(fn.Recv.List[0].Type) != recvName {
			continue
		}
		assertSignature(t, method, fn.Type, params, results)
		return
	}
	t.Fatalf("method %s.%s not found", recvName, method)
}

func assertSignature(t *testing.T, label string, fn *ast.FuncType, wantParams, wantResults []string) {
	t.Helper()
	if got := fieldTypes(fn.Params); !sameStrings(got, wantParams) {
		t.Fatalf("%s params = %v, want %v", label, got, wantParams)
	}
	if got := fieldTypes(fn.Results); !sameStrings(got, wantResults) {
		t.Fatalf("%s results = %v, want %v", label, got, wantResults)
	}
}

func fieldTypes(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var out []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			out = append(out, exprString(field.Type))
		}
	}
	return out
}

func receiverName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return receiverName(v.X)
	default:
		return exprString(expr)
	}
}

func exprString(expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), expr); err != nil {
		return "<invalid>"
	}
	return buf.String()
}

func assertContains(t *testing.T, label, src string, snippets ...string) {
	t.Helper()
	for _, snippet := range snippets {
		if !strings.Contains(src, snippet) {
			t.Fatalf("%s: missing source guard %q", label, snippet)
		}
	}
}

func assertNotContains(t *testing.T, label, src string, snippets ...string) {
	t.Helper()
	for _, snippet := range snippets {
		if strings.Contains(src, snippet) {
			t.Fatalf("%s: source must not contain %q", label, snippet)
		}
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
