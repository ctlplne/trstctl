// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
)

const managedKeyRuntimePlatform = "linux/amd64"

var managedKeyIdentityClosure = []string{
	".github/workflows/release.yml",
	"deploy/docker/Dockerfile.signer-hsm",
	"go.mod",
	"go.sum",
	"internal/server/dod_managed_key_runtime_test.go",
	"tools/dodcensus/Dockerfile.managed-key-runtime",
	"tools/dodcensus/substrates/managed_key_signer_entrypoint.sh",
	"tools/dodcensus/substrates/managed_keys.py",
}

// inspectManagedKeyRuntimeClosure makes the dynamic image bytes part of the
// gate, not merely a convention in a runtime test. The committed identity must
// bind every file which chooses the builder/runtime bases, apt package universe,
// signer parent image, and final container image ID reported in the receipt.
func inspectManagedKeyRuntimeClosure(repo string, substrate Substrate) error {
	want := append([]string(nil), managedKeyIdentityClosure...)
	got := append([]string(nil), substrate.IdentityFiles...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("managed-key identity_files = %v, want exact base/package/runtime closure %v", got, want)
	}

	read := func(name string) (string, error) {
		path, err := safeRepoPath(repo, name)
		if err != nil {
			return "", err
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		return string(raw), nil
	}

	signerDockerfile, err := read("deploy/docker/Dockerfile.signer-hsm")
	if err != nil {
		return err
	}
	if err := requireNoDefaultDockerArg(signerDockerfile, "BUILD_IMAGE"); err != nil {
		return fmt.Errorf("HSM signer builder base: %w", err)
	}
	if err := requireNoDefaultDockerArg(signerDockerfile, "BASE_IMAGE"); err != nil {
		return fmt.Errorf("HSM signer runtime base: %w", err)
	}
	if err := requirePinnedAptSnapshot(signerDockerfile); err != nil {
		return fmt.Errorf("HSM signer packages: %w", err)
	}

	overlayDockerfile, err := read("tools/dodcensus/Dockerfile.managed-key-runtime")
	if err != nil {
		return err
	}
	if err := requireNoDefaultDockerArg(overlayDockerfile, "SIGNER_IMAGE"); err != nil {
		return fmt.Errorf("managed-key verifier parent: %w", err)
	}
	if err := requirePinnedAptSnapshot(overlayDockerfile); err != nil {
		return fmt.Errorf("managed-key verifier packages: %w", err)
	}

	workflow, err := read(".github/workflows/release.yml")
	if err != nil {
		return err
	}
	for _, required := range []string{
		"id: hsm_basedigest",
		`docker buildx imagetools inspect "${build_base}" --format '{{.Manifest.Digest}}'`,
		`docker buildx imagetools inspect "${runtime_base}" --format '{{.Manifest.Digest}}'`,
		`echo "build_ref=golang@${build_digest}"`,
		`echo "runtime_ref=debian@${runtime_digest}"`,
		"BUILD_IMAGE=${{ steps.hsm_basedigest.outputs.build_ref }}",
		"BASE_IMAGE=${{ steps.hsm_basedigest.outputs.runtime_ref }}",
	} {
		if !strings.Contains(workflow, required) {
			return fmt.Errorf("HSM release workflow omits immutable base-image dataflow %q", required)
		}
	}

	runtimeSource, err := read("internal/server/dod_managed_key_runtime_test.go")
	if err != nil {
		return err
	}
	platformDeclared := false
	for _, line := range strings.Split(runtimeSource, "\n") {
		if strings.Join(strings.Fields(line), " ") == `dodManagedKeyRuntimePlatform = "linux/amd64"` {
			platformDeclared = true
			break
		}
	}
	if !platformDeclared {
		return fmt.Errorf("managed-key runtime does not freeze its shipped platform to linux/amd64")
	}
	if err := inspectManagedKeyTPMRestartClosure("internal/server/dod_managed_key_runtime_test.go", runtimeSource); err != nil {
		return fmt.Errorf("managed-key TPM restart proof: %w", err)
	}
	for _, required := range []string{
		`buildBase := dodPinnedBaseImage(t, "golang:"+goVersion+"-bookworm", "golang")`,
		`runtimeBase := dodPinnedBaseImage(t, "debian:bookworm-slim", "debian")`,
		`"docker", "pull", "--platform", dodManagedKeyRuntimePlatform, taggedImage`,
		`"--format={{json .RepoDigests}}"`,
		`"docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "deploy/docker/Dockerfile.signer-hsm"`,
		`"BUILD_IMAGE="+buildBase`,
		`"BASE_IMAGE="+runtimeBase`,
		`signerImage := dodBuiltImageID(t, "trstctl-signer-hsm:dod", dodManagedKeyRuntimePlatform)`,
		`t.Setenv("DOCKER_BUILDKIT", "0")`,
		`"docker", "build", "--platform", dodManagedKeyRuntimePlatform, "-f", "tools/dodcensus/Dockerfile.managed-key-runtime"`,
		`"SIGNER_IMAGE="+signerImage`,
		`runtimeImage := dodBuiltImageID(t, "trstctl-managed-key-runtime:dod", dodManagedKeyRuntimePlatform)`,
		`dodManagedKeyPostgresImage                 = "postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229"`,
		`postgresDSN: dodManagedKeyPostgresDSN(t)`,
		`"docker", "pull", dodManagedKeyPostgresImage`,
		`fields[1] != "linux/amd64" && fields[1] != "linux/arm64"`,
		`postgresUser := strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`,
		`"--user", postgresUser`,
		`"--read-only", "--security-opt", "no-new-privileges", "--cap-drop", "ALL"`,
		`"--network", "bridge", "--pids-limit", "256", "--memory", "512m"`,
		`"-p", fmt.Sprintf("127.0.0.1:%d:5432", port)`,
		`passwordMountSource := proof.DockerHostMountSource(t, passwordFile)`,
		`row.Image != imageID || row.Config.Image != dodManagedKeyPostgresImage || row.Config.User != postgresUser || !row.State.Running`,
		`row.HostConfig.Privileged || len(row.HostConfig.CapAdd) != 0`,
		`row.HostConfig.PidMode != ""`,
		`host, err := dodRuntimeDockerHost()`,
		`"--format={{.Id}} {{.Os}}/{{.Architecture}}"`,
		`len(fields) != 2 || fields[1] != platform`,
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", runtimeImage)`,
		`"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid)`,
		`"--security-opt", "no-new-privileges", "--cap-drop", "ALL"`,
		`runtimeMountSource := proof.DockerHostMountSource(r.t, r.dir)`,
		`passwdMountSource := proof.DockerHostMountSource(r.t, passwdFile)`,
		`groupMountSource := proof.DockerHostMountSource(r.t, groupFile)`,
		`maxHandle  = uint64(0x817fffff)`,
		`"--mount", "type=bind,src="+runtimeMountSource+",dst=/runtime"`,
		`"--mount", "type=bind,src="+passwdMountSource+",dst=/etc/passwd,readonly"`,
		`"--mount", "type=bind,src="+groupMountSource+",dst=/etc/group,readonly"`,
		`os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`,
		`"--scopes", "keys:read,keys:write,keys:approve"`,
		`"--scopes", "keys:approve"`,
		`r.approvalSubjects = []string{"dod-hsm-custodian-one", "dod-hsm-custodian-two"}`,
		`denied.StatusCode != http.StatusForbidden`,
		`self.StatusCode != http.StatusForbidden`,
		`oneApproval.StatusCode != http.StatusForbidden`,
		`recorded.Action != "managedkey:"+action`,
		`recorded.Approvals != index+1`,
		`controlEndpoint = dodManagedKeyControlEndpoint(r.t, endpoint)`,
		`control["TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT"] = controlEndpoint`,
		`control["TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT"] = controlEndpoint`,
		`control["TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT"] = controlEndpoint + "/v1"`,
		`upstream, err := dodValidateManagedKeyRelayUpstream(endpoint, host)`,
		`listener, err := net.Listen("tcp4", "127.0.0.1:0")`,
		`parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() != allowedHost || parsed.Port() == ""`,
		`(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != ""`,
		`Proxy:                 nil`,
		`signerAddress := dodManagedKeySignerAddress(r.t, r.signerPort)`,
	} {
		if !strings.Contains(runtimeSource, required) {
			return fmt.Errorf("managed-key runtime omits content-addressed image dataflow %q", required)
		}
	}
	if count := strings.Count(runtimeSource, `"--platform", dodManagedKeyRuntimePlatform`); count != 4 {
		return fmt.Errorf("managed-key runtime pins linux/amd64 at %d shipped pull/build/run sites, want four", count)
	}
	if count := strings.Count(runtimeSource, `"--format={{.Id}} {{.Os}}/{{.Architecture}}"`); count != 2 {
		return fmt.Errorf("managed-key runtime has %d architecture-bound image inspections, want PostgreSQL plus signer", count)
	}
	if count := strings.Count(runtimeSource, `os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`); count != 2 {
		return fmt.Errorf("managed-key runtime has %d exclusive private NSS writers, want PostgreSQL plus signer", count)
	}
	for _, forbidden := range []string{
		`"BUILD_IMAGE=golang:`, `"BASE_IMAGE=debian:`,
		`"SIGNER_IMAGE=trstctl-signer-hsm:dod"`,
		`t.Setenv("TRSTCTL_HSM_PROOF_IMAGE", "trstctl-managed-key-runtime:dod")`,
		`"docker", "image", "inspect", "--format={{.Id}}", image`,
		`"docker", "build", "-f", "deploy/docker/Dockerfile.signer-hsm"`,
		`"docker", "build", "-f", "tools/dodcensus/Dockerfile.managed-key-runtime"`,
		`postgresDSN: serverTestPostgresDSN(t)`,
		`"postgres:16-alpine"`,
		`fmt.Sprintf("0.0.0.0:%d:5432", port)`,
		`"--network", "host"`,
		`"--privileged"`,
		`"seccomp=unconfined"`,
		`"--user", "0:0"`,
		`"-v", r.dir+":/runtime"`,
		`"unsafe"`,
		`"syscall"`,
		`ptrace`,
		`process_vm`,
		`pidfd`,
		`/proc/`,
		`SYS_PTRACE`,
		`"--cap-add"`,
		`"--pid"`,
		`"docker", "exec"`,
		`/var/run/docker.sock`,
		`nsenter`,
		`control["TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT"] = endpoint`,
		`control["TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT"] = endpoint`,
		`control["TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT"] = endpoint + "/v1"`,
	} {
		if strings.Contains(runtimeSource, forbidden) {
			return fmt.Errorf("managed-key runtime retains mutable image input %q", forbidden)
		}
	}

	entrypointSource, err := read("tools/dodcensus/substrates/managed_key_signer_entrypoint.sh")
	if err != nil {
		return err
	}
	if count := strings.Count(entrypointSource, "--seccomp action=none"); count != 1 {
		return fmt.Errorf("managed-key signer disables swtpm internal seccomp %d times, want exactly once for Docker-seccomp compatibility", count)
	}

	substrateSource, err := read("tools/dodcensus/substrates/managed_keys.py")
	if err != nil {
		return err
	}
	for _, required := range []string{
		"image = required_image_id()",
		`"docker", "run", "--rm", "--platform", "linux/amd64"`,
	} {
		if !strings.Contains(substrateSource, required) {
			return fmt.Errorf("managed-key substrate omits image-ID receipt binding %q", required)
		}
	}
	if strings.Contains(substrateSource, `"docker", "run", "--rm", "--name"`) {
		return fmt.Errorf("managed-key substrate retains an unpinned inner runtime platform")
	}
	if count := strings.Count(substrateSource, `"runtime_identity": image`); count != 2 {
		return fmt.Errorf("managed-key substrate image-ID binding appears %d times, want READY and final receipt", count)
	}
	return nil
}

type managedKeyRuntimeSyntax struct {
	functions map[string]*ast.FuncDecl
	constants map[string]string
}

type managedKeyExprMatcher func(ast.Expr) bool

func inspectManagedKeyTPMRestartClosure(filename, source string) error {
	syntax, err := parseManagedKeyRuntimeSyntax(filename, source)
	if err != nil {
		return err
	}
	if syntax.constants["dodManagedKeyRestartProbe"] != "post-restart TPM custody signature proof" {
		return fmt.Errorf("restart probe is not the fixed non-empty custody challenge")
	}
	checks := []struct {
		name string
		fn   func(*managedKeyRuntimeSyntax) error
	}{
		{"production TPM entry", inspectManagedKeyTPMEntry},
		{"destructive-action dual control", inspectManagedKeyDualControl},
		{"provider restart order", inspectManagedKeyProviderRestartOrder},
		{"signer stop", inspectManagedKeySignerStop},
		{"signer restart", inspectManagedKeySignerRestart},
		{"public witness", inspectManagedKeyPublicWitnessValidation},
		{"post-restart signature", inspectManagedKeyPostRestartSignature},
	}
	for _, check := range checks {
		if err := check.fn(syntax); err != nil {
			return fmt.Errorf("%s: %w", check.name, err)
		}
	}
	return nil
}

func inspectManagedKeyDualControl(syntax *managedKeyRuntimeSyntax) error {
	provider, err := managedKeyRequiredFunction(syntax, "dodRunManagedKeyProvider")
	if err != nil {
		return err
	}
	rotateApproval := managedKeyFindStatement(provider.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "runtime.approveManagedKeyAction",
			managedKeyPathArg("generated.KeyID"), managedKeyStringArg("rotate"))
	})
	stop := managedKeyFindStatement(provider.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"preRestartTPM"}, "runtime.stopSigner", managedKeyPathArg("generated"))
	})
	revokeApproval := managedKeyFindStatement(provider.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "runtime.approveManagedKeyAction",
			managedKeyPathArg("rotated.KeyID"), managedKeyStringArg("revoke"))
	})
	revoke := managedKeyFindStatement(provider.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignsName(statement, "revoked")
	})
	zeroizeApproval := managedKeyFindStatement(provider.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "runtime.approveManagedKeyAction",
			managedKeyPathArg("rotated.KeyID"), managedKeyStringArg("zeroize"))
	})
	zeroize := managedKeyFindStatement(provider.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignsName(statement, "zeroized")
	})
	if !managedKeyOrdered(rotateApproval, stop, revokeApproval, revoke, zeroizeApproval, zeroize) {
		return fmt.Errorf("want rotate approval -> rotate -> revoke approval -> revoke -> zeroize approval -> zeroize, got statement indexes %d,%d,%d,%d,%d,%d",
			rotateApproval, stop, revokeApproval, revoke, zeroizeApproval, zeroize)
	}
	if managedKeyUnconditionallyExits(provider.Body.List[:rotateApproval]) ||
		managedKeyUnconditionallyExits(provider.Body.List[rotateApproval+1:stop]) ||
		managedKeyUnconditionallyExits(provider.Body.List[stop+1:revokeApproval]) ||
		managedKeyUnconditionallyExits(provider.Body.List[revokeApproval+1:revoke]) ||
		managedKeyUnconditionallyExits(provider.Body.List[revoke+1:zeroizeApproval]) ||
		managedKeyUnconditionallyExits(provider.Body.List[zeroizeApproval+1:zeroize]) {
		return fmt.Errorf("a destructive managed-key approval is unreachable from its provider action")
	}

	helper, err := managedKeyRequiredFunction(syntax, "dodManagedKeyRuntime.approveManagedKeyAction")
	if err != nil {
		return err
	}
	absent := make([]int, 0, 3)
	for index, statement := range helper.Body.List {
		if managedKeyExpressionCall(statement, "r.requireManagedKeyCommandAbsent", managedKeyPathArg("action")) {
			absent = append(absent, index)
		}
	}
	denied := managedKeyFindStatement(helper.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"denied"}, "dodManagedKeyRequest",
			managedKeyPathArg("r"), managedKeyPathArg("http.MethodPost"), managedKeyPathArg("path"),
			managedKeyPathArg("action"), managedKeyAnyArg())
	})
	self := managedKeyFindStatement(helper.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"self"}, "dodManagedKeyRequest",
			managedKeyPathArg("r"), managedKeyPathArg("http.MethodPost"),
			managedKeyStringArg("/api/v1/managed-keys/approvals"), managedKeyAnyArg(), managedKeyPathArg("approval"))
	})
	approvalLoop := managedKeyFindStatement(helper.Body, func(statement ast.Stmt) bool {
		rangeStatement, ok := statement.(*ast.RangeStmt)
		return ok && managedKeyPathArg("index")(rangeStatement.Key) && managedKeyPathArg("token")(rangeStatement.Value) &&
			managedKeyPathArg("r.approvalTokens")(rangeStatement.X)
	})
	if len(absent) != 3 || !managedKeyOrdered(absent[0], denied, absent[1], self, approvalLoop, absent[2]) {
		return fmt.Errorf("want no-command -> zero-approval denial -> no-command -> self denial -> two approvals -> no-command, got absent=%v denial=%d self=%d loop=%d",
			absent, denied, self, approvalLoop)
	}
	if managedKeyUnconditionallyExits(helper.Body.List[:absent[0]]) ||
		managedKeyUnconditionallyExits(helper.Body.List[absent[0]+1:denied]) ||
		managedKeyUnconditionallyExits(helper.Body.List[denied+1:absent[1]]) ||
		managedKeyUnconditionallyExits(helper.Body.List[absent[1]+1:self]) ||
		managedKeyUnconditionallyExits(helper.Body.List[self+1:approvalLoop]) ||
		managedKeyUnconditionallyExits(helper.Body.List[approvalLoop+1:absent[2]]) {
		return fmt.Errorf("managed-key dual-control proof chain contains an unconditional exit")
	}

	loop := helper.Body.List[approvalLoop].(*ast.RangeStmt).Body
	record := managedKeyFindStatement(loop, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"response"}, "dodManagedKeyRequestWithToken",
			managedKeyPathArg("r"), managedKeyPathArg("token"), managedKeyPathArg("http.MethodPost"),
			managedKeyStringArg("/api/v1/managed-keys/approvals"), managedKeyAnyArg(), managedKeyPathArg("approval"))
	})
	oneApproval := managedKeyFindStatement(loop, func(statement ast.Stmt) bool {
		selection, ok := statement.(*ast.IfStmt)
		if !ok || !managedKeyCallFreeEquality(selection.Cond, managedKeyPathArg("index"), managedKeyIntArg(0)) {
			return false
		}
		deniedAgain := managedKeyFindStatement(selection.Body, func(statement ast.Stmt) bool {
			return managedKeyAssignedCall(statement, []string{"oneApproval"}, "dodManagedKeyRequest",
				managedKeyPathArg("r"), managedKeyPathArg("http.MethodPost"), managedKeyPathArg("path"),
				managedKeyPathArg("action"), managedKeyAnyArg())
		})
		noCommand := managedKeyFindStatement(selection.Body, func(statement ast.Stmt) bool {
			return managedKeyExpressionCall(statement, "r.requireManagedKeyCommandAbsent", managedKeyPathArg("action"))
		})
		return managedKeyOrdered(deniedAgain, noCommand) &&
			!managedKeyUnconditionallyExits(selection.Body.List[:deniedAgain]) &&
			!managedKeyUnconditionallyExits(selection.Body.List[deniedAgain+1:noCommand])
	})
	if !managedKeyOrdered(record, oneApproval) {
		return fmt.Errorf("approval loop does not record one custodian then prove the same command remains denied; indexes %d,%d", record, oneApproval)
	}
	return nil
}

func parseManagedKeyRuntimeSyntax(filename, source string) (*managedKeyRuntimeSyntax, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		return nil, fmt.Errorf("parse runtime proof: %w", err)
	}
	syntax := &managedKeyRuntimeSyntax{functions: map[string]*ast.FuncDecl{}, constants: map[string]string{}}
	for _, declaration := range parsed.Decls {
		switch value := declaration.(type) {
		case *ast.FuncDecl:
			key, keyErr := managedKeyFunctionKey(value)
			if keyErr != nil {
				return nil, keyErr
			}
			if syntax.functions[key] != nil {
				return nil, fmt.Errorf("runtime proof declares %s more than once", key)
			}
			syntax.functions[key] = value
		case *ast.GenDecl:
			if value.Tok == token.CONST {
				managedKeyCollectConstants(syntax.constants, value)
			}
		}
	}
	return syntax, nil
}

func managedKeyFunctionKey(function *ast.FuncDecl) (string, error) {
	if function.Recv == nil {
		return function.Name.Name, nil
	}
	if len(function.Recv.List) != 1 {
		return "", fmt.Errorf("runtime proof function %s has an ambiguous receiver", function.Name.Name)
	}
	receiver := function.Recv.List[0].Type
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver = pointer.X
	}
	identifier, ok := receiver.(*ast.Ident)
	if !ok {
		return "", fmt.Errorf("runtime proof function %s has an unsupported receiver", function.Name.Name)
	}
	return identifier.Name + "." + function.Name.Name, nil
}

func managedKeyCollectConstants(constants map[string]string, declaration *ast.GenDecl) {
	for _, specification := range declaration.Specs {
		value, ok := specification.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for index, name := range value.Names {
			if index >= len(value.Values) {
				continue
			}
			literal, ok := value.Values[index].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			if decoded, err := strconv.Unquote(literal.Value); err == nil {
				constants[name.Name] = decoded
			}
		}
	}
}

func inspectManagedKeyTPMEntry(syntax *managedKeyRuntimeSyntax) error {
	function, err := managedKeyRequiredFunction(syntax, "TestDODManagedKeyProductionAssembly")
	if err != nil {
		return err
	}
	for _, statement := range function.Body.List {
		selection, ok := statement.(*ast.IfStmt)
		if !ok || !managedKeyOnlySelection(selection.Cond, "hsm_kms.tpm2") {
			continue
		}
		index := managedKeyFindStatement(selection.Body, func(statement ast.Stmt) bool {
			return managedKeyExpressionCall(statement, "dodRunManagedKeyProvider",
				managedKeyPathArg("t"), managedKeyPathArg("artifacts"), managedKeyStringArg("hsm_kms.tpm2"),
				managedKeyPathArg("config.ManagedKeyProviderTPM2"), managedKeyPathArg("tpmEntry"),
				managedKeyZeroArgCall("tpmEntry.Endpoint"),
			)
		})
		if index >= 0 && !managedKeyUnconditionallyExits(selection.Body.List[:index]) {
			return nil
		}
	}
	return fmt.Errorf("production test does not reach dodRunManagedKeyProvider with the TPM2 provider")
}

func inspectManagedKeyProviderRestartOrder(syntax *managedKeyRuntimeSyntax) error {
	function, err := managedKeyRequiredFunction(syntax, "dodRunManagedKeyProvider")
	if err != nil {
		return err
	}
	stop := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"preRestartTPM"}, "runtime.stopSigner", managedKeyPathArg("generated"))
	})
	rotate := managedKeyFindStatement(function.Body, managedKeyRotationLaunch)
	restart := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "runtime.restartSigner", managedKeyPathArg("generated"), managedKeyPathArg("preRestartTPM"))
	})
	completed := managedKeyFindStatement(function.Body, managedKeyRotationCompletion)
	if !managedKeyOrdered(stop, rotate, restart, completed) {
		return fmt.Errorf("want stopSigner -> queued rotation -> restartSigner -> rotation result, got statement indexes %d,%d,%d,%d", stop, rotate, restart, completed)
	}
	if managedKeyUnconditionallyExits(function.Body.List[:stop]) || managedKeyUnconditionallyExits(function.Body.List[stop+1:completed]) {
		return fmt.Errorf("restart chain has an unconditional exit before the rotation result")
	}
	return nil
}

func inspectManagedKeySignerStop(syntax *managedKeyRuntimeSyntax) error {
	function, err := managedKeyRequiredFunction(syntax, "dodManagedKeyRuntime.stopSigner")
	if err != nil {
		return err
	}
	tpmBranch := managedKeyFindTPMBranch(function.Body)
	stop := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "dodRunCommand", managedKeyPathArg("r.t"),
			managedKeyStringArg("stop managed-key signer for outbox redelivery"), managedKeyStringArg("docker"),
			managedKeyStringArg("stop"), managedKeyStringArg("-t"), managedKeyStringArg("2"), managedKeyPathArg("r.containerName"))
	})
	if tpmBranch < 0 || stop <= tpmBranch {
		return fmt.Errorf("TPM branch is not followed by docker stop")
	}
	branch := function.Body.List[tpmBranch].(*ast.IfStmt).Body
	read := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"observed", "ok"}, "r.readTPMPublicWitness",
			managedKeyPathArg("key.KeyID"), managedKeyStringArg("before-restart"))
	})
	validate := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyIfInitErrorGuard(statement, "dodValidateTPMPublicSurvival", managedKeyPathArg("key.PublicDER"),
			managedKeyPathArg("observed"), managedKeyPathArg("observed"))
	})
	remember := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyAssignment(statement, []string{"before"}, []managedKeyExprMatcher{managedKeyAddressArg("observed")})
	})
	shutdown := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "r.dockerExecTPM", managedKeyPathArg("true"),
			managedKeyStringArg("shutdown TPM emulator before signer restart"), managedKeyStringArg("tpm2_shutdown"), managedKeyStringArg("-c"))
	})
	if !managedKeyOrdered(read, validate, remember, shutdown) {
		return fmt.Errorf("want read witness -> validate -> retain witness -> graceful TPM shutdown, got statement indexes %d,%d,%d,%d", read, validate, remember, shutdown)
	}
	if managedKeyUnconditionallyExits(function.Body.List[:tpmBranch]) || managedKeyUnconditionallyExits(branch.List[:read]) ||
		managedKeyUnconditionallyExits(branch.List[read+1:shutdown]) || managedKeyUnconditionallyExits(function.Body.List[tpmBranch+1:stop]) {
		return fmt.Errorf("graceful TPM shutdown cannot reach docker stop")
	}
	return nil
}

func inspectManagedKeySignerRestart(syntax *managedKeyRuntimeSyntax) error {
	function, err := managedKeyRequiredFunction(syntax, "dodManagedKeyRuntime.restartSigner")
	if err != nil {
		return err
	}
	start := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "dodRunCommand", managedKeyPathArg("r.t"),
			managedKeyStringArg("restart managed-key signer"), managedKeyStringArg("docker"), managedKeyStringArg("start"), managedKeyPathArg("r.containerName"))
	})
	wait := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "r.waitSigner")
	})
	tpmBranch := managedKeyFindTPMBranch(function.Body)
	if !managedKeyOrdered(start, wait, tpmBranch) {
		return fmt.Errorf("want docker start -> waitSigner -> TPM validation, got statement indexes %d,%d,%d", start, wait, tpmBranch)
	}
	branch := function.Body.List[tpmBranch].(*ast.IfStmt).Body
	read := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"after", "ok"}, "r.readTPMPublicWitness",
			managedKeyPathArg("key.KeyID"), managedKeyStringArg("after-restart"))
	})
	validate := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyIfInitErrorGuard(statement, "dodValidateTPMPublicSurvival", managedKeyPathArg("key.PublicDER"),
			managedKeyDereferenceArg("before"), managedKeyPathArg("after"))
	})
	sign := managedKeyFindStatement(branch, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "r.assertTPMPostRestartSignature", managedKeyPathArg("key"))
	})
	if !managedKeyOrdered(read, validate, sign) {
		return fmt.Errorf("want post-restart witness -> DER/Name validation -> exact-key signature, got statement indexes %d,%d,%d", read, validate, sign)
	}
	if managedKeyUnconditionallyExits(function.Body.List[:start]) || managedKeyUnconditionallyExits(function.Body.List[start+1:tpmBranch]) ||
		managedKeyUnconditionallyExits(branch.List[:read]) || managedKeyUnconditionallyExits(branch.List[read+1:sign]) {
		return fmt.Errorf("signer restart cannot reach the post-restart signature")
	}
	return nil
}

func inspectManagedKeyPublicWitnessValidation(syntax *managedKeyRuntimeSyntax) error {
	function, err := managedKeyRequiredFunction(syntax, "dodValidateTPMPublicSurvival")
	if err != nil {
		return err
	}
	wants := [][2]string{
		{"before.PublicDER", "generatedDER"},
		{"after.PublicDER", "before.PublicDER"},
		{"after.Name", "before.Name"},
	}
	previous := -1
	for _, want := range wants {
		index := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
			selection, ok := statement.(*ast.IfStmt)
			return ok && managedKeyNegatedCall(selection.Cond, "bytes.Equal", managedKeyPathArg(want[0]), managedKeyPathArg(want[1])) && managedKeyBlockReturnsError(selection.Body)
		})
		if index <= previous {
			return fmt.Errorf("missing ordered failing bytes.Equal(%s, %s) guard", want[0], want[1])
		}
		if managedKeyUnconditionallyExits(function.Body.List[previous+1 : index]) {
			return fmt.Errorf("bytes.Equal(%s, %s) guard is unreachable", want[0], want[1])
		}
		previous = index
	}
	return nil
}

func inspectManagedKeyPostRestartSignature(syntax *managedKeyRuntimeSyntax) error {
	function, err := managedKeyRequiredFunction(syntax, "dodManagedKeyRuntime.assertTPMPostRestartSignature")
	if err != nil {
		return err
	}
	requireKey := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "r.requireHardwareKeyID", managedKeyPathArg("key.KeyID"))
	})
	write := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyIfInitErrorGuard(statement, "os.WriteFile", managedKeyPathArg("messagePath"),
			managedKeyByteSliceArg("dodManagedKeyRestartProbe"), managedKeyAnyArg())
	})
	sign := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyExpressionCall(statement, "r.dockerExecTPM", managedKeyPathArg("true"),
			managedKeyStringArg("sign with exact TPM key after restart"), managedKeyStringArg("tpm2_sign"),
			managedKeyStringArg("-c"), managedKeyPathArg("key.KeyID"), managedKeyStringArg("-g"),
			managedKeyStringArg("sha256"), managedKeyStringArg("-f"), managedKeyStringArg("plain"),
			managedKeyStringArg("-o"), managedKeyStringArg("/runtime/tpm-restart-signature"),
			managedKeyStringArg("/runtime/tpm-restart-message"))
	})
	read := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyAssignedCall(statement, []string{"signature", "err"}, "os.ReadFile", managedKeyPathArg("signaturePath"))
	})
	verify := managedKeyFindStatement(function.Body, func(statement ast.Stmt) bool {
		return managedKeyIfInitErrorGuard(statement, "crypto.VerifyMessage", managedKeyPathArg("key.PublicDER"),
			managedKeyByteSliceArg("dodManagedKeyRestartProbe"), managedKeyPathArg("signature"))
	})
	if !managedKeyOrdered(requireKey, write, sign, read, verify) {
		return fmt.Errorf("want exact key -> fixed probe -> TPM sign -> signature read -> API-public-key verify, got statement indexes %d,%d,%d,%d,%d", requireKey, write, sign, read, verify)
	}
	if managedKeyUnconditionallyExits(function.Body.List[:requireKey]) || managedKeyUnconditionallyExits(function.Body.List[requireKey+1:verify]) {
		return fmt.Errorf("post-restart exact-key signature chain has an unconditional exit")
	}
	return nil
}

func managedKeyRequiredFunction(syntax *managedKeyRuntimeSyntax, name string) (*ast.FuncDecl, error) {
	function := syntax.functions[name]
	if function == nil || function.Body == nil {
		return nil, fmt.Errorf("reachable function %s is absent", name)
	}
	return function, nil
}

func managedKeyFindTPMBranch(block *ast.BlockStmt) int {
	return managedKeyFindStatement(block, func(statement ast.Stmt) bool {
		selection, ok := statement.(*ast.IfStmt)
		return ok && managedKeyCallFreeEquality(selection.Cond, managedKeyPathArg("r.provider"), managedKeyPathArg("config.ManagedKeyProviderTPM2"))
	})
}

func managedKeyFindStatement(block *ast.BlockStmt, match func(ast.Stmt) bool) int {
	for index, statement := range block.List {
		if match(statement) {
			return index
		}
	}
	return -1
}

func managedKeyOrdered(indexes ...int) bool {
	for index, value := range indexes {
		if value < 0 || index > 0 && value <= indexes[index-1] { // #nosec G602 -- fixed-shape data inside a developer tool (CWE-118)
			return false
		}
	}
	return true
}

func managedKeyUnconditionallyExits(statements []ast.Stmt) bool {
	for _, statement := range statements {
		if managedKeyStatementUnconditionallyExits(statement) {
			return true
		}
	}
	return false
}

func managedKeyStatementUnconditionallyExits(statement ast.Stmt) bool {
	switch value := statement.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return value.Tok == token.GOTO || value.Tok == token.FALLTHROUGH
	case *ast.ExprStmt:
		call, ok := value.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		name := managedKeyExpressionPath(call.Fun)
		return name == "panic" || name == "os.Exit" || name == "goruntime.Goexit" ||
			strings.HasSuffix(name, ".Fatal") || strings.HasSuffix(name, ".Fatalf") || strings.HasSuffix(name, ".FailNow")
	case *ast.BlockStmt:
		return managedKeyUnconditionallyExits(value.List)
	case *ast.IfStmt:
		if managedKeyBooleanLiteral(value.Cond, true) {
			return managedKeyUnconditionallyExits(value.Body.List)
		}
		return value.Else != nil && managedKeyUnconditionallyExits(value.Body.List) && managedKeyElseUnconditionallyExits(value.Else)
	case *ast.ForStmt:
		return value.Cond == nil && !managedKeyContainsBreak(value.Body)
	}
	return false
}

func managedKeyElseUnconditionallyExits(statement ast.Stmt) bool {
	if block, ok := statement.(*ast.BlockStmt); ok {
		return managedKeyUnconditionallyExits(block.List)
	}
	return managedKeyStatementUnconditionallyExits(statement)
}

func managedKeyBooleanLiteral(expression ast.Expr, want bool) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == strconv.FormatBool(want)
}

func managedKeyContainsBreak(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(node ast.Node) bool {
		if branch, ok := node.(*ast.BranchStmt); ok && branch.Tok == token.BREAK {
			found = true
			return false
		}
		return !found
	})
	return found
}

func managedKeyOnlySelection(expression ast.Expr, entryID string) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.LOR {
		return false
	}
	empty := func(value ast.Expr) bool {
		return managedKeyCallFreeEquality(value, managedKeyPathArg("only"), managedKeyStringArg(""))
	}
	selected := func(value ast.Expr) bool {
		return managedKeyCallFreeEquality(value, managedKeyPathArg("only"), managedKeyStringArg(entryID))
	}
	return empty(binary.X) && selected(binary.Y) || selected(binary.X) && empty(binary.Y)
}

func managedKeyRotationLaunch(statement ast.Stmt) bool {
	launch, ok := statement.(*ast.GoStmt)
	if !ok || len(launch.Call.Args) != 0 {
		return false
	}
	literal, ok := launch.Call.Fun.(*ast.FuncLit)
	if !ok || literal.Body == nil {
		return false
	}
	return managedKeyFindStatement(literal.Body, func(statement ast.Stmt) bool {
		send, ok := statement.(*ast.SendStmt)
		return ok && managedKeyPathArg("rotateResult")(send.Chan) && managedKeyCallMatches(send.Value, "dodManagedKeyRequest",
			managedKeyPathArg("runtime"), managedKeyPathArg("http.MethodPost"), managedKeyStringArg("/api/v1/managed-keys/rotate"),
			managedKeyStringArg("rotate"), managedKeyAnyArg())
	}) >= 0
}

func managedKeyRotationCompletion(statement ast.Stmt) bool {
	selection, ok := statement.(*ast.SelectStmt)
	if !ok {
		return false
	}
	for _, statement := range selection.Body.List {
		clause, ok := statement.(*ast.CommClause)
		if !ok {
			continue
		}
		assignment, ok := clause.Comm.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || !managedKeyPathArg("rotateResponse")(assignment.Lhs[0]) {
			continue
		}
		receive, ok := assignment.Rhs[0].(*ast.UnaryExpr)
		if ok && receive.Op == token.ARROW && managedKeyPathArg("rotateResult")(receive.X) {
			return true
		}
	}
	return false
}

func managedKeyExpressionCall(statement ast.Stmt, name string, arguments ...managedKeyExprMatcher) bool {
	expression, ok := statement.(*ast.ExprStmt)
	return ok && managedKeyCallMatches(expression.X, name, arguments...)
}

func managedKeyAssignedCall(statement ast.Stmt, left []string, name string, arguments ...managedKeyExprMatcher) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != len(left) || len(assignment.Rhs) != 1 {
		return false
	}
	for index, want := range left {
		if !managedKeyPathArg(want)(assignment.Lhs[index]) {
			return false
		}
	}
	return managedKeyCallMatches(assignment.Rhs[0], name, arguments...)
}

func managedKeyAssignsName(statement ast.Stmt, name string) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	return ok && len(assignment.Lhs) > 0 && managedKeyPathArg(name)(assignment.Lhs[0])
}

func managedKeyAssignment(statement ast.Stmt, left []string, right []managedKeyExprMatcher) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != len(left) || len(assignment.Rhs) != len(right) {
		return false
	}
	for index, want := range left {
		if !managedKeyPathArg(want)(assignment.Lhs[index]) || !right[index](assignment.Rhs[index]) {
			return false
		}
	}
	return true
}

func managedKeyIfInitErrorGuard(statement ast.Stmt, name string, arguments ...managedKeyExprMatcher) bool {
	selection, ok := statement.(*ast.IfStmt)
	if !ok || selection.Init == nil {
		return false
	}
	assignment, ok := selection.Init.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || !managedKeyPathArg("err")(assignment.Lhs[0]) ||
		!managedKeyCallMatches(assignment.Rhs[0], name, arguments...) {
		return false
	}
	return managedKeyCallFreeInequality(selection.Cond, managedKeyPathArg("err"), managedKeyPathArg("nil")) &&
		managedKeyUnconditionallyExits(selection.Body.List)
}

func managedKeyNegatedCall(expression ast.Expr, name string, arguments ...managedKeyExprMatcher) bool {
	negation, ok := expression.(*ast.UnaryExpr)
	return ok && negation.Op == token.NOT && managedKeyCallMatches(negation.X, name, arguments...)
}

func managedKeyCallMatches(expression ast.Expr, name string, arguments ...managedKeyExprMatcher) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || managedKeyExpressionPath(call.Fun) != name || len(call.Args) != len(arguments) {
		return false
	}
	for index, match := range arguments {
		if !match(call.Args[index]) {
			return false
		}
	}
	return true
}

func managedKeyCallFreeEquality(expression ast.Expr, left, right managedKeyExprMatcher) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.EQL {
		return false
	}
	return left(binary.X) && right(binary.Y) || right(binary.X) && left(binary.Y)
}

func managedKeyCallFreeInequality(expression ast.Expr, left, right managedKeyExprMatcher) bool {
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return false
	}
	return left(binary.X) && right(binary.Y) || right(binary.X) && left(binary.Y)
}

func managedKeyBlockReturnsError(block *ast.BlockStmt) bool {
	if len(block.List) != 1 {
		return false
	}
	returned, ok := block.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	call, ok := returned.Results[0].(*ast.CallExpr)
	return ok && managedKeyExpressionPath(call.Fun) == "fmt.Errorf" && len(call.Args) > 0
}

func managedKeyPathArg(want string) managedKeyExprMatcher {
	return func(expression ast.Expr) bool { return managedKeyExpressionPath(expression) == want }
}

func managedKeyStringArg(want string) managedKeyExprMatcher {
	return func(expression ast.Expr) bool {
		literal, ok := expression.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return false
		}
		value, err := strconv.Unquote(literal.Value)
		return err == nil && value == want
	}
}

func managedKeyIntArg(want int64) managedKeyExprMatcher {
	return func(expression ast.Expr) bool {
		literal, ok := expression.(*ast.BasicLit)
		if !ok || literal.Kind != token.INT {
			return false
		}
		value, err := strconv.ParseInt(literal.Value, 0, 64)
		return err == nil && value == want
	}
}

func managedKeyAddressArg(want string) managedKeyExprMatcher {
	return func(expression ast.Expr) bool {
		address, ok := expression.(*ast.UnaryExpr)
		return ok && address.Op == token.AND && managedKeyExpressionPath(address.X) == want
	}
}

func managedKeyDereferenceArg(want string) managedKeyExprMatcher {
	return func(expression ast.Expr) bool {
		dereference, ok := expression.(*ast.StarExpr)
		return ok && managedKeyExpressionPath(dereference.X) == want
	}
}

func managedKeyByteSliceArg(want string) managedKeyExprMatcher {
	return func(expression ast.Expr) bool {
		conversion, ok := expression.(*ast.CallExpr)
		if !ok || len(conversion.Args) != 1 || managedKeyExpressionPath(conversion.Args[0]) != want {
			return false
		}
		slice, ok := conversion.Fun.(*ast.ArrayType)
		return ok && slice.Len == nil && managedKeyExpressionPath(slice.Elt) == "byte"
	}
}

func managedKeyAnyArg() managedKeyExprMatcher {
	return func(ast.Expr) bool { return true }
}

func managedKeyZeroArgCall(want string) managedKeyExprMatcher {
	return func(expression ast.Expr) bool {
		call, ok := expression.(*ast.CallExpr)
		return ok && len(call.Args) == 0 && managedKeyExpressionPath(call.Fun) == want
	}
}

func managedKeyExpressionPath(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		prefix := managedKeyExpressionPath(value.X)
		if prefix == "" {
			return ""
		}
		return prefix + "." + value.Sel.Name
	case *ast.ParenExpr:
		return managedKeyExpressionPath(value.X)
	}
	return ""
}

func requireNoDefaultDockerArg(source, name string) error {
	found := false
	for _, instruction := range dockerInstructions(source) {
		if !strings.HasPrefix(strings.ToUpper(instruction), "ARG ") {
			continue
		}
		declaration := strings.TrimSpace(instruction[len("ARG "):])
		if declaration == name {
			found = true
		}
		if strings.HasPrefix(declaration, name+"=") {
			return fmt.Errorf("ARG %s has a default and can silently accept a mutable reference", name)
		}
	}
	if !found {
		return fmt.Errorf("ARG %s is not required without a default", name)
	}
	return nil
}

func requirePinnedAptSnapshot(source string) error {
	instructions := dockerInstructions(source)
	aptRuns := 0
	for _, instruction := range instructions {
		if !strings.HasPrefix(strings.ToUpper(instruction), "RUN ") || !strings.Contains(instruction, "apt-get") {
			continue
		}
		aptRuns++
		for _, required := range []string{
			"snapshot.debian.org/archive/debian/20260701T000000Z",
			"snapshot.debian.org/archive/debian-security/20260701T000000Z",
			"check-valid-until=no",
			"rm -f /etc/apt/sources.list.d/debian.sources",
		} {
			if !strings.Contains(instruction, required) {
				return fmt.Errorf("apt RUN omits immutable repository input %q", required)
			}
		}
		if strings.Contains(instruction, "deb.debian.org") || strings.Contains(instruction, "security.debian.org") {
			return fmt.Errorf("apt RUN retains a moving Debian repository")
		}
	}
	if aptRuns != 1 {
		return fmt.Errorf("dockerfile has %d apt RUN instructions, want one fully pinned transaction", aptRuns)
	}
	return nil
}
