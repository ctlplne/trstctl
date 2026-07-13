// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	maxRuntimeHelpers        = 64
	maxRuntimeDepth          = 8
	maxReceiptBytes          = 1 << 20
	dodProofBuildTag         = "trstctl_dodproof"
	dodReceiptTestTimeoutArg = "-timeout=30m"
)

var verifierConstructor = map[string]string{
	"external-write":       "ExternalWrite",
	"credential-lifecycle": "CredentialLifecycle",
	"ca-issue-chain":       "CAIssueChain",
	"tls-deploy":           "TLSDeploy",
	"notification":         "Notification",
	"hsm-sign":             "HSMSign",
	"interop":              "IndependentInterop",
}

var requiredObservations = map[string][]string{
	"external-write":       {"destination_digest", "write_digest", "readback_digest", "execution_receipt_digest"},
	"credential-lifecycle": {"issued_digest", "rotated_digest", "revocation_receipt_digest", "export_digest", "execution_receipt_digest"},
	"ca-issue-chain":       {"leaf_digest", "chain_digest", "verification_digest", "execution_receipt_digest"},
	"tls-deploy":           {"deployed_digest", "config_digest", "reload_receipt_digest", "readback_digest", "execution_receipt_digest"},
	"notification":         {"contract_digest", "acceptance_digest", "delivery_digest", "execution_receipt_digest"},
	"hsm-sign":             {"signature_digest", "public_key_digest", "export_denial_digest", "execution_receipt_digest"},
	"interop":              {"client_identity_digest", "transcript_digest", "independent_verifier_digest", "execution_receipt_digest"},
}

func validateSubstrate(where string, substrate Substrate) error {
	if _, ok := verifierConstructor[substrate.Verifier]; !ok {
		return fmt.Errorf("%s.verifier %q is not a closed verifier", where, substrate.Verifier)
	}
	switch substrate.Kind {
	case "vendor-emulator", "testcontainer", "real-system", "independent-interop":
	default:
		return fmt.Errorf("%s.kind %q is not an accepted out-of-process substrate", where, substrate.Kind)
	}
	switch substrate.Execution {
	case "command", "container", "remote":
	default:
		return fmt.Errorf("%s.execution %q is not command, container, or remote", where, substrate.Execution)
	}
	if substrate.Identity == "" || !strings.Contains(substrate.Identity, "@sha256:") || !pinnedImagePattern.MatchString(substrate.Identity) {
		return fmt.Errorf("%s.identity %q is not pinned with @sha256:<64 hex>", where, substrate.Identity)
	}
	if substrate.ContractFile == "" || filepath.IsAbs(substrate.ContractFile) || strings.Contains(substrate.ContractFile, "..") || strings.HasSuffix(substrate.ContractFile, "_test.go") {
		return fmt.Errorf("%s.contract_file must be a committed non-_test repo-relative contract", where)
	}
	if !digestPattern.MatchString(substrate.ContractSHA256) {
		return fmt.Errorf("%s.contract_sha256 must be sha256:<64 lowercase hex>", where)
	}
	switch substrate.Kind {
	case "vendor-emulator":
		if substrate.Execution != "command" && substrate.Execution != "container" {
			return fmt.Errorf("%s vendor emulator must execute out of process by command or container", where)
		}
	case "testcontainer":
		if substrate.Execution != "container" || !pinnedImagePattern.MatchString(substrate.Image) {
			return fmt.Errorf("%s testcontainer must name an image pinned with @sha256", where)
		}
	case "real-system", "independent-interop":
		if substrate.Execution != "remote" || len(substrate.Command) == 0 || !digestPattern.MatchString(substrate.CommandSHA256) {
			return fmt.Errorf("%s real/interop substrate must use a digest-pinned out-of-process verifier command against the remote identity", where)
		}
	}
	if substrate.Execution == "command" || substrate.Execution == "remote" {
		if len(substrate.Command) == 0 || filepath.IsAbs(substrate.Command[0]) || strings.Contains(substrate.Command[0], "..") || strings.HasSuffix(substrate.Command[0], "_test.go") {
			return fmt.Errorf("%s command substrate must name a committed repo-relative executable", where)
		}
	}
	if substrate.Execution == "command" {
		if err := validateIdentityFiles(where, substrate.Command[0], substrate.IdentityFiles); err != nil {
			return err
		}
	} else if len(substrate.IdentityFiles) != 0 {
		return fmt.Errorf("%s.identity_files is only valid for command substrates", where)
	}
	if substrate.Execution == "container" && !pinnedImagePattern.MatchString(substrate.Image) {
		return fmt.Errorf("%s container image is not pinned with @sha256", where)
	}
	return nil
}

func inspectSubstrate(repo, id string, substrate Substrate) checkEvidence {
	evidence := checkEvidence{Required: []string{id, substrate.Identity, substrate.ContractFile, substrate.ContractSHA256, substrate.Execution, substrate.Verifier}}
	evidence.Required = append(evidence.Required, substrate.IdentityFiles...)
	if err := validateSubstrate("substrate "+id, substrate); err != nil {
		evidence.Detail = err.Error()
		return evidence
	}
	if id == "managed_key_custody" {
		if err := inspectManagedKeyRuntimeClosure(repo, substrate); err != nil {
			evidence.Detail = "managed-key base/package/runtime identity closure: " + err.Error()
			return evidence
		}
	}
	contractPath, err := safeRepoPath(repo, substrate.ContractFile)
	if err != nil {
		evidence.Detail = "contract path: " + err.Error()
		return evidence
	}
	contract, err := os.ReadFile(contractPath)
	if err != nil {
		evidence.Detail = "read substrate contract: " + err.Error()
		return evidence
	}
	actual := "sha256:" + internalcrypto.SHA256Hex(contract)
	if actual != substrate.ContractSHA256 {
		evidence.Detail = fmt.Sprintf("substrate contract digest = %s, want %s", actual, substrate.ContractSHA256)
		return evidence
	}
	if substrate.Execution == "command" || substrate.Execution == "remote" {
		commandPath, pathErr := safeRepoPath(repo, substrate.Command[0])
		if pathErr != nil {
			evidence.Detail = "emulator command path: " + pathErr.Error()
			return evidence
		}
		info, statErr := os.Stat(commandPath)
		if statErr != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			evidence.Detail = "emulator command is missing, a directory, or not executable"
			return evidence
		}
		commandBytes, readErr := os.ReadFile(commandPath)
		if readErr != nil {
			evidence.Detail = "read emulator/verifier command: " + readErr.Error()
			return evidence
		}
		commandDigest := "sha256:" + internalcrypto.SHA256Hex(commandBytes)
		if substrate.Execution == "command" {
			closureDigest, closureErr := commandIdentityDigest(repo, substrate.IdentityFiles)
			if closureErr != nil {
				evidence.Detail = "command substrate identity closure: " + closureErr.Error()
				return evidence
			}
			if !strings.HasSuffix(substrate.Identity, "@"+closureDigest) {
				evidence.Detail = fmt.Sprintf("command substrate identity does not bind closure digest %s", closureDigest)
				return evidence
			}
		}
		if substrate.Execution == "remote" && substrate.CommandSHA256 != commandDigest {
			evidence.Detail = fmt.Sprintf("remote verifier command digest = %s, want %s", commandDigest, substrate.CommandSHA256)
			return evidence
		}
	}
	if substrate.Execution == "container" && substrate.Identity != substrate.Image {
		evidence.Detail = "container substrate identity must exactly equal its pinned image"
		return evidence
	}
	evidence.Found = append([]string(nil), evidence.Required...)
	evidence.OK = true
	evidence.Detail = "substrate identity closure, out-of-process execution, and committed contract digest are pinned"
	return evidence
}

func validateIdentityFiles(where, command string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("%s.identity_files must bind every command-substrate runtime source", where)
	}
	seen := make(map[string]bool, len(names))
	commandIncluded := false
	for _, name := range names {
		if name == "" || filepath.IsAbs(name) || strings.Contains(name, "..") || filepath.ToSlash(name) != name {
			return fmt.Errorf("%s.identity_files contains non-repo path %q", where, name)
		}
		if seen[name] {
			return fmt.Errorf("%s.identity_files contains duplicate %q", where, name)
		}
		seen[name] = true
		commandIncluded = commandIncluded || name == command
	}
	if !commandIncluded {
		return fmt.Errorf("%s.identity_files must include command executable %q", where, command)
	}
	return nil
}

func commandIdentityDigest(repo string, names []string) (string, error) {
	ordered := append([]string(nil), names...)
	sort.Strings(ordered)
	var framed bytes.Buffer
	appendIdentityFrame(&framed, []byte("trstctl-dod-command-identity-v1"))
	for _, name := range ordered {
		path, err := safeRepoPath(repo, name)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("identity file %s is not a regular file", name)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		appendIdentityFrame(&framed, []byte(name))
		appendIdentityFrame(&framed, content)
	}
	return "sha256:" + internalcrypto.SHA256Hex(framed.Bytes()), nil
}

func appendIdentityFrame(target *bytes.Buffer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = target.Write(size[:])
	_, _ = target.Write(value)
}

type runtimeFunction struct {
	decl    *ast.FuncDecl
	file    string
	imports map[string]string
}

type runtimeTrace struct {
	buildBound        bool
	startBound        bool
	handlerStart      bool
	launchedRespStart bool
	completeBound     bool
	handConstructed   bool
	httptest          bool
	commandExecution  bool
	containerExec     bool
	endpointUsed      bool
	launchedBuild     bool
	launchedStart     bool
	launchedDo        bool
	unsafeConditional bool
	visited           map[string]bool
	active            map[string]bool
	functions         map[string]runtimeFunction
	entryID           string
	onlyExpectation   string
	constructor       string
	commandLiteral    string
	containerImage    string
}

type runtimeTaint string

const (
	taintDeps             runtimeTaint = "deps"
	taintServer           runtimeTaint = "server"
	taintHandler          runtimeTaint = "handler"
	taintSession          runtimeTaint = "session"
	taintEvidence         runtimeTaint = "evidence"
	taintCommand          runtimeTaint = "external-command"
	taintReceipt          runtimeTaint = "external-execution-receipt"
	taintProbe            runtimeTaint = "sealed-domain-probe"
	taintSubstrate        runtimeTaint = "external-substrate"
	taintEndpoint         runtimeTaint = "external-endpoint"
	taintShippedProcess   runtimeTaint = "gate-built-shipped-process"
	taintLaunchedResponse runtimeTaint = "pid-listener-bound-http-response"
	taintGateEnvironment  runtimeTaint = "gate-runtime-environment"
)

func literalTaint(value string) runtimeTaint { return runtimeTaint("literal:" + value) }

func inspectRuntimeBinding(repo string, entry Entry, substrates map[string]Substrate, profiles ...BuildProfile) checkEvidence {
	return inspectRuntimeBindingMode(repo, entry, substrates, entry.ID, profiles...)
}

// inspectRuntimeBindingForGroup audits both concrete values returned by
// proof.OnlyExpectation. A focused execution receives exactly this entry and
// returns its ID. A full execution of a shared profile/package/test group
// receives every sibling and returns empty. Each trace must independently bind
// production assembly through sealed evidence; proof progress is never merged
// across the two execution modes.
func inspectRuntimeBindingForGroup(repo string, entry Entry, substrates map[string]Substrate, fullGroup []Entry, profiles ...BuildProfile) checkEvidence {
	if len(fullGroup) == 0 {
		return checkEvidence{Detail: "runtime source has no unfiltered full-manifest execution group"}
	}
	found := false
	for _, grouped := range fullGroup {
		if grouped.ID == entry.ID {
			found = true
		}
		if grouped.Runtime.Package != entry.Runtime.Package || grouped.Runtime.Test != entry.Runtime.Test {
			return checkEvidence{Detail: "runtime source full-manifest group mixes package/test executions"}
		}
	}
	if !found {
		return checkEvidence{Detail: "runtime source full-manifest group omits the inspected entry"}
	}

	focused := inspectRuntimeBindingMode(repo, entry, substrates, entry.ID, profiles...)
	if !focused.OK {
		focused.Detail = "focused runtime source: " + focused.Detail
		return focused
	}
	if len(fullGroup) == 1 {
		focused.Detail += "; singleton full execution returns the same exact expectation"
		return focused
	}
	full := inspectRuntimeBindingMode(repo, entry, substrates, "", profiles...)
	if !full.OK {
		full.Detail = "full-group runtime source: " + full.Detail
		return full
	}
	focused.Detail += "; independent empty-selection full-group trace is also production-bound"
	return focused
}

func inspectRuntimeBindingMode(repo string, entry Entry, substrates map[string]Substrate, onlyExpectation string, profiles ...BuildProfile) checkEvidence {
	proof := entry.Runtime
	if !runtimeConfigured(proof) {
		return checkEvidence{Detail: "runtime proof is not configured; compiled/assembled is still a stub until a served test exists"}
	}
	if err := validateRuntime("entry "+entry.ID, proof, substrates); err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	if err := requireDODProofBuildConstraint(repo, proof.File); err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	substrate := substrates[proof.SubstrateID]
	if substrateEvidence := inspectSubstrate(repo, proof.SubstrateID, substrate); !substrateEvidence.OK {
		return substrateEvidence
	}
	profile := BuildProfile{CGOEnabled: "0", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if len(profiles) > 0 {
		profile = profiles[0]
	}
	functions, err := parseRuntimeFunctions(repo, proof.File, profile)
	if err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	if functions[proof.Test].decl == nil {
		return checkEvidence{Detail: fmt.Sprintf("runtime test %s is not declared in %s", proof.Test, proof.File)}
	}
	proofPath, pathErr := safeRepoPath(repo, proof.File)
	if pathErr != nil || filepath.Clean(functions[proof.Test].file) != filepath.Clean(proofPath) {
		return checkEvidence{Detail: fmt.Sprintf("runtime test %s is not owned by manifest file %s", proof.Test, proof.File)}
	}
	trace := &runtimeTrace{
		visited:         map[string]bool{},
		active:          map[string]bool{},
		functions:       functions,
		entryID:         entry.ID,
		onlyExpectation: onlyExpectation,
		constructor:     verifierConstructor[substrate.Verifier],
		commandLiteral:  firstString(substrate.Command),
		containerImage:  substrate.Image,
	}
	trace.evalFunction(proof.Test, nil, 0)
	if trace.unsafeConditional {
		return checkEvidence{Detail: "runtime proof exists on only one viable side of a nonconstant condition"}
	}
	if trace.handConstructed {
		return checkEvidence{Detail: "runtime test hand-constructs Deps; it must use production buildRunDeps output"}
	}
	missing := make([]string, 0, 9)
	if proof.Mode == "assembled-handler" {
		if !trace.buildBound {
			missing = append(missing, "Build receives production buildRunDeps output")
		}
		if !trace.handlerStart {
			missing = append(missing, "proof.Start receives this id and the assembled Server.Handler")
		}
	} else {
		if !trace.launchedBuild {
			missing = append(missing, "proof.BuildShippedProcess receives this id and gate-builds cmd/trstctl")
		}
		if !trace.launchedStart {
			missing = append(missing, "the same gate-built ShippedProcess is started")
		}
		if !trace.launchedDo {
			missing = append(missing, "the same live ShippedProcess owns the direct HTTP response")
		}
		if !trace.launchedRespStart {
			missing = append(missing, "proof.StartResponse receives only the PID/listener-bound launched response")
		}
	}
	if !trace.completeBound {
		missing = append(missing, "the same Session.Complete receives sealed proof."+trace.constructor+" evidence")
	}
	if trace.httptest {
		missing = append(missing, "net/http/httptest is forbidden for DoD runtime evidence")
	}
	if (substrate.Execution == "command" || substrate.Execution == "remote") && !trace.commandExecution {
		missing = append(missing, "out-of-process command execution is absent")
	}
	if substrate.Execution == "container" && !trace.containerExec {
		missing = append(missing, "pinned testcontainer execution is absent")
	}
	if !trace.endpointUsed {
		missing = append(missing, "external substrate Endpoint is absent from the action setup")
	}
	if len(trace.visited) >= maxRuntimeHelpers {
		missing = append(missing, "runtime helper graph exceeded the bounded 64-function audit")
	}
	if len(missing) > 0 {
		return checkEvidence{Required: missing, Detail: "runtime source is not bound to production assembly, sealed evidence, and the declared substrate"}
	}
	if proof.Mode == "launched-binary" {
		return checkEvidence{OK: true, Detail: fmt.Sprintf("%s and %d bounded same-package helpers bind gate-built cmd/trstctl -> live PID-owned listener -> StartResponse -> sealed %s evidence", proof.Test, len(trace.visited)-1, substrate.Verifier)}
	}
	return checkEvidence{OK: true, Detail: fmt.Sprintf("%s and %d bounded same-package helpers bind buildRunDeps -> Build -> Handler -> Start -> sealed %s evidence", proof.Test, len(trace.visited)-1, substrate.Verifier)}
}

func requireDODProofBuildConstraint(repo, name string) error {
	path, err := safeRepoPath(repo, name)
	if err != nil {
		return fmt.Errorf("runtime proof path: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runtime proof build constraint: %w", err)
	}
	want := "//go:build " + dodProofBuildTag + "\n\n"
	if !strings.HasPrefix(string(raw), want) {
		return fmt.Errorf("runtime proof %s must begin with exact dedicated build constraint %q", name, strings.TrimSpace(want))
	}
	return nil
}

func parseRuntimeFunctions(repo, rootFile string, profile BuildProfile) (map[string]runtimeFunction, error) {
	rootPath, err := safeRepoPath(repo, rootFile)
	if err != nil {
		return nil, fmt.Errorf("runtime proof path: %w", err)
	}
	rootParsed, err := parser.ParseFile(token.NewFileSet(), rootPath, nil, parser.ImportsOnly)
	if err != nil {
		return nil, fmt.Errorf("parse runtime proof: %w", err)
	}
	rootPackage := rootParsed.Name.Name
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(rootPath), "*_test.go"))
	if err != nil {
		return nil, fmt.Errorf("enumerate runtime helpers: %w", err)
	}
	functions := map[string]runtimeFunction{}
	buildContext := build.Default
	buildContext.GOOS = profile.GOOS
	buildContext.GOARCH = profile.GOARCH
	buildContext.CgoEnabled = profile.CGOEnabled == "1"
	buildContext.BuildTags = append(append([]string(nil), profile.Tags...), dodProofBuildTag)
	for _, path := range paths {
		matched, matchErr := buildContext.MatchFile(filepath.Dir(path), filepath.Base(path))
		if matchErr != nil {
			return nil, fmt.Errorf("evaluate runtime helper build constraints %s: %w", path, matchErr)
		}
		if !matched {
			continue
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return nil, fmt.Errorf("parse runtime helper %s: %w", path, parseErr)
		}
		if parsed.Name.Name != rootPackage {
			continue
		}
		imports := map[string]string{}
		for _, spec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				continue
			}
			alias := filepath.Base(importPath)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias != "." && alias != "_" {
				imports[alias] = importPath
			}
		}
		for _, declaration := range parsed.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			if prior := functions[fn.Name.Name]; prior.decl != nil {
				return nil, fmt.Errorf("runtime helper %s is duplicated in active files %s and %s", fn.Name.Name, prior.file, path)
			}
			functions[fn.Name.Name] = runtimeFunction{decl: fn, file: path, imports: imports}
		}
	}
	return functions, nil
}

func (trace *runtimeTrace) evalFunction(name string, incoming []runtimeTaint, depth int) []runtimeTaint {
	if depth > maxRuntimeDepth || len(trace.visited) >= maxRuntimeHelpers || trace.active[name] {
		return nil
	}
	fn := trace.functions[name]
	if fn.decl == nil {
		return nil
	}
	trace.active[name] = true
	trace.visited[name] = true
	defer delete(trace.active, name)
	for _, importPath := range fn.imports {
		if importPath == "net/http/httptest" {
			trace.httptest = true
		}
	}
	env := map[string]runtimeTaint{}
	parameterNames := fieldNames(fn.decl.Type.Params)
	for index, parameter := range parameterNames {
		if index < len(incoming) {
			env[parameter] = incoming[index]
		}
	}
	ast.Inspect(fn.decl.Body, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if ok && (expressionName(literal.Type) == "Deps" || strings.HasSuffix(expressionName(literal.Type), ".Deps")) {
			trace.handConstructed = true
		}
		return true
	})
	var returns []runtimeTaint
	trace.evalStatements(fn, fn.decl.Body.List, env, depth, &returns)
	return returns
}

func fieldNames(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var names []string
	for _, field := range fields.List {
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}

func (trace *runtimeTrace) evalStatements(fn runtimeFunction, statements []ast.Stmt, env map[string]runtimeTaint, depth int, returns *[]runtimeTaint) {
	for _, statement := range statements {
		switch value := statement.(type) {
		case *ast.AssignStmt:
			for index, rhs := range value.Rhs {
				taints := trace.evalExpression(fn, rhs, env, depth)
				if len(taints) == 0 {
					continue
				}
				if len(value.Rhs) == 1 {
					for lhsIndex, lhs := range value.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok && lhsIndex < len(taints) {
							env[ident.Name] = taints[lhsIndex]
						}
					}
				} else if index < len(value.Lhs) {
					if ident, ok := value.Lhs[index].(*ast.Ident); ok {
						env[ident.Name] = taints[0]
					}
				}
			}
		case *ast.DeclStmt:
			declaration, ok := value.Decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range declaration.Specs {
				values, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, expression := range values.Values {
					taints := trace.evalExpression(fn, expression, env, depth)
					if index < len(values.Names) && len(taints) > 0 {
						env[values.Names[index].Name] = taints[0]
					}
				}
			}
		case *ast.ExprStmt:
			trace.evalExpression(fn, value.X, env, depth)
		case *ast.ReturnStmt:
			for _, expression := range value.Results {
				taints := trace.evalExpression(fn, expression, env, depth)
				if len(taints) > 0 {
					*returns = append(*returns, taints[0])
				} else {
					*returns = append(*returns, "")
				}
			}
			return
		case *ast.IfStmt:
			trace.evalExpression(fn, value.Cond, env, depth)
			if condition, known := trace.conditionBool(fn, value.Cond, env, depth); known {
				if condition {
					trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
				} else if value.Else != nil {
					trace.evalNestedStatement(fn, value.Else, cloneTaints(env), depth, returns)
				}
			} else {
				bodyTrace := trace.cloneForBranch()
				bodyTrace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
				elseTrace := trace.cloneForBranch()
				if value.Else != nil {
					elseTrace.evalNestedStatement(fn, value.Else, cloneTaints(env), depth, returns)
				}
				if bodyTrace.proofProgress() != elseTrace.proofProgress() {
					trace.unsafeConditional = true
				}
				trace.mergeBranch(bodyTrace)
				trace.mergeBranch(elseTrace)
			}
		case *ast.ForStmt:
			if value.Cond == nil {
				trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
			} else if condition, known := constantBool(value.Cond); !known || condition {
				trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
			}
		case *ast.RangeStmt:
			trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
		case *ast.DeferStmt:
			trace.evalExpression(fn, value.Call, env, depth)
		case *ast.GoStmt:
			trace.evalExpression(fn, value.Call, env, depth)
		}
		if statementTerminates(statement) {
			return
		}
	}
}

func constantBool(expression ast.Expr) (bool, bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		if value.Name == "true" {
			return true, true
		}
		if value.Name == "false" {
			return false, true
		}
	case *ast.ParenExpr:
		return constantBool(value.X)
	case *ast.UnaryExpr:
		if value.Op == token.NOT {
			result, known := constantBool(value.X)
			return !result, known
		}
	case *ast.BinaryExpr:
		left, leftKnown := constantBool(value.X)
		right, rightKnown := constantBool(value.Y)
		switch value.Op {
		case token.LAND:
			if leftKnown && !left || rightKnown && !right {
				return false, true
			}
			if leftKnown && rightKnown {
				return left && right, true
			}
		case token.LOR:
			if leftKnown && left || rightKnown && right {
				return true, true
			}
			if leftKnown && rightKnown {
				return left || right, true
			}
		}
	}
	return false, false
}

func (trace *runtimeTrace) conditionBool(fn runtimeFunction, expression ast.Expr, env map[string]runtimeTaint, depth int) (bool, bool) {
	if value, known := constantBool(expression); known {
		return value, true
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return trace.conditionBool(fn, value.X, env, depth)
	case *ast.UnaryExpr:
		if value.Op == token.NOT {
			result, known := trace.conditionBool(fn, value.X, env, depth)
			return !result, known
		}
	case *ast.BinaryExpr:
		switch value.Op {
		case token.EQL, token.NEQ:
			left := firstTaint(trace.evalExpression(fn, value.X, env, depth))
			right := firstTaint(trace.evalExpression(fn, value.Y, env, depth))
			if strings.HasPrefix(string(left), "literal:") && strings.HasPrefix(string(right), "literal:") {
				equal := left == right
				if value.Op == token.NEQ {
					equal = !equal
				}
				return equal, true
			}
		case token.LAND:
			left, leftKnown := trace.conditionBool(fn, value.X, env, depth)
			if leftKnown && !left {
				return false, true
			}
			right, rightKnown := trace.conditionBool(fn, value.Y, env, depth)
			if rightKnown && !right {
				return false, true
			}
			if leftKnown && rightKnown {
				return left && right, true
			}
		case token.LOR:
			left, leftKnown := trace.conditionBool(fn, value.X, env, depth)
			if leftKnown && left {
				return true, true
			}
			right, rightKnown := trace.conditionBool(fn, value.Y, env, depth)
			if rightKnown && right {
				return true, true
			}
			if leftKnown && rightKnown {
				return left || right, true
			}
		}
	}
	return false, false
}

func (trace *runtimeTrace) cloneForBranch() *runtimeTrace {
	clone := *trace
	clone.visited = make(map[string]bool, len(trace.visited))
	for name, value := range trace.visited {
		clone.visited[name] = value
	}
	clone.active = make(map[string]bool, len(trace.active))
	for name, value := range trace.active {
		clone.active[name] = value
	}
	return &clone
}

func (trace *runtimeTrace) proofProgress() bool {
	return trace.startBound && trace.completeBound && trace.endpointUsed && (trace.commandExecution || trace.containerExec) &&
		(!trace.launchedBuild || trace.launchedStart && trace.launchedDo)
}

func (trace *runtimeTrace) mergeBranch(branch *runtimeTrace) {
	trace.buildBound = trace.buildBound || branch.buildBound
	trace.startBound = trace.startBound || branch.startBound
	trace.handlerStart = trace.handlerStart || branch.handlerStart
	trace.launchedRespStart = trace.launchedRespStart || branch.launchedRespStart
	trace.completeBound = trace.completeBound || branch.completeBound
	trace.handConstructed = trace.handConstructed || branch.handConstructed
	trace.httptest = trace.httptest || branch.httptest
	trace.commandExecution = trace.commandExecution || branch.commandExecution
	trace.containerExec = trace.containerExec || branch.containerExec
	trace.endpointUsed = trace.endpointUsed || branch.endpointUsed
	trace.launchedBuild = trace.launchedBuild || branch.launchedBuild
	trace.launchedStart = trace.launchedStart || branch.launchedStart
	trace.launchedDo = trace.launchedDo || branch.launchedDo
	trace.unsafeConditional = trace.unsafeConditional || branch.unsafeConditional
	for name := range branch.visited {
		trace.visited[name] = true
	}
}

func statementTerminates(statement ast.Stmt) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Fatal", "Fatalf", "FailNow":
		return true
	default:
		return false
	}
}

func (trace *runtimeTrace) evalNestedStatement(fn runtimeFunction, statement ast.Stmt, env map[string]runtimeTaint, depth int, returns *[]runtimeTaint) {
	switch value := statement.(type) {
	case *ast.BlockStmt:
		trace.evalStatements(fn, value.List, env, depth, returns)
	case *ast.IfStmt:
		trace.evalStatements(fn, []ast.Stmt{value}, env, depth, returns)
	}
}

func cloneTaints(source map[string]runtimeTaint) map[string]runtimeTaint {
	out := make(map[string]runtimeTaint, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func (trace *runtimeTrace) evalExpression(fn runtimeFunction, expression ast.Expr, env map[string]runtimeTaint, depth int) []runtimeTaint {
	switch value := expression.(type) {
	case *ast.Ident:
		return []runtimeTaint{env[value.Name]}
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			if decoded, err := strconv.Unquote(value.Value); err == nil {
				return []runtimeTaint{literalTaint(decoded)}
			}
		}
	case *ast.ParenExpr:
		return trace.evalExpression(fn, value.X, env, depth)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok || expressionName(pair.Key) != "ExecutionReceipt" {
				continue
			}
			if firstTaint(trace.evalExpression(fn, pair.Value, env, depth)) == taintReceipt {
				return []runtimeTaint{taintProbe}
			}
		}
	case *ast.FuncLit:
		var returns []runtimeTaint
		trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth+1, &returns)
		return returns
	case *ast.CallExpr:
		name := expressionName(value.Fun)
		if name == "buildRunDeps" {
			return []runtimeTaint{taintDeps}
		}
		if name == "Build" {
			for _, argument := range value.Args {
				if firstTaint(trace.evalExpression(fn, argument, env, depth)) == taintDeps {
					trace.buildBound = true
					return []runtimeTaint{taintServer, ""}
				}
			}
		}
		if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
			alias, _ := selector.X.(*ast.Ident)
			importPath := ""
			if alias != nil {
				importPath = fn.imports[alias.Name]
			}
			// Only the exact imported gate helper is constant. The caller runs this
			// trace separately with the focused entry ID and, for a shared full
			// execution, with empty. This keeps the branch model equal to both real
			// runtime envelopes without merging proof progress between them.
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && selector.Sel.Name == "OnlyExpectation" && len(value.Args) == 1 {
				return []runtimeTaint{literalTaint(trace.onlyExpectation)}
			}
			if importPath == "os" && selector.Sel.Name == "Getenv" && len(value.Args) == 1 {
				name := firstTaint(trace.evalExpression(fn, value.Args[0], env, depth))
				variable := strings.TrimPrefix(string(name), "literal:")
				if variable == "TRSTCTL_HSM_PROOF_ONLY" {
					// The parent runner strips every ambient TRSTCTL_* value and
					// injects only its DOD expectation envelope. This legacy selector
					// is therefore exactly empty; managed-key tests then delegate to
					// proof.OnlyExpectation.
					return []runtimeTaint{literalTaint("")}
				}
				if strings.HasPrefix(variable, "TRSTCTL_") {
					// In particular, TRSTCTL_DOD_EXPECTATIONS is nonempty at
					// runtime. Treat gate/test-set environment as nonconstant so a
					// proof cannot hide test-only assembly behind its presence.
					return []runtimeTaint{taintGateEnvironment}
				}
			}
			if importPath == "os/exec" && (selector.Sel.Name == "Command" || selector.Sel.Name == "CommandContext") {
				for _, argument := range value.Args {
					if firstTaint(trace.evalExpression(fn, argument, env, depth)) == literalTaint(trace.commandLiteral) {
						trace.commandExecution = true
						return []runtimeTaint{taintCommand}
					}
				}
			}
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && (selector.Sel.Name == "StartCommand" || selector.Sel.Name == "StartContainer") {
				if containsRuntimeLiteral(trace, fn, value.Args, env, depth, trace.entryID) {
					if selector.Sel.Name == "StartCommand" && trace.commandLiteral != "" {
						trace.commandExecution = true
					}
					if selector.Sel.Name == "StartContainer" && trace.containerImage != "" {
						trace.containerExec = true
					}
					return []runtimeTaint{taintSubstrate}
				}
			}
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && selector.Sel.Name == "BuildShippedProcess" && containsRuntimeLiteral(trace, fn, value.Args, env, depth, trace.entryID) {
				trace.launchedBuild = true
				return []runtimeTaint{taintShippedProcess}
			}
			if selector.Sel.Name == "Endpoint" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintSubstrate {
				trace.endpointUsed = true
				return []runtimeTaint{taintEndpoint}
			}
			if selector.Sel.Name == "StopAndReceipt" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintSubstrate {
				return []runtimeTaint{taintReceipt}
			}
			if selector.Sel.Name == "Start" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintShippedProcess {
				trace.launchedStart = true
				return nil
			}
			if selector.Sel.Name == "Do" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintShippedProcess {
				trace.launchedDo = true
				return []runtimeTaint{taintLaunchedResponse}
			}
			if (selector.Sel.Name == "Output" || selector.Sel.Name == "CombinedOutput") && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintCommand {
				return []runtimeTaint{taintReceipt, ""}
			}
			if strings.Contains(importPath, "testcontainers-go") && selector.Sel.Name == "GenericContainer" && containsLiteral(value.Args, trace.containerImage) {
				trace.containerExec = true
			}
			if selector.Sel.Name == "Handler" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintServer {
				return []runtimeTaint{taintHandler}
			}
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && selector.Sel.Name == "Start" {
				idBound := false
				handlerBound := false
				for _, argument := range value.Args {
					taint := firstTaint(trace.evalExpression(fn, argument, env, depth))
					idBound = idBound || taint == literalTaint(trace.entryID)
					handlerBound = handlerBound || taint == taintHandler
				}
				if idBound && handlerBound {
					trace.startBound = true
					trace.handlerStart = true
					return []runtimeTaint{taintSession}
				}
			}
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && selector.Sel.Name == "StartResponse" {
				idBound := false
				responseBound := false
				for _, argument := range value.Args {
					taint := firstTaint(trace.evalExpression(fn, argument, env, depth))
					idBound = idBound || taint == literalTaint(trace.entryID)
					responseBound = responseBound || taint == taintLaunchedResponse
				}
				if idBound && responseBound {
					trace.startBound = true
					trace.launchedRespStart = true
					return []runtimeTaint{taintSession}
				}
			}
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && selector.Sel.Name == trace.constructor {
				if probeCarriesExecutionReceipt(trace, fn, value.Args, env, depth) {
					return []runtimeTaint{taintEvidence}
				}
			}
			if selector.Sel.Name == "Complete" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintSession && len(value.Args) == 1 && firstTaint(trace.evalExpression(fn, value.Args[0], env, depth)) == taintEvidence {
				trace.completeBound = true
			}
		}
		if local := trace.functions[name]; local.decl != nil {
			incoming := make([]runtimeTaint, 0, len(value.Args))
			for _, argument := range value.Args {
				incoming = append(incoming, firstTaint(trace.evalExpression(fn, argument, env, depth)))
			}
			return trace.evalFunction(name, incoming, depth+1)
		}
		for _, argument := range value.Args {
			trace.evalExpression(fn, argument, env, depth)
		}
	}
	return nil
}

func firstTaint(values []runtimeTaint) runtimeTaint {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func probeCarriesExecutionReceipt(trace *runtimeTrace, fn runtimeFunction, arguments []ast.Expr, env map[string]runtimeTaint, depth int) bool {
	for _, argument := range arguments {
		if firstTaint(trace.evalExpression(fn, argument, env, depth)) == taintProbe {
			return true
		}
	}
	return false
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func containsLiteral(expressions []ast.Expr, want string) bool {
	for _, expression := range expressions {
		literal, ok := expression.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && value == want {
			return true
		}
	}
	return false
}

func containsRuntimeLiteral(trace *runtimeTrace, fn runtimeFunction, expressions []ast.Expr, env map[string]runtimeTaint, depth int, want string) bool {
	for _, expression := range expressions {
		if firstTaint(trace.evalExpression(fn, expression, env, depth)) == literalTaint(want) {
			return true
		}
	}
	return false
}

type runtimeExpectation struct {
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
	ReceiptMACKey         []byte            `json:"-"`
}

type runtimeReceipt struct {
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

type runtimeTestExecution struct {
	result       commandResult
	passed       bool
	skipped      bool
	failed       bool
	expectations map[string]runtimeExpectation
	receiptDir   string
	broker       *substrateBroker
}

type launchedBinarySpec struct {
	ModulePath        string
	BinaryPackage     string
	CompanionPackages []string
	CGOEnabled        string
	GOOS              string
	GOARCH            string
	Tags              []string
}

func launchedBinarySpecForManifest(repo string, manifest Manifest) (launchedBinarySpec, error) {
	profile, ok := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	if !ok || profile.BinaryPackage != manifest.BinaryPackage {
		return launchedBinarySpec{}, fmt.Errorf("default shipped profile does not own manifest binary_package %q", manifest.BinaryPackage)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		return launchedBinarySpec{}, fmt.Errorf("read module path for launched binary: %w", err)
	}
	fields := strings.Fields(string(raw))
	modulePath := ""
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "module" {
			modulePath = fields[index+1]
			break
		}
	}
	if modulePath == "" || strings.ContainsAny(modulePath, "\r\n\x00") {
		return launchedBinarySpec{}, fmt.Errorf("go.mod has no safe module path for launched binary")
	}
	companions := make([]string, 0, len(profile.Artifact.Companions))
	for _, companion := range profile.Artifact.Companions {
		companions = append(companions, companion.BinaryPackage)
	}
	sort.Strings(companions)
	return launchedBinarySpec{
		ModulePath: modulePath, BinaryPackage: manifest.BinaryPackage, CompanionPackages: companions,
		CGOEnabled: profile.CGOEnabled, GOOS: profile.GOOS, GOARCH: profile.GOARCH,
		Tags: append([]string(nil), profile.Tags...),
	}, nil
}

func runtimeCacheKey(profileName string, entry Entry) string {
	return strings.Join([]string{profileName, entry.Runtime.Package, entry.Runtime.Test}, "\x00")
}

func groupRuntimeEntries(manifest Manifest, selectedID string, selectionActive bool) map[string][]Entry {
	groups := map[string][]Entry{}
	for _, entry := range manifest.Entries {
		if selectionActive && entry.ID != selectedID {
			continue
		}
		if !runtimeConfigured(entry.Runtime) {
			continue
		}
		profileName, _ := resolvedProfile(manifest, entry)
		key := runtimeCacheKey(profileName, entry)
		groups[key] = append(groups[key], entry)
	}
	return groups
}

func cleanupRuntimeExecutions(executions map[string]*runtimeTestExecution) {
	for _, execution := range executions {
		if execution == nil {
			continue
		}
		for id, expectation := range execution.expectations {
			secret.Wipe(expectation.ReceiptMACKey)
			expectation.ReceiptMACKey = nil
			execution.expectations[id] = expectation
		}
		execution.broker.close()
		if execution.receiptDir != "" {
			_ = os.RemoveAll(execution.receiptDir)
		}
	}
}

func runRuntimeProof(ctx context.Context, repo string, entry Entry, profileName string, profile BuildProfile, launched launchedBinarySpec, substrate Substrate, runner commandRunner, group []Entry, cache map[string]*runtimeTestExecution) checkEvidence {
	key := runtimeCacheKey(profileName, entry)
	execution := cache[key]
	if execution == nil {
		var err error
		execution, err = executeRuntimeTest(ctx, repo, profileName, profile, launched, substrate, group, runner)
		if err != nil {
			return checkEvidence{Detail: err.Error()}
		}
		cache[key] = execution
	}
	if execution.skipped {
		return checkEvidence{Detail: "runtime proof skipped; skips never prove a shipped capability"}
	}
	if execution.failed || !execution.passed {
		return checkEvidence{Detail: runtimeFailureDetail(execution.result)}
	}
	expected, ok := execution.expectations[entry.ID]
	if !ok {
		return checkEvidence{Detail: "shared runtime execution did not receive this entry's independent expectation"}
	}
	if expected.SubstrateID != entry.Runtime.SubstrateID || expected.SubstrateIdentity != substrate.Identity {
		return checkEvidence{Detail: "cached runtime expectation belongs to a different substrate"}
	}
	if err := finalizeParentReceipt(expected, execution.broker); err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	if err := validateReceipt(expected); err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	return checkEvidence{OK: true, Detail: fmt.Sprintf("%s passed without skip and wrote an exact nonce/id/route/profile/substrate/digest-bound JSON receipt", entry.Runtime.Test)}
}

func runtimeFailureDetail(result commandResult) string {
	if detail := strings.TrimSpace(result.Stderr); detail != "" {
		return detail
	}
	if detail := strings.TrimSpace(result.Stdout); detail != "" {
		return "go test -json: " + condensedGoTestFailure(detail)
	}
	if result.Err != nil {
		return result.Err.Error()
	}
	return "dedicated runtime test did not pass"
}

func condensedGoTestFailure(raw string) string {
	type event struct {
		Action     string `json:"Action"`
		Output     string `json:"Output"`
		Test       string `json:"Test"`
		Package    string `json:"Package"`
		ImportPath string `json:"ImportPath"`
	}
	const (
		keepFirst = 6
		keepLast  = 8
	)
	firstMessages := make([]string, 0, keepFirst)
	lastMessages := make([]string, 0, keepLast)
	appendMessage := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" {
			return
		}
		if len(firstMessages) < keepFirst {
			firstMessages = append(firstMessages, message)
			return
		}
		if len(lastMessages) == keepLast {
			copy(lastMessages, lastMessages[1:])
			lastMessages = lastMessages[:keepLast-1]
		}
		lastMessages = append(lastMessages, message)
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		var item event
		if json.Unmarshal(scanner.Bytes(), &item) != nil {
			continue
		}
		switch item.Action {
		case "build-output", "output":
			appendMessage(item.Output)
		case "build-fail", "fail":
			label := item.Test
			if label == "" {
				label = item.ImportPath
			}
			if label == "" {
				label = item.Package
			}
			if label == "" {
				label = "runtime test"
			}
			appendMessage(label + " failed")
		}
	}
	messages := append(firstMessages, lastMessages...)
	detail := strings.Join(messages, " | ")
	if detail == "" {
		detail = strings.TrimSpace(raw)
	}
	const limit = 2048
	if len(detail) > limit {
		const divider = " ... [bounded crash tail] ... "
		head := (limit - len(divider)) / 2
		tail := limit - len(divider) - head
		detail = detail[:head] + divider + detail[len(detail)-tail:]
	}
	return detail
}

func executeRuntimeTest(ctx context.Context, repo, profileName string, profile BuildProfile, launched launchedBinarySpec, substrate Substrate, group []Entry, runner commandRunner) (*runtimeTestExecution, error) {
	if len(group) == 0 {
		return nil, fmt.Errorf("runtime test has no grouped manifest expectations")
	}
	if preparer, ok := runner.(runtimeProfilePreparer); ok {
		prepared, err := preparer.PrepareRuntime(ctx, repo, profile)
		if err != nil {
			return nil, fmt.Errorf("prepare shipped-profile runtime: %w", err)
		}
		profile = prepared
	}
	nonceBytes, err := internalcrypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate runtime receipt nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	receiptDir, err := os.MkdirTemp("", "trstctl-dod-receipts-")
	if err != nil {
		return nil, fmt.Errorf("create runtime receipt directory: %w", err)
	}
	macKey, err := internalcrypto.RandomBytes(32)
	if err != nil {
		_ = os.RemoveAll(receiptDir)
		return nil, fmt.Errorf("generate runtime receipt MAC key: %w", err)
	}
	defer secret.Wipe(macKey)
	broker := newInMemorySubstrateBroker(repo, receiptDir)
	if provider, ok := runner.(substrateBrokerProvider); ok {
		broker, err = provider.StartSubstrateBroker(repo, receiptDir, profile.RuntimeRunnerImage != "")
		if err != nil {
			_ = os.RemoveAll(receiptDir)
			return nil, err
		}
	}
	execution := &runtimeTestExecution{expectations: map[string]runtimeExpectation{}, receiptDir: receiptDir, broker: broker}
	for _, groupedEntry := range group {
		substrateID := groupedEntry.Runtime.SubstrateID
		if substrateID != group[0].Runtime.SubstrateID {
			broker.close()
			_ = os.RemoveAll(receiptDir)
			return nil, fmt.Errorf("shared runtime test mixes substrate ids; split the dedicated tests")
		}
		// All grouped entries were already manifest-validated. The substrate is
		// supplied to proof.Start through this signed-off expectation, never by
		// arbitrary test strings.
		expectation := runtimeExpectation{
			SchemaVersion: 1, Repo: repo, Nonce: nonce, ID: groupedEntry.ID, BuildProfile: profileName,
			Method: groupedEntry.Runtime.Method, Path: groupedEntry.Runtime.Path, RuntimeMode: groupedEntry.Runtime.Mode,
			SubstrateID:   substrateID,
			SubstrateKind: substrate.Kind, SubstrateIdentity: substrate.Identity,
			ContractDigest: substrate.ContractSHA256, Verifier: substrate.Verifier,
			Execution: substrate.Execution, Command: append([]string(nil), substrate.Command...), Image: substrate.Image,
			ReceiptFile:           filepath.Join(receiptDir, strings.ReplaceAll(groupedEntry.ID, ".", "_")+".receipt.json"),
			EvidenceFile:          filepath.Join(receiptDir, strings.ReplaceAll(groupedEntry.ID, ".", "_")+".evidence.json"),
			RuntimeRunnerIdentity: profile.RuntimeRunner.Identity,
			RuntimeRunnerImage:    profile.RuntimeRunnerImage,
			RuntimeTestPackage:    groupedEntry.Runtime.Package,
			RuntimeCGOEnabled:     profile.CGOEnabled,
			RuntimeGOOS:           profile.GOOS,
			RuntimeGOARCH:         profile.GOARCH,
			RuntimeTags:           append([]string(nil), profile.Tags...),
			LaunchedModulePath:    launched.ModulePath,
			LaunchedBinaryPackage: launched.BinaryPackage,
			LaunchedCompanions:    append([]string(nil), launched.CompanionPackages...),
			LaunchedCGOEnabled:    launched.CGOEnabled,
			LaunchedGOOS:          launched.GOOS,
			LaunchedGOARCH:        launched.GOARCH,
			LaunchedTags:          append([]string(nil), launched.Tags...),
			BrokerEndpoint:        broker.clientEndpoint(), BrokerToken: broker.token,
			Required:      map[string]string{},
			ReceiptMACKey: append([]byte(nil), macKey...),
		}
		execution.expectations[groupedEntry.ID] = expectation
	}
	broker.configure(execution.expectations)
	payload, err := sortedExpectationJSON(execution.expectations)
	if err != nil {
		broker.close()
		_ = os.RemoveAll(receiptDir)
		return nil, fmt.Errorf("encode runtime expectations: %w", err)
	}
	runtimeProfile := profile
	runtimeProfile.HostRuntime = false
	runtimeProfile.RuntimeExecution = true
	runtimeProfile.RuntimeScratchDir = receiptDir
	runtimeProfile.RuntimeBroker = broker
	runtimeProfile.RuntimeEnv = map[string]string{
		"TRSTCTL_DOD_EXPECTATIONS": string(payload),
	}
	tags := append([]string(nil), profile.Tags...)
	tags = append(tags, dodProofBuildTag)
	args := []string{"test", "-tags=" + strings.Join(tags, ",")}
	proof := group[0].Runtime
	args = append(args, "-json", "-count=1", dodReceiptTestTimeoutArg, "-run", "^"+regexp.QuoteMeta(proof.Test)+"$", proof.Package)
	execution.result = runner.Run(ctx, repo, runtimeProfile, "go", args...)
	execution.passed, execution.skipped, execution.failed = parseTestOutcome(execution.result, proof.Test)
	return execution, nil
}

func finalizeParentReceipt(expected runtimeExpectation, broker *substrateBroker) error {
	if _, err := os.Lstat(expected.ReceiptFile); err == nil {
		return fmt.Errorf("runtime test pre-created final receipt for %s; only the parent gate may sign it", expected.ID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect final runtime receipt path: %w", err)
	}
	receipt, err := readRuntimeReceipt(expected.EvidenceFile, "unsigned evidence envelope")
	if err != nil {
		return err
	}
	parentReceipt := broker.receipt(expected.ID)
	if len(parentReceipt) == 0 {
		return fmt.Errorf("parent-owned substrate broker has no independently captured receipt for %s", expected.ID)
	}
	if err := validateRuntimeReceiptBody(expected, receipt, false, parentReceipt); err != nil {
		return err
	}
	canonical, err := runtimeReceiptMACPayload(receipt)
	if err != nil {
		return fmt.Errorf("canonicalize parent-signed runtime receipt: %w", err)
	}
	receipt.MAC = "hmac-sha256:" + hex.EncodeToString(internalcrypto.HMACSHA256(expected.ReceiptMACKey, canonical))
	file, err := os.OpenFile(expected.ReceiptFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("parent create unique signed runtime receipt: %w", err)
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(receipt); err != nil {
		_ = file.Close()
		return fmt.Errorf("parent encode signed runtime receipt: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("parent sync signed runtime receipt: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("parent close signed runtime receipt: %w", err)
	}
	return nil
}

func validateReceipt(expected runtimeExpectation) error {
	receipt, err := readRuntimeReceipt(expected.ReceiptFile, "parent-signed runtime receipt")
	if err != nil {
		return err
	}
	return validateRuntimeReceiptBody(expected, receipt, true, nil)
}

func readRuntimeReceipt(path, label string) (runtimeReceipt, error) {
	info, err := os.Stat(path)
	if err != nil {
		return runtimeReceipt{}, fmt.Errorf("%s is missing: %w", label, err)
	}
	if info.IsDir() || info.Size() <= 0 || info.Size() > maxReceiptBytes {
		return runtimeReceipt{}, fmt.Errorf("%s has invalid size %d", label, info.Size())
	}
	file, err := os.Open(path)
	if err != nil {
		return runtimeReceipt{}, fmt.Errorf("open %s: %w", label, err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxReceiptBytes+1))
	decoder.DisallowUnknownFields()
	var receipt runtimeReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return runtimeReceipt{}, fmt.Errorf("decode %s: %w", label, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return runtimeReceipt{}, fmt.Errorf("%s contains trailing JSON", label)
	}
	return receipt, nil
}

func validateRuntimeReceiptBody(expected runtimeExpectation, receipt runtimeReceipt, signed bool, parentReceipt []byte) error {
	if _, err := parseContentImageID(expected.RuntimeRunnerImage); err != nil {
		return fmt.Errorf("runtime expectation has no exact content-addressed runner image: %w", err)
	}
	if receipt.SchemaVersion != 1 || receipt.Nonce != expected.Nonce || receipt.ID != expected.ID || receipt.BuildProfile != expected.BuildProfile || receipt.Method != expected.Method || receipt.Path != expected.Path || receipt.RuntimeMode != expected.RuntimeMode || receipt.SubstrateID != expected.SubstrateID || receipt.SubstrateKind != expected.SubstrateKind || receipt.SubstrateIdentity != expected.SubstrateIdentity || receipt.ContractDigest != expected.ContractDigest || receipt.Verifier != expected.Verifier || receipt.RuntimeRunnerIdentity != expected.RuntimeRunnerIdentity || receipt.RuntimeRunnerImage != expected.RuntimeRunnerImage {
		return fmt.Errorf("runtime receipt identity/nonce/route/profile/substrate/runner/digest does not exactly match the gate expectation")
	}
	if expected.RuntimeMode == "launched-binary" {
		process := receipt.LaunchedProcess
		if process == nil || process.PID <= 0 || process.BinaryModulePath != expected.LaunchedModulePath ||
			process.BinaryPackage != expected.LaunchedBinaryPackage || process.BinaryCGOEnabled != expected.LaunchedCGOEnabled ||
			process.BinaryGOOS != expected.LaunchedGOOS || process.BinaryGOARCH != expected.LaunchedGOARCH ||
			!slices.Equal(process.BinaryTags, expected.LaunchedTags) ||
			!validRuntimeLaunchedWitness(*process) || !strings.HasPrefix(process.Address, "127.0.0.1:") {
			return fmt.Errorf("launched runtime receipt has no exact process lineage/listener witness")
		}
		port, portErr := strconv.Atoi(strings.TrimPrefix(process.Address, "127.0.0.1:"))
		if portErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("launched runtime receipt has an invalid literal-loopback port or listener inode")
		}
	} else if receipt.LaunchedProcess != nil {
		return fmt.Errorf("assembled-handler runtime receipt added an unexpected launched-process witness")
	}
	if !receipt.Passed || receipt.Skipped {
		return fmt.Errorf("runtime receipt is not pass=true, skip=false")
	}
	if signed {
		if !receiptMACPattern.MatchString(receipt.MAC) {
			return fmt.Errorf("runtime receipt has no valid parent-only keyed MAC")
		}
		canonical, err := runtimeReceiptMACPayload(receipt)
		if err != nil {
			return err
		}
		wantMAC := internalcrypto.HMACSHA256(expected.ReceiptMACKey, canonical)
		gotMAC, err := hex.DecodeString(strings.TrimPrefix(receipt.MAC, "hmac-sha256:"))
		if err != nil || !internalcrypto.ConstantTimeEqual(gotMAC, wantMAC) {
			return fmt.Errorf("runtime receipt keyed MAC does not match the parent-only key")
		}
	} else if receipt.MAC != "" {
		return fmt.Errorf("child evidence envelope tried to supply a parent-only MAC")
	}
	wantKeys := requiredObservations[expected.Verifier]
	if len(receipt.Observations) != len(wantKeys) {
		return fmt.Errorf("runtime receipt observations = %d, want exact closed set of %d", len(receipt.Observations), len(wantKeys))
	}
	for _, key := range wantKeys {
		value, ok := receipt.Observations[key]
		if !ok || !digestPattern.MatchString(value) {
			return fmt.Errorf("runtime receipt missing digest observation %q", key)
		}
	}
	if len(parentReceipt) > 0 {
		childCanonical, err := canonicalExecutionReceipt(receipt.ExecutionReceipt)
		if err != nil {
			return err
		}
		parentCanonical, err := canonicalExecutionReceipt(parentReceipt)
		if err != nil {
			return fmt.Errorf("parent substrate receipt: %w", err)
		}
		if !bytes.Equal(childCanonical, parentCanonical) {
			return fmt.Errorf("child evidence does not match the receipt captured directly by the parent-owned substrate process")
		}
		wantDigest := "sha256:" + internalcrypto.SHA256Hex(parentCanonical)
		if receipt.Observations["execution_receipt_digest"] != wantDigest {
			return fmt.Errorf("execution receipt digest does not match parent-captured substrate bytes")
		}
	}
	for key, want := range expected.Required {
		if receipt.Observations[key] != want {
			return fmt.Errorf("runtime receipt observation %q does not match gate-issued substrate evidence", key)
		}
	}
	return nil
}

func validRuntimeLaunchedWitness(process launchedProcessReceipt) bool {
	positiveDecimal := func(value string) bool {
		parsed, err := strconv.ParseUint(value, 10, 64)
		return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
	}
	if process.BinaryModulePath == "" || process.BinaryPackage == "" ||
		(process.BinaryCGOEnabled != "0" && process.BinaryCGOEnabled != "1") || process.BinaryGOOS == "" || process.BinaryGOARCH == "" ||
		!digestPattern.MatchString(process.BinaryDigest) || !positiveDecimal(process.ProcessStartTicks) ||
		!positiveDecimal(process.BinaryDevice) || !positiveDecimal(process.BinaryInode) ||
		!positiveDecimal(process.ListenerInode) || !positiveDecimal(process.AcceptedConnectionInode) ||
		process.ListenerInode == process.AcceptedConnectionInode {
		return false
	}
	switch process.ProcessMode {
	case "native":
		return process.InterpreterDigest == "" && process.InterpreterDevice == "" && process.InterpreterInode == ""
	case "binfmt":
		return digestPattern.MatchString(process.InterpreterDigest) && positiveDecimal(process.InterpreterDevice) && positiveDecimal(process.InterpreterInode)
	default:
		return false
	}
}

func canonicalExecutionReceipt(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxReceiptBytes {
		return nil, fmt.Errorf("external execution receipt size %d is invalid", len(raw))
	}
	var receipt brokerReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("decode external execution receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("external execution receipt has trailing JSON")
	}
	return json.Marshal(receipt)
}

func runtimeReceiptMACPayload(receipt runtimeReceipt) ([]byte, error) {
	receipt.MAC = ""
	return json.Marshal(receipt)
}

func parseTestOutcome(result commandResult, testName string) (passed, skipped, failed bool) {
	type event struct {
		Action string `json:"Action"`
		Test   string `json:"Test"`
	}
	failed = result.Err != nil
	scanner := bufio.NewScanner(strings.NewReader(result.Stdout))
	for scanner.Scan() {
		var item event
		if json.Unmarshal(scanner.Bytes(), &item) != nil || item.Test != testName {
			continue
		}
		switch item.Action {
		case "pass":
			passed = true
		case "skip":
			skipped = true
		case "fail":
			failed = true
		}
	}
	return passed, skipped, failed
}

func sortedExpectationJSON(expectations map[string]runtimeExpectation) ([]byte, error) {
	ids := make([]string, 0, len(expectations))
	for id := range expectations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ordered := make([]runtimeExpectation, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, expectations[id])
	}
	return json.Marshal(ordered)
}
