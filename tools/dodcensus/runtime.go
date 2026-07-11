// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	internalcrypto "trstctl.com/trstctl/internal/crypto"
)

const (
	maxRuntimeHelpers = 64
	maxRuntimeDepth   = 8
	maxReceiptBytes   = 1 << 20
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
	if substrate.Execution == "container" && !pinnedImagePattern.MatchString(substrate.Image) {
		return fmt.Errorf("%s container image is not pinned with @sha256", where)
	}
	return nil
}

func inspectSubstrate(repo, id string, substrate Substrate) checkEvidence {
	evidence := checkEvidence{Required: []string{id, substrate.Identity, substrate.ContractFile, substrate.ContractSHA256, substrate.Execution, substrate.Verifier}}
	if err := validateSubstrate("substrate "+id, substrate); err != nil {
		evidence.Detail = err.Error()
		return evidence
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
		if substrate.Execution == "command" && !strings.HasSuffix(substrate.Identity, "@"+commandDigest) {
			evidence.Detail = fmt.Sprintf("command substrate identity does not bind executable digest %s", commandDigest)
			return evidence
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
	evidence.Detail = "substrate identity, out-of-process execution, and committed contract digest are pinned"
	return evidence
}

type runtimeFunction struct {
	decl    *ast.FuncDecl
	file    string
	imports map[string]string
}

type runtimeTrace struct {
	buildBound       bool
	startBound       bool
	completeBound    bool
	handConstructed  bool
	httptest         bool
	commandExecution bool
	containerExec    bool
	endpointUsed     bool
	visited          map[string]bool
	active           map[string]bool
	functions        map[string]runtimeFunction
	entryID          string
	constructor      string
	commandLiteral   string
	containerImage   string
}

type runtimeTaint string

const (
	taintDeps         runtimeTaint = "deps"
	taintServer       runtimeTaint = "server"
	taintHandler      runtimeTaint = "handler"
	taintSession      runtimeTaint = "session"
	taintEvidence     runtimeTaint = "evidence"
	taintCommand      runtimeTaint = "external-command"
	taintReceipt      runtimeTaint = "external-execution-receipt"
	taintProbe        runtimeTaint = "sealed-domain-probe"
	taintSubstrate    runtimeTaint = "external-substrate"
	taintEndpoint     runtimeTaint = "external-endpoint"
	taintHTTPResponse runtimeTaint = "external-http-response"
)

func literalTaint(value string) runtimeTaint { return runtimeTaint("literal:" + value) }

func inspectRuntimeBinding(repo string, entry Entry, substrates map[string]Substrate) checkEvidence {
	proof := entry.Runtime
	if !runtimeConfigured(proof) {
		return checkEvidence{Detail: "runtime proof is not configured; compiled/assembled is still a stub until a served test exists"}
	}
	if err := validateRuntime("entry "+entry.ID, proof, substrates); err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	substrate := substrates[proof.SubstrateID]
	if substrateEvidence := inspectSubstrate(repo, proof.SubstrateID, substrate); !substrateEvidence.OK {
		return substrateEvidence
	}
	functions, err := parseRuntimeFunctions(repo, proof.File)
	if err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	if functions[proof.Test].decl == nil {
		return checkEvidence{Detail: fmt.Sprintf("runtime test %s is not declared in %s", proof.Test, proof.File)}
	}
	trace := &runtimeTrace{
		visited:        map[string]bool{},
		active:         map[string]bool{},
		functions:      functions,
		entryID:        entry.ID,
		constructor:    verifierConstructor[substrate.Verifier],
		commandLiteral: firstString(substrate.Command),
		containerImage: substrate.Image,
	}
	trace.evalFunction(proof.Test, nil, 0)
	if trace.handConstructed {
		return checkEvidence{Detail: "runtime test hand-constructs Deps; it must use production buildRunDeps output"}
	}
	missing := make([]string, 0, 6)
	if proof.Mode == "assembled-handler" && !trace.buildBound {
		missing = append(missing, "Build receives production buildRunDeps output")
	}
	if !trace.startBound {
		missing = append(missing, "proof.Start receives this id and the assembled Server.Handler")
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
	return checkEvidence{OK: true, Detail: fmt.Sprintf("%s and %d bounded same-package helpers bind buildRunDeps -> Build -> Handler -> Start -> sealed %s evidence", proof.Test, len(trace.visited)-1, substrate.Verifier)}
}

func parseRuntimeFunctions(repo, rootFile string) (map[string]runtimeFunction, error) {
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
	for _, path := range paths {
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
		case *ast.IfStmt:
			trace.evalExpression(fn, value.Cond, env, depth)
			trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
			if value.Else != nil {
				trace.evalNestedStatement(fn, value.Else, cloneTaints(env), depth, returns)
			}
		case *ast.ForStmt:
			trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
		case *ast.RangeStmt:
			trace.evalStatements(fn, value.Body.List, cloneTaints(env), depth, returns)
		case *ast.DeferStmt:
			trace.evalExpression(fn, value.Call, env, depth)
		case *ast.GoStmt:
			trace.evalExpression(fn, value.Call, env, depth)
		}
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
			if selector.Sel.Name == "Endpoint" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintSubstrate {
				trace.endpointUsed = true
				return []runtimeTaint{taintEndpoint}
			}
			if selector.Sel.Name == "StopAndReceipt" && firstTaint(trace.evalExpression(fn, selector.X, env, depth)) == taintSubstrate {
				return []runtimeTaint{taintReceipt}
			}
			if selector.Sel.Name == "Do" {
				return []runtimeTaint{taintHTTPResponse, ""}
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
					return []runtimeTaint{taintSession}
				}
			}
			if importPath == "trstctl.com/trstctl/tools/dodcensus/proof" && selector.Sel.Name == "StartResponse" {
				idBound := false
				responseBound := false
				for _, argument := range value.Args {
					taint := firstTaint(trace.evalExpression(fn, argument, env, depth))
					idBound = idBound || taint == literalTaint(trace.entryID)
					responseBound = responseBound || taint == taintHTTPResponse
				}
				if idBound && responseBound {
					trace.startBound = true
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

type runtimeReceipt struct {
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

type runtimeTestExecution struct {
	result       commandResult
	passed       bool
	skipped      bool
	failed       bool
	expectations map[string]runtimeExpectation
	receiptDir   string
}

func runtimeCacheKey(profileName string, entry Entry) string {
	return strings.Join([]string{profileName, entry.Runtime.Package, entry.Runtime.Test}, "\x00")
}

func groupRuntimeEntries(manifest Manifest) map[string][]Entry {
	groups := map[string][]Entry{}
	for _, entry := range manifest.Entries {
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
		if execution != nil && execution.receiptDir != "" {
			_ = os.RemoveAll(execution.receiptDir)
		}
	}
}

func runRuntimeProof(ctx context.Context, repo string, entry Entry, profileName string, profile BuildProfile, substrate Substrate, runner commandRunner, group []Entry, cache map[string]*runtimeTestExecution) checkEvidence {
	key := runtimeCacheKey(profileName, entry)
	execution := cache[key]
	if execution == nil {
		var err error
		execution, err = executeRuntimeTest(ctx, repo, profileName, profile, substrate, group, runner)
		if err != nil {
			return checkEvidence{Detail: err.Error()}
		}
		cache[key] = execution
	}
	if execution.skipped {
		return checkEvidence{Detail: "runtime proof skipped; skips never prove a shipped capability"}
	}
	if execution.failed || !execution.passed {
		detail := strings.TrimSpace(execution.result.Stderr)
		if detail == "" {
			detail = "dedicated runtime test did not pass"
		}
		return checkEvidence{Detail: detail}
	}
	expected, ok := execution.expectations[entry.ID]
	if !ok {
		return checkEvidence{Detail: "shared runtime execution did not receive this entry's independent expectation"}
	}
	if expected.SubstrateID != entry.Runtime.SubstrateID || expected.SubstrateIdentity != substrate.Identity {
		return checkEvidence{Detail: "cached runtime expectation belongs to a different substrate"}
	}
	if err := validateReceipt(expected); err != nil {
		return checkEvidence{Detail: err.Error()}
	}
	return checkEvidence{OK: true, Detail: fmt.Sprintf("%s passed without skip and wrote an exact nonce/id/route/profile/substrate/digest-bound JSON receipt", entry.Runtime.Test)}
}

func executeRuntimeTest(ctx context.Context, repo, profileName string, profile BuildProfile, substrate Substrate, group []Entry, runner commandRunner) (*runtimeTestExecution, error) {
	if len(group) == 0 {
		return nil, fmt.Errorf("runtime test has no grouped manifest expectations")
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
	execution := &runtimeTestExecution{expectations: map[string]runtimeExpectation{}, receiptDir: receiptDir}
	for _, groupedEntry := range group {
		substrateID := groupedEntry.Runtime.SubstrateID
		if substrateID != group[0].Runtime.SubstrateID {
			_ = os.RemoveAll(receiptDir)
			return nil, fmt.Errorf("shared runtime test mixes substrate ids; split the dedicated tests")
		}
		// All grouped entries were already manifest-validated. The substrate is
		// supplied to proof.Start through this signed-off expectation, never by
		// arbitrary test strings.
		expectation := runtimeExpectation{
			SchemaVersion: 1, Repo: repo, Nonce: nonce, ID: groupedEntry.ID, BuildProfile: profileName,
			Method: groupedEntry.Runtime.Method, Path: groupedEntry.Runtime.Path,
			SubstrateID:   substrateID,
			SubstrateKind: substrate.Kind, SubstrateIdentity: substrate.Identity,
			ContractDigest: substrate.ContractSHA256, Verifier: substrate.Verifier,
			Execution: substrate.Execution, Command: append([]string(nil), substrate.Command...), Image: substrate.Image,
			ReceiptFile: filepath.Join(receiptDir, strings.ReplaceAll(groupedEntry.ID, ".", "_")+".json"),
			Required:    map[string]string{},
		}
		execution.expectations[groupedEntry.ID] = expectation
	}
	payload, err := sortedExpectationJSON(execution.expectations)
	if err != nil {
		_ = os.RemoveAll(receiptDir)
		return nil, fmt.Errorf("encode runtime expectations: %w", err)
	}
	runtimeProfile := profile
	runtimeProfile.HostRuntime = true
	runtimeProfile.RuntimeEnv = map[string]string{"TRSTCTL_DOD_EXPECTATIONS": string(payload)}
	args := []string{"test"}
	if len(profile.Tags) > 0 {
		args = append(args, "-tags="+strings.Join(profile.Tags, ","))
	}
	proof := group[0].Runtime
	args = append(args, "-json", "-count=1", "-run", "^"+regexp.QuoteMeta(proof.Test)+"$", proof.Package)
	execution.result = runner.Run(ctx, repo, runtimeProfile, "go", args...)
	execution.passed, execution.skipped, execution.failed = parseTestOutcome(execution.result, proof.Test)
	return execution, nil
}

func validateReceipt(expected runtimeExpectation) error {
	info, err := os.Stat(expected.ReceiptFile)
	if err != nil {
		return fmt.Errorf("runtime test passed without unique JSON receipt for %s: %w", expected.ID, err)
	}
	if info.IsDir() || info.Size() <= 0 || info.Size() > maxReceiptBytes {
		return fmt.Errorf("runtime receipt for %s has invalid size %d", expected.ID, info.Size())
	}
	file, err := os.Open(expected.ReceiptFile)
	if err != nil {
		return fmt.Errorf("open runtime receipt: %w", err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxReceiptBytes+1))
	decoder.DisallowUnknownFields()
	var receipt runtimeReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return fmt.Errorf("decode runtime receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("runtime receipt contains trailing JSON")
	}
	if receipt.SchemaVersion != 1 || receipt.Nonce != expected.Nonce || receipt.ID != expected.ID || receipt.BuildProfile != expected.BuildProfile || receipt.Method != expected.Method || receipt.Path != expected.Path || receipt.SubstrateID != expected.SubstrateID || receipt.SubstrateKind != expected.SubstrateKind || receipt.SubstrateIdentity != expected.SubstrateIdentity || receipt.ContractDigest != expected.ContractDigest || receipt.Verifier != expected.Verifier {
		return fmt.Errorf("runtime receipt identity/nonce/route/profile/substrate/digest does not exactly match the gate expectation")
	}
	if !receipt.Passed || receipt.Skipped {
		return fmt.Errorf("runtime receipt is not pass=true, skip=false")
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
	for key, want := range expected.Required {
		if receipt.Observations[key] != want {
			return fmt.Errorf("runtime receipt observation %q does not match gate-issued substrate evidence", key)
		}
	}
	return nil
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
