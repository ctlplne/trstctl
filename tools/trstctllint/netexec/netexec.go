// SPDX-License-Identifier: MPL-2.0

// Package netexec enforces the SEC-005 hardening guardrail: new outbound HTTP
// and process-exec surfaces must use the shared SSRF primitives or validated
// argv paths instead of ambient defaults.
package netexec

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer blocks unreviewed additions of unsafe outbound and process execution
// surfaces. Existing call sites in provider SDK wrappers, signer supervision, and
// test utilities are allowlisted by file and function so new surfaces fail closed.
var Analyzer = &analysis.Analyzer{
	Name: "netexec",
	Doc:  "SEC-005: new outbound HTTP and exec surfaces must use netsec clients or validated argv, not ambient DefaultClient or shell interpreters.",
	Run:  run,
}

var reviewedDefaultClientUses = map[string]map[string]bool{
	"cmd/trstctl/connector.go": {
		"": true,
	},
	"internal/authmethod/aws_iam.go": {
		"GetCallerIdentity": true,
	},
	"internal/connector/azurekv/token.go": {
		"NewClientCredentials": true,
	},
	"internal/connector/gcpcm/token.go": {
		"NewMetadataToken": true,
	},
	"internal/connector/httpops.go": {
		"NewHTTPOps": true,
	},
	"internal/discovery/cloudcert/acmdisc/acmdisc.go": {
		"New": true,
	},
	"internal/discovery/cloudcert/gcmdisc/gcmdisc.go": {
		"New": true,
	},
	"internal/discovery/cloudcert/kvdisc/kvdisc.go": {
		"New": true,
	},
	"internal/dns/acmedns/acmedns.go": {
		"New": true,
	},
	"internal/dns/akamai/akamai.go": {
		"New": true,
	},
	"internal/dns/azuredns/azuredns.go": {
		"New": true,
	},
	"internal/dns/cloudflare/cloudflare.go": {
		"New": true,
	},
	"internal/dns/googledns/googledns.go": {
		"New": true,
	},
	"internal/dns/ns1/ns1.go": {
		"New": true,
	},
	"internal/dns/route53/route53.go": {
		"New": true,
	},
	"internal/dns/ultradns/ultradns.go": {
		"New": true,
	},
	"internal/dns/webhook/webhook.go": {
		"New": true,
	},
	"internal/dynsecret/providers_real.go": {
		"NewAWSIAMBackend":     true,
		"NewAzureEntraBackend": true,
		"NewGCPIAMBackend":     true,
		"NewKubernetesBackend": true,
	},
	"internal/kms/awskms/awskms.go": {
		"New": true,
	},
	"internal/kms/azurekv/azurekv.go": {
		"New": true,
	},
	"internal/kms/gcpkms/gcpkms.go": {
		"New": true,
	},
	"internal/secretsync/pushers.go": {
		"NewAWSSecretsManagerPusher": true,
		"NewAzureKeyVaultPusher":     true,
		"NewGCPSecretManagerPusher":  true,
		"NewGitHubActionsPusher":     true,
		"NewGitLabCIPusher":          true,
		"NewJSONPusher":              true,
		"NewKubernetesPusher":        true,
		"NewVercelPusher":            true,
	},
	"internal/spireupstream/plugin.go": {
		"New":        true,
		"httpClient": true,
	},
}

var reviewedExecUses = map[string]map[string]bool{
	"tools/dodcensus/main.go": {
		"Run": true,
	},
	"tools/dodcensus/proof/proof.go": {
		"StartCommand":   true,
		"StartContainer": true,
	},
	"tools/dodcensus/proof/launched.go": {
		"buildShippedProcess": true,
		"CreateToken":         true,
		"Start":               true,
	},
	"tools/dodcensus/runtime_runner.go": {
		"runHostCommand": true,
	},
	"tools/dodcensus/substrate_broker.go": {
		"launch": true,
	},
	"cmd/trstctl-agent/sshtrust.go": {
		"runCommandLine": true,
	},
	"internal/ca/shellca/shellca.go": {
		"run": true,
	},
	"internal/connector/localops.go": {
		"ExecContext": true,
	},
	"internal/perf/live.go": {
		"liveSignerBinary": true,
		"commandOutput":    true,
	},
	"internal/crypto/kmswrap/external_kms.go": {
		"run": true,
	},
	"internal/secretscan/gitdiff.go": {
		"gitOutput": true,
	},
	"internal/secretscan/gitleaks.go": {
		"ScanWithOptions": true,
	},
	"internal/secretscan/repository.go": {
		"runGit": true,
	},
	"internal/secretscli/secretscli.go": {
		"InjectIO": true,
	},
	"internal/server/bundled_pg_verify.go": {
		"unameMachine": true,
	},
	"internal/server/signer_token_command.go": {
		"Authorize": true,
	},
	"internal/signing/supervisor.go": {
		"Start":      true,
		"StartChild": true,
		"run":        true,
	},
	"internal/testutil/openssltest/openssltest.go": {
		"SupportsVerifyPartialChain": true,
		"commandOK":                  true,
	},
}

var shellInterpreters = map[string]bool{
	"bash":       true,
	"cmd":        true,
	"dash":       true,
	"fish":       true,
	"ksh":        true,
	"powershell": true,
	"pwsh":       true,
	"sh":         true,
	"zsh":        true,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		if isTestFile(pass, file) {
			continue
		}
		checkFile(pass, file)
	}
	return nil, nil
}

func checkFile(pass *analysis.Pass, file *ast.File) {
	checkNode := func(funcName string, n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if isHTTPDefaultClient(pass, x) && !reviewedUse(pass, x.Pos(), funcName, reviewedDefaultClientUses) {
				pass.Reportf(x.Pos(), "http.DefaultClient is not allowed in new outbound surfaces (SEC-005); use internal/netsec.SafeClient or add a reviewed package-specific client seam")
			}
		case *ast.CallExpr:
			if isExecCommandCall(pass, x) {
				if commandIsShell(pass, x) {
					pass.Reportf(x.Pos(), "direct shell interpreter execution is not allowed (SEC-005); pass validated argv to the target binary instead")
					return true
				}
				if !reviewedUse(pass, x.Pos(), funcName, reviewedExecUses) {
					pass.Reportf(x.Pos(), "exec.Command is not allowed in new process surfaces (SEC-005); use an existing validated argv primitive or add a reviewed allowlist entry with tests")
				}
			}
		}
		return true
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n == nil {
					return true
				}
				return checkNode(fn.Name.Name, n)
			})
			continue
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			if n == nil {
				return true
			}
			return checkNode("", n)
		})
	}
}

func isHTTPDefaultClient(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	obj := pass.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Name() != "DefaultClient" || obj.Pkg() == nil || obj.Pkg().Path() != "net/http" {
		return false
	}
	_, ok := obj.(*types.Var)
	return ok
}

func isExecCommandCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := pass.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "os/exec" {
		return false
	}
	return obj.Name() == "Command" || obj.Name() == "CommandContext"
}

func commandIsShell(pass *analysis.Pass, call *ast.CallExpr) bool {
	cmdArg := 0
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CommandContext" {
		cmdArg = 1
	}
	if len(call.Args) <= cmdArg {
		return false
	}
	tv, ok := pass.TypesInfo.Types[call.Args[cmdArg]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	raw := constant.StringVal(tv.Value)
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(raw)), ".exe")
	return shellInterpreters[base]
}

func reviewedUse(pass *analysis.Pass, pos token.Pos, funcName string, allow map[string]map[string]bool) bool {
	file := normalizedFilename(pass, pos)
	for suffix, funcs := range allow {
		if strings.HasSuffix(file, suffix) && funcs[funcName] {
			return true
		}
	}
	return false
}

func normalizedFilename(pass *analysis.Pass, pos token.Pos) string {
	name := pass.Fset.Position(pos).Filename
	name = filepath.ToSlash(name)
	if i := strings.Index(name, "/trstctl.com/trstctl/"); i >= 0 {
		return name[i+len("/trstctl.com/trstctl/"):]
	}
	return strings.TrimPrefix(name, "./")
}

func isTestFile(pass *analysis.Pass, file *ast.File) bool {
	return strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go")
}
