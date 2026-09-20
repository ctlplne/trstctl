// SPDX-License-Identifier: BUSL-1.1

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
	Doc:  "SEC-005: new outbound HTTP and exec surfaces must use netsec/egress clients or validated argv, not ambient DefaultClient, ambient http.Client construction, package-level http.Get/Post helpers, or shell interpreters.",
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

// ambientHTTPClientGuardPackages are the two packages that IMPLEMENT the
// sanctioned outbound path. They must build *http.Client values by hand — that
// is their whole job — so the ambient-construction rule cannot apply to them
// without becoming circular. This exemption is permanent by design and is
// deliberately package-scoped and tiny: every OTHER package has to obtain its
// client from netsec.SafeClient / netsec.InsecureLoopbackClient /
// egress.Guard.Client, or carry a reviewed row in reviewedAmbientHTTPClients.
var ambientHTTPClientGuardPackages = map[string]bool{
	"trstctl.com/trstctl/internal/netsec": true,
	"trstctl.com/trstctl/internal/egress": true,
}

// reviewedAmbientHTTPClients is the SEC-005 burn-down ledger, not a permanent
// exemption list. It is pre-sized to the ambient `&http.Client{...}` sites that
// already existed when the rule landed, so the rule could be turned on without a
// 27-file big-bang. Every row is debt: it means that call site still builds its
// own client instead of going through the reviewed netsec/egress path. Rows come
// OUT as sites migrate; no row may be added for new code. The first burn-down
// pass took it from 27 to 20: the CT-log fetcher and the ARI client now default
// to netsec.SafeClient, and the agent HTTP enroller, the ACME HTTP-01
// conformance escape hatch, the perf live stack, and the PQC lab now default to
// netsec.InsecureLoopbackClient.
var reviewedAmbientHTTPClients = map[string]map[string]bool{
	"cmd/trstctl-agent/main.go": {
		"enrollmentHTTPClient": true,
	},
	"cmd/trstctl/main.go": {
		"controlPlaneProbe": true,
	},
	"internal/agent/k8s/client.go": {
		"InCluster": true,
		"New":       true,
	},
	"internal/agent/k8s/signer.go": {
		"NewHTTPSigner": true,
	},
	"internal/aimodel/http.go": {
		"NewHTTPCompleter": true,
	},
	"internal/cli/cli.go": {
		"httpClientForEnv": true,
	},
	"internal/crypto/mtls/server.go": {
		"LoopbackProbeClient": true,
	},
	// A3 relay runtime. This is the one outbound surface in the tree that
	// deliberately does NOT carry the SSRF transport or the egress guard, and
	// the reason is architectural rather than convenient: a network relay exists
	// to reach appliances on private, non-routable addresses inside its own
	// segment — an F5 management interface on 10.x, a NetScaler on a management
	// VLAN — which is precisely the destination class those controls are built
	// to refuse. Wrapping this client would not harden the relay; it would stop
	// it working at all, and the pressure would then be to punch holes in the
	// guard for private ranges globally, which is worse.
	//
	// What replaces the control here is placement: the endpoint is validated at
	// target-config ADMISSION on the control plane (validateConnectorEndpoint),
	// the relay only ever receives targets that passed it, and an operator
	// granting the network role is granting reachability into that segment
	// explicitly. docs/limitations.md states the reduction rather than leaving
	// it to be discovered.
	"cmd/trstctl-agent/relayloop.go": {
		"relayHTTPClient": true,
	},
	// Moved from internal/observ/otlp.go (same construction, same rationale)
	// when the exporter was split out so the observ metrics core could stay
	// linkable by the agent binary (A3 import boundary). The exporter's endpoint
	// comes from operator configuration and is egress-guarded by the caller
	// (otlpExporterFromConfig wraps the transport); the ambient client here is
	// the pre-guard base that the wrap replaces.
	"internal/observ/otlp/otlp.go": {
		"NewHTTPExporter": true,
	},
	"internal/operator/client.go": {
		"InCluster": true,
		"NewClient": true,
	},
	"internal/operator/secretsync.go": {
		"NewHTTPSecretResolver": true,
	},
	"internal/server/auth.go": {
		"buildOIDCAuthConfig": true,
	},
	"internal/server/external_ca_config.go": {
		"externalCAHTTPClient": true,
	},
	"internal/server/run_connectors.go": {
		"connectorHTTPClientFromConfig": true,
	},
	"internal/telemetry/poster.go": {
		"HTTPPoster": true,
	},
	"internal/terraformprovider/client.go": {
		"NewClient": true,
	},
	"tools/dodcensus/proof/launched.go": {
		"Do": true,
	},
	"tools/dodcensus/proof/proof.go": {
		"brokerRequest": true,
		"cleanup":       true,
	},
}

var reviewedExecUses = map[string]map[string]bool{
	// The vendored embedded-Postgres launcher executes only fixed PostgreSQL
	// utilities from the checksum-pinned archive (plus the fixed local `uname`
	// probe). No shell is involved, the password uses a mode-0600 file, and the
	// exact function set is pinned by TestReviewedExecAllowlistPinsEmbeddedPostgres.
	"third_party/embedded-postgres/embedded_postgres.go": {
		"startPostgres": true,
		"stopPostgres":  true,
	},
	"third_party/embedded-postgres/prepare_database.go": {
		"defaultInitDatabase": true,
	},
	"third_party/embedded-postgres/version_strategy.go": {
		"linuxMachineName": true,
	},
	// A5's single-box demo spawns the SIBLING trstctl-agent binary. Reviewed
	// rather than refactored because there is nothing to validate away: the
	// program is resolved beside this executable (or from PATH) and never comes
	// from a request, every argv entry is built from this process's own
	// configuration, and no shell is involved. Exec is also the POINT — the
	// agent binary must not link the control plane
	// (docs/agent_binary_import_boundary_test.go), so a demo that avoided the
	// process boundary would violate a stronger rule than this one.
	//
	// Covered by cmd/trstctl/demo_test.go, which pins that the demo execs rather
	// than imports the agent and that the bootstrap token travels by 0600 file
	// rather than as an argument.
	"cmd/trstctl/demo.go": {
		"runDemoAgent": true,
	},
	"tools/pqclab/main.go": {
		"newValidatedCommand": true,
	},
	"tools/dodcensus/main.go": {
		"Run": true,
	},
	"tools/dodcensus/proof/proof.go": {
		"StartCommand":   true,
		"StartContainer": true,
	},
	"tools/dodcensus/proof/launched.go": {
		"buildShippedProcess":        true,
		"companionProductionClosure": true,
		"CreateToken":                true,
		"Start":                      true,
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
		case *ast.CompositeLit:
			if isHTTPClientLiteral(pass, x) && !isAmbientHTTPGuardPackage(pass) && !reviewedUse(pass, x.Pos(), funcName, reviewedAmbientHTTPClients) {
				pass.Reportf(x.Pos(), "ambient http.Client construction is not allowed in new outbound surfaces (SEC-005); use internal/netsec.SafeClient, internal/netsec.InsecureLoopbackClient, or egress.Guard.Client so the SSRF and egress checks cannot be bypassed")
			}
		case *ast.CallExpr:
			if isAmbientHTTPPackageCall(pass, x) {
				pass.Reportf(x.Pos(), "http.Get/http.Head/http.Post/http.PostForm are not allowed (SEC-005); these use http.DefaultClient implicitly, so call the method on a client from internal/netsec or egress.Guard instead")
				return true
			}
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

// isHTTPClientLiteral reports whether a composite literal constructs a
// net/http.Client. It resolves the literal's type, so an import alias, a dot
// import, or a type alias cannot spell its way past the rule.
func isHTTPClientLiteral(pass *analysis.Pass, lit *ast.CompositeLit) bool {
	tv, ok := pass.TypesInfo.Types[lit]
	if !ok || tv.Type == nil {
		return false
	}
	named, ok := types.Unalias(tv.Type).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "Client" && obj.Pkg() != nil && obj.Pkg().Path() == "net/http"
}

// isAmbientHTTPPackageCall reports whether a call is one of the package-level
// net/http helpers that silently use http.DefaultClient. The receiver check is
// load-bearing: client.Get(url) on a reviewed *http.Client is exactly the shape
// we want callers to use, and must not be flagged.
func isAmbientHTTPPackageCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "net/http" {
		return false
	}
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		return false
	}
	switch fn.Name() {
	case "Get", "Head", "Post", "PostForm":
		return true
	}
	return false
}

func isAmbientHTTPGuardPackage(pass *analysis.Pass) bool {
	if pass.Pkg == nil {
		return false
	}
	return ambientHTTPClientGuardPackages[basePackagePath(pass.Pkg.Path())]
}

// basePackagePath strips the go/packages test-variant suffix ("p [p.test]").
// Without it a guard package would lose its exemption the moment `go vet`
// re-analyzed it as part of its own test binary, and `make lint` would fail on
// internal/netsec itself.
func basePackagePath(path string) string {
	if i := strings.Index(path, " ["); i >= 0 {
		return path[:i]
	}
	return path
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
