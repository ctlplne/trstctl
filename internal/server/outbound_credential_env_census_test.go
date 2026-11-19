// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// CR-008: the value behind a tenant-authored env reference is read in one place,
// after the binding check, and only the operator-owned resolvers read one without
// a tenant binding. The census over the non-test files of this package fails when
//
//	(a) an env reader (os.LookupEnv, os.Getenv, os.Environ, os.ExpandEnv,
//	    os.Expand, syscall.Getenv, syscall.Environ, or one of them passed as a
//	    value) takes a name that is not a constant, outside lookupEnvCredential
//	    and resolveDeploymentCredentialRef;
//	(b) resolveOperatorCredentialRef or resolveOperatorCredentialBytesRef is used
//	    outside the ServiceNow ticket and close handlers and the Slack app;
//	(c) PinClient or a bound resolver is handed http.DefaultClient;
//	(d) lookupEnvCredential is used outside the three resolvers in
//	    outbound_credentials.go;
//	(e) resolveDeploymentCredentialRef, which also reads file: references, is used
//	    outside the four Provider-plane files;
//	(f) boundCredentialEnvValue, which reads a value without pinning a client, is
//	    used outside its fixed-destination callers.
//
// A guarded resolver is only ever called directly, never passed on as a value.
// Rule (a) also covers this package's subdirectories, the API and the packages
// that decode tenant integration config, and there even an env read by a
// constant name must be one of the reviewed (file, name) pairs below, so no
// provider falls back to an ambient deployment credential.
func TestOutboundEnvCredentialReadsStayInTheResolvers(t *testing.T) {
	census := serverEnvCensus()
	census.constantAllow = reviewedConstantEnvReads
	if err := census.dir("."); err != nil {
		t.Fatal(err)
	}
	for _, v := range census.violations {
		t.Error(v)
	}
	// The census must still see the sites it guards; a rename or a parser
	// change that hides them must fail here rather than pass silently.
	for name, least := range map[string]int{
		"lookupEnvCredential":               3,
		"resolveOperatorCredentialRef":      3,
		"resolveOperatorCredentialBytesRef": 3,
		"resolveDeploymentCredentialRef":    4,
		"boundCredentialEnvValue":           7,
		"env read by a resolver":            2,
		"bound client call":                 1,
	} {
		if got := census.found[name]; got < least {
			t.Errorf("the census saw %d uses of %s, want at least %d; it lost track of them", got, name, least)
		}
	}

	// Rule (a) over the packages that decode tenant integration config. The
	// secret scanner hands its subprocess the environment through one of its
	// sanitizers, which strip the variables that could inject configuration.
	for _, root := range []string{".", "../api", "../discovery", "../cloudentitlements", "../auditsink", "../scancollect",
		"../scanannotate", "../oauthrevoke", "../secretscan"} {
		dirs := []string{}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				if root == "." && path == "." {
					return nil // this package itself ran under every rule above
				}
				dirs = append(dirs, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range dirs {
			pkg := &envCensus{environArgs: map[string]bool{"sanitizedGitleaksEnv": true, "sanitizedGitEnv": true},
				constantAllow: reviewedConstantEnvReads}
			if err := pkg.dir(dir); err != nil {
				t.Fatal(err)
			}
			for _, v := range pkg.violations {
				t.Error(v)
			}
		}
	}
}

// The census itself: each rule refuses the use it exists for and accepts what it
// allows, so a census that reads nothing cannot pass.
func TestOutboundEnvCredentialCensusCatchesEveryRule(t *testing.T) {
	refused := map[string]string{
		"a: a computed name":             "package server\nimport \"os\"\nfunc readName(name string) string { return os.Getenv(name) }\n",
		"a: lookup as a value":           "package server\nimport \"os\"\nvar lookup = os.LookupEnv\n",
		"a: the whole environment":       "package server\nimport \"os\"\nfunc all() []string { return os.Environ() }\n",
		"a: expansion":                   "package server\nimport \"os\"\nfunc expand(s string) string { return os.ExpandEnv(s) }\n",
		"a: expansion through getenv":    "package server\nimport \"os\"\nfunc expand(s string) string { return os.Expand(\"$X\", os.Getenv) }\n",
		"a: an aliased import":           "package server\nimport goos \"os\"\nfunc readName(name string) string { return goos.Getenv(name) }\n",
		"a: syscall":                     "package server\nimport \"syscall\"\nfunc readName(name string) (string, bool) { return syscall.Getenv(name) }\n",
		"a: syscall environment":         "package server\nimport \"syscall\"\nfunc all() []string { return syscall.Environ() }\n",
		"a: a dot import":                "package server\nimport . \"os\"\nfunc readName(name string) string { return Getenv(name) }\n",
		"a: a parameter shadows a const": "package server\nimport \"os\"\nconst envName = \"TRSTCTL_X\"\nfunc readName(envName string) string { return os.Getenv(envName) }\n",
		"b: another worker":              "package server\nimport \"context\"\nfunc (d *issuanceDispatcher) handleOther(ctx context.Context) { _, _ = resolveOperatorCredentialRef(ctx, \"env:X\") }\n",
		"b: bytes from another worker":   "package server\nimport \"context\"\nfunc handleOther(ctx context.Context) { _, _ = resolveOperatorCredentialBytesRef(ctx, \"env:X\") }\n",
		"b: as a value":                  "package server\nvar resolve = resolveOperatorCredentialRef\n",
		"c: pinning the default client":  "package server\nimport (\"net/http\"; \"trstctl.com/trstctl/internal/outboundcred\")\nfunc pin() error { return outboundcred.PinClient(http.DefaultClient, nil) }\n",
		"c: resolving onto it":           "package server\nimport (\"context\"; \"net/http\")\nfunc use(ctx context.Context, ref string) { _, _ = resolveBoundCredentialRef(ctx, ref, http.DefaultClient) }\n",
		"d: another resolver":            "package server\nfunc resolveOther(ref string) (string, error) { return lookupEnvCredential(ref) }\n",
		"e: another file":                "package server\nfunc collect(ref string) { _, _ = resolveDeploymentCredentialRef(ref) }\n",
		"a: x/sys getenv":                "package server\nimport \"golang.org/x/sys/unix\"\nfunc readName(name string) (string, bool) { return unix.Getenv(name) }\n",
		"a: a command's environment":     "package server\nimport \"os/exec\"\nfunc all() []string { return exec.Command(\"true\").Environ() }\n",
		"b: passed on as a value":        "package server\nimport \"context\"\nfunc (d *issuanceDispatcher) handleServiceNowTicket(ctx context.Context) { use(resolveOperatorCredentialRef) }\n",
		"b: a Slack method elsewhere":    "package server\nimport \"context\"\nfunc (a *slackAppServer) other(ctx context.Context) { _, _ = resolveOperatorCredentialBytesRef(ctx, \"env:X\") }\n",
		"f: an unpinned read elsewhere":  "package server\nimport \"context\"\nfunc (d *issuanceDispatcher) collect(ctx context.Context, ref string) { _, _ = boundCredentialEnvValue(ctx, ref, \"https://x.example\") }\n",
	}
	for name, src := range refused {
		census := serverEnvCensus()
		if err := census.source("other.go", src); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(census.violations) == 0 {
			t.Errorf("%s: the census accepted it", name)
		}
	}
	// The direct-call rule fails on its own: an allowed owner in its own file
	// passes the resolver on as a value.
	passedOn := serverEnvCensus()
	if err := passedOn.source("itsm.go", "package server\nimport \"context\"\nfunc (d *issuanceDispatcher) handleServiceNowTicket(ctx context.Context) { use(resolveOperatorCredentialRef) }\n"); err != nil {
		t.Fatal(err)
	}
	if len(passedOn.violations) == 0 {
		t.Error("b: an allowed owner passing the resolver on as a value was accepted")
	}
	// Package scope is no allowed owner of the unpinned resolver.
	packageScope := serverEnvCensus()
	if err := packageScope.source("other.go", "package server\nimport \"context\"\nvar _, _ = boundCredentialEnvValue(context.Background(), \"env:X\", \"https://x.example\")\n"); err != nil {
		t.Fatal(err)
	}
	if len(packageScope.violations) == 0 {
		t.Error("f: a package-scope call of the unpinned resolver was accepted")
	}
	// Outside the reviewed (file, name) pairs, an env read by a constant name is
	// an ambient credential fallback.
	ambient := serverEnvCensus()
	ambient.constantAllow = reviewedConstantEnvReads
	if err := ambient.source("vault.go", "package discovery\nimport \"os\"\nfunc token() string { return os.Getenv(\"VAULT_TOKEN\") }\n"); err != nil {
		t.Fatal(err)
	}
	if len(ambient.violations) == 0 {
		t.Error("a: an ambient constant-name env read was accepted")
	}
	// The resolver rules are tied to their files as well as their functions.
	census := serverEnvCensus()
	if err := census.source("other.go", "package server\nfunc resolveBoundCredentialRef(ref string) (string, error) { return lookupEnvCredential(ref) }\n"); err != nil {
		t.Fatal(err)
	}
	if len(census.violations) == 0 {
		t.Error("d: a resolver of the same name in another file was accepted")
	}

	allowed := map[string]string{
		"outbound_credentials.go": "package server\nimport \"os\"\nfunc lookupEnvCredential(ref string) (string, error) { v, _ := os.LookupEnv(ref); return v, nil }\n" +
			"func resolveOperatorCredentialRef(ref string) (string, error) { return lookupEnvCredential(ref) }\n",
		"itsm.go":              "package server\nimport \"context\"\nfunc (d *issuanceDispatcher) handleServiceNowTicket(ctx context.Context) { _, _ = resolveOperatorCredentialRef(ctx, \"env:X\") }\n",
		"slack_app.go":         "package server\nimport \"context\"\nfunc (a *slackAppServer) verified(ctx context.Context) { _, _ = resolveOperatorCredentialBytesRef(ctx, \"env:X\") }\n",
		"audit_feed_syslog.go": "package server\nimport \"context\"\nfunc deliverSyslogBatch(ctx context.Context, ref string) { _, _ = boundCredentialEnvValue(ctx, ref, \"syslog+tls://x.example\") }\n",
		"provider_rmm.go":      "package server\nfunc collect(ref string) { _, _ = resolveDeploymentCredentialRef(ref) }\n",
		"constants.go":         "package server\nimport \"os\"\nconst prefix = \"TRSTCTL_\"\nconst envName = prefix + \"X\"\nfunc read() string { return os.Getenv(envName) + os.Getenv(\"TRSTCTL_Y\") + os.Getenv(prefix+\"Z\") }\n",
		"bound.go":             "package server\nimport (\"context\"; \"net/http\")\nfunc use(ctx context.Context, ref string) { _, _ = resolveBoundCredentialRef(ctx, ref, &http.Client{}) }\n",
	}
	for file, src := range allowed {
		census := serverEnvCensus()
		if err := census.source(file, src); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, v := range census.violations {
			t.Errorf("%s: %s", file, v)
		}
	}
	scanner := &envCensus{environArgs: map[string]bool{"sanitizedGitEnv": true}}
	if err := scanner.source("repository.go", "package secretscan\nimport \"os\"\nfunc env() []string { return sanitizedGitEnv(os.Environ()) }\nfunc sanitizedGitEnv(e []string) []string { return e }\n"); err != nil {
		t.Fatal(err)
	}
	for _, v := range scanner.violations {
		t.Errorf("a sanitized subprocess environment was refused: %s", v)
	}
	if err := scanner.source("other.go", "package secretscan\nimport \"os\"\nfunc env() []string { e := os.Environ(); return sanitizedGitEnv(e) }\n"); err != nil {
		t.Fatal(err)
	}
	if len(scanner.violations) == 0 {
		t.Error("a: an environment read outside the sanitizer argument was accepted")
	}
}

// serverEnvCensus returns the census rules for this package.
func serverEnvCensus() *envCensus {
	serviceNowOrSlack := func(file, owner string) bool {
		return (file == "itsm.go" && owner == "issuanceDispatcher.handleServiceNowTicket") ||
			(file == "itsm_close.go" && owner == "issuanceDispatcher.handleServiceNowClose") ||
			(file == "slack_app.go" && strings.HasPrefix(owner, "slackAppServer."))
	}
	// The fixed-destination callers name the exact destinations their client
	// dials; a new one needs review and an endpoint-equality test.
	fixedDestination := map[string]string{
		"audit_feed_syslog.go":        "deliverSyslogBatch",
		"cloud_entitlements.go":       "issuanceDispatcher.executeCloudMachineEntitlementRun",
		"cloud_gcp_inventory.go":      "issuanceDispatcher.executeGCPMachineIdentityRun",
		"cloud_azure_inventory.go":    "issuanceDispatcher.executeAzureMachineIdentityRun",
		"cloud_machine_changes.go":    "issuanceDispatcher.handleCloudMachineChange",
		"cloud_replacement_worker.go": "issuanceDispatcher.replacementRoleReadback",
	}
	providerFiles := []string{"provider_billing_sync.go", "provider_psa_tickets.go", "provider_rmm.go", "provider_doc_records.go"}
	return &envCensus{
		readers: map[string]bool{"lookupEnvCredential": true, "resolveDeploymentCredentialRef": true},
		guarded: map[string]func(file, owner string) bool{
			"resolveOperatorCredentialRef": func(file, owner string) bool {
				return serviceNowOrSlack(file, owner) || (file == "outbound_credentials.go" && owner == "resolveOperatorCredentialBytesRef")
			},
			"resolveOperatorCredentialBytesRef": serviceNowOrSlack,
			"lookupEnvCredential": func(file, owner string) bool {
				return file == "outbound_credentials.go" &&
					slices.Contains([]string{"resolveBoundCredentialRef", "boundCredentialEnvValue", "resolveOperatorCredentialRef"}, owner)
			},
			"resolveDeploymentCredentialRef": func(file, _ string) bool { return slices.Contains(providerFiles, file) },
			"boundCredentialEnvValue": func(file, owner string) bool {
				allowed, ok := fixedDestination[file]
				return ok && allowed == owner
			},
		},
		boundClientCallees: map[string]bool{
			"PinClient": true, "resolveBoundCredentialRef": true, "resolveBoundCredentialBytesRef": true,
			"resolveOptionalBoundCredentialRef": true, "resolveOptionalBoundCredentialBytesRef": true,
		},
	}
}

// reviewedConstantEnvReads are the env reads by a constant name the census
// accepts, as file:argument: deployment settings, never tenant credentials.
var reviewedConstantEnvReads = map[string]bool{
	`server/bundled_pg.go:"TRSTCTL_BUNDLED_PG_CACHE_ROOT"`:  true,
	`server/bundled_pg.go:"TRSTCTL_BUNDLED_PG_ARCHIVE_DIR"`: true,
	`server/dod_runtime_export.go:dodRuntimeTempRootEnv`:    true,
	`secretscan/gitleaks.go:"TRSTCTL_GITLEAKS_BIN"`:         true,
}

// envCensus walks Go source for the CR-008 rules.
type envCensus struct {
	// readers may read an env name that is not a constant.
	readers map[string]bool
	// environArgs may take os.Environ() as a direct argument.
	environArgs map[string]bool
	// guarded says, per package function, which file and owner may use it.
	guarded map[string]func(file, owner string) bool
	// boundClientCallees may never be handed http.DefaultClient.
	boundClientCallees map[string]bool
	// constantAllow, when set, lists the only env reads by a constant name the
	// census accepts, as file:argument.
	constantAllow map[string]bool

	// pkg is the package's directory under internal/, the allowlist's prefix.
	pkg        string
	fset       *token.FileSet
	consts     map[string]bool
	found      map[string]int
	violations []string
}

// dir reads every non-test Go file in dir as one package.
func (c *envCensus) dir(dir string) error {
	c.pkg = filepath.ToSlash(filepath.Clean(filepath.Join("server", dir)))
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return err
	}
	sources := map[string][]byte{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) // #nosec G304 -- the census reads this package's own source files by glob (CWE-22)
		if err != nil {
			return err
		}
		sources[name] = src
	}
	return c.files(sources)
}

// source reads one file as a package of its own.
func (c *envCensus) source(name, src string) error {
	return c.files(map[string][]byte{name: []byte(src)})
}

func (c *envCensus) files(sources map[string][]byte) error {
	c.fset = token.NewFileSet()
	c.consts = map[string]bool{}
	if c.found == nil {
		c.found = map[string]int{}
	}
	parsed := map[string]*ast.File{}
	names := make([]string, 0, len(sources))
	for name, src := range sources {
		file, err := parser.ParseFile(c.fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		parsed[name] = file
		names = append(names, name)
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.CONST {
				for _, spec := range gen.Specs {
					for _, ident := range spec.(*ast.ValueSpec).Names {
						c.consts[ident.Name] = true
					}
				}
			}
		}
	}
	slices.Sort(names)
	for _, name := range names {
		c.file(filepath.Base(name), parsed[name])
	}
	return nil
}

func (c *envCensus) file(name string, f *ast.File) {
	imports := map[string]string{}
	for _, spec := range f.Imports {
		path := strings.Trim(spec.Path.Value, "\"")
		local := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			local = spec.Name.Name
		}
		if local == "." && (path == "os" || path == "syscall") {
			c.violations = append(c.violations, c.fset.Position(spec.Pos()).String()+": a dot import of "+path+" hides its env readers from the census")
		}
		imports[local] = path
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			owner := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) == 1 {
				owner = receiverName(d.Recv.List[0].Type) + "." + owner
			}
			locals := declaredNames(d)
			c.inspect(name, owner, locals, imports, d.Type)
			if d.Body != nil {
				c.inspect(name, owner, locals, imports, d.Body)
			}
		default:
			c.inspect(name, "", nil, imports, decl)
		}
	}
}

func (c *envCensus) inspect(file, owner string, locals map[string]bool, imports map[string]string, root ast.Node) {
	where := func(n ast.Node) string {
		in := owner
		if in == "" {
			in = "package scope"
		}
		return c.fset.Position(n.Pos()).String() + " in " + in
	}
	callOf := map[ast.Expr]*ast.CallExpr{}
	argOf := map[*ast.CallExpr]*ast.CallExpr{}
	ast.Inspect(root, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			callOf[call.Fun] = call
			for _, arg := range call.Args {
				if inner, ok := arg.(*ast.CallExpr); ok {
					argOf[inner] = call
				}
			}
		}
		return true
	})
	ast.Inspect(root, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			pkg, ok := x.X.(*ast.Ident)
			if !ok || locals[pkg.Name] {
				return true
			}
			path := imports[pkg.Name]
			switch path {
			case "os":
			case "syscall", "golang.org/x/sys/unix", "golang.org/x/sys/windows":
				path = "syscall"
			default:
				return true
			}
			c.envRead(file, where(x), owner, locals, path+"."+x.Sel.Name, callOf[x], argOf)
		case *ast.Ident:
			if rule, ok := c.guarded[x.Name]; ok && !locals[x.Name] {
				c.found[x.Name]++
				if !rule(file, owner) {
					c.violations = append(c.violations, where(x)+": uses "+x.Name+" outside the sites allowed to")
				} else if callOf[x] == nil {
					c.violations = append(c.violations, where(x)+": passes "+x.Name+" on as a value; call it directly")
				}
			}
		case *ast.CallExpr:
			callee := ""
			switch f := x.Fun.(type) {
			case *ast.Ident:
				callee = f.Name
			case *ast.SelectorExpr:
				callee = f.Sel.Name
				// A command's Environ() (exec.Cmd) is the whole environment too.
				if pkg, ok := f.X.(*ast.Ident); (!ok || imports[pkg.Name] == "") && f.Sel.Name == "Environ" && len(x.Args) == 0 {
					if outer := argOf[x]; outer == nil || !c.environArg(outer) {
						c.violations = append(c.violations, where(x)+": reads the whole environment with a command's Environ()")
					}
				}
			}
			if !c.boundClientCallees[callee] {
				return true
			}
			c.found["bound client call"]++
			for _, arg := range x.Args {
				if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "DefaultClient" {
					if pkg, ok := sel.X.(*ast.Ident); ok && imports[pkg.Name] == "net/http" {
						c.violations = append(c.violations, where(x)+": hands http.DefaultClient to "+callee+"; it is shared by the whole process")
					}
				}
			}
		}
		return true
	})
}

// environArg reports whether call is one of the sanitizers that may take the
// whole environment as its argument.
func (c *envCensus) environArg(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && c.environArgs[ident.Name]
}

// envRead applies rule (a) to one use of an os or syscall function.
func (c *envCensus) envRead(file, where, owner string, locals map[string]bool, fn string, call *ast.CallExpr, argOf map[*ast.CallExpr]*ast.CallExpr) {
	switch fn {
	case "os.Getenv", "os.LookupEnv", "syscall.Getenv", "os.ExpandEnv", "os.Expand":
	case "os.Environ", "syscall.Environ":
		if call != nil {
			if outer := argOf[call]; outer != nil && c.environArg(outer) {
				return
			}
		}
		c.violations = append(c.violations, where+": reads the whole environment with "+fn)
		return
	default:
		return
	}
	if call == nil {
		c.violations = append(c.violations, where+": passes "+fn+" as a value, so the names it reads cannot be checked")
		return
	}
	if len(call.Args) > 0 && c.constant(call.Args[0], locals) {
		if c.constantAllow != nil && !c.constantAllow[c.pkg+"/"+file+":"+types.ExprString(call.Args[0])] {
			c.violations = append(c.violations, where+": "+fn+"("+types.ExprString(call.Args[0])+") is not a reviewed deployment setting; "+
				"tenant integrations read credentials only through their bound references")
		}
		return
	}
	if c.readers[owner] {
		c.found["env read by a resolver"]++
		return
	}
	c.violations = append(c.violations, where+": "+fn+" reads an env name that is not a constant; tenant references resolve only through the bound resolvers")
}

// constant reports whether e is a string constant: a literal, a package-level
// constant no local name shadows, or a sum of them.
func (c *envCensus) constant(e ast.Expr, locals map[string]bool) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.Ident:
		return c.consts[v.Name] && !locals[v.Name]
	case *ast.ParenExpr:
		return c.constant(v.X, locals)
	case *ast.BinaryExpr:
		return v.Op == token.ADD && c.constant(v.X, locals) && c.constant(v.Y, locals)
	}
	return false
}

func receiverName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return receiverName(v.X)
	case *ast.IndexExpr:
		return receiverName(v.X)
	case *ast.IndexListExpr:
		return receiverName(v.X)
	case *ast.Ident:
		return v.Name
	}
	return ""
}

// declaredNames lists the names a function declares (receiver, parameters,
// results and locals), which shadow package-level names of the same spelling.
func declaredNames(fn *ast.FuncDecl) map[string]bool {
	names := map[string]bool{}
	fields := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			for _, ident := range field.Names {
				names[ident.Name] = true
			}
		}
	}
	fields(fn.Recv)
	fields(fn.Type.Params)
	fields(fn.Type.Results)
	if fn.Body == nil {
		return names
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE {
				for _, lhs := range x.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						names[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, ident := range x.Names {
				names[ident.Name] = true
			}
		case *ast.RangeStmt:
			if x.Tok == token.DEFINE {
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if ident, ok := e.(*ast.Ident); ok {
						names[ident.Name] = true
					}
				}
			}
		case *ast.FuncLit:
			fields(x.Type.Params)
			fields(x.Type.Results)
		}
		return true
	})
	return names
}
