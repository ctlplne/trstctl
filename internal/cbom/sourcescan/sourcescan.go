// SPDX-License-Identifier: BUSL-1.1

// Package sourcescan finds where a repository's source code uses
// cryptography (X6): Go through its syntax tree, Java and Python through the
// JCA and pyca/cryptography call patterns. It reads files and executes
// nothing, and it reports each use with the file and line it came from, as a
// CycloneDX CBOM the inventory imports.
package sourcescan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Use is one place the source uses an algorithm.
type Use struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Language  string `json:"language"`
	Algorithm string `json:"algorithm"` // RSA, ECDH-P256, ECDSA-P384, 3DES, MD5, ...
	KeyBits   int    `json:"key_bits,omitempty"`
	API       string `json:"api"`
}

const maxSourceFileBytes = 2 << 20

// skipDirs are never walked.
var skipDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, "build": true, "target": true}

// Scan walks root and returns every crypto use it recognizes, ordered by file
// and line. Paths are relative to root.
func Scan(ctx context.Context, root string) ([]Use, error) {
	var out []Use
	goDirs := map[string][]goSource{} // Go files by directory, read as packages
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxSourceFileBytes {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go":
			dir := filepath.Dir(path)
			goDirs[dir] = append(goDirs[dir], goSource{path: path, rel: rel})
		case ".java", ".kt":
			out = append(out, scanPatterns(path, rel, "java", javaPatterns)...)
		case ".py":
			out = append(out, scanPatterns(path, rel, "python", pythonPatterns)...)
		}
		return nil
	})
	dirs := make([]string, 0, len(goDirs))
	for dir := range goDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		out = append(out, scanGoDir(goDirs[dir])...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, err
}

// ---------------------------------------------------------------- Go

var goCurves = map[string]string{"P224": "P224", "P256": "P256", "P384": "P384", "P521": "P521", "X25519": "X25519"}

// goSource is one Go file of a directory.
type goSource struct {
	path, rel string
}

// goFile is a parsed Go file with its import names.
type goFile struct {
	rel     string
	fset    *token.FileSet
	file    *ast.File
	imports map[string]string // local name → import path
}

// scanGoDir reads one directory's Go files as the packages they declare
// (X6-L2): a key size or curve held in a constant, or in a variable assigned
// once, anywhere in the package resolves to its value, and a function of the
// package that passes its own parameter to a key generator is followed one
// level to its callers in the package, which report the size or curve they
// pass at their own line.
func scanGoDir(sources []goSource) []Use {
	packages := map[string][]*goFile{}
	var names []string
	for _, src := range sources {
		f := parseGo(src)
		if f == nil {
			continue
		}
		name := f.file.Name.Name
		if packages[name] == nil {
			names = append(names, name)
		}
		packages[name] = append(packages[name], f)
	}
	sort.Strings(names)
	var out []Use
	for _, name := range names {
		out = append(out, scanGoPackage(packages[name])...)
	}
	return out
}

func parseGo(src goSource) *goFile {
	fset := token.NewFileSet()
	body, err := os.ReadFile(src.path) // #nosec G304 -- a repository the operator named; reading its files is the product function (CWE-22)
	if err != nil {
		return nil
	}
	file, err := parser.ParseFile(fset, src.path, body, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	imports := map[string]string{}
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = p
	}
	return &goFile{rel: src.rel, fset: fset, file: file, imports: imports}
}

// generatorKind is what a key generator's resolved argument means.
type generatorKind int

const (
	rsaBitsArg    generatorKind = iota + 1 // crypto/rsa.GenerateKey's size
	ecdsaCurveArg                          // crypto/ecdsa.GenerateKey's curve
)

// wrapper is a package function that hands one of its parameters to a key
// generator.
type wrapper struct {
	param int
	kind  generatorKind
	api   string
}

func scanGoPackage(files []*goFile) []Use {
	pkg := newGoScope(nil)
	reassigned := map[string]bool{}
	for _, f := range files {
		collectReassigned(f.file, reassigned)
	}
	for _, f := range files {
		for _, decl := range f.file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				pkg.declare(gen, reassigned)
			}
		}
	}
	// One level of wrappers: a function whose parameter reaches a generator.
	wrappers := map[string]wrapper{}
	for _, f := range files {
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			params := paramIndex(fn.Type)
			bodyReassigned := map[string]bool{}
			collectReassigned(fn.Body, bodyReassigned)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				kind, argIndex, api := generatorCall(call, f.imports)
				if kind == 0 || argIndex >= len(call.Args) {
					return true
				}
				if id, ok := call.Args[argIndex].(*ast.Ident); ok {
					if i, ok := params[id.Name]; ok && !bodyReassigned[id.Name] {
						wrappers[fn.Name.Name] = wrapper{param: i, kind: kind, api: api}
					}
				}
				return true
			})
		}
	}
	var out []Use
	for _, f := range files {
		out = append(out, scanGoFile(f, pkg, wrappers)...)
	}
	return out
}

// generatorCall says whether call is a key generator whose argument the scan
// resolves, which argument, and its API name.
func generatorCall(call *ast.CallExpr, imports map[string]string) (generatorKind, int, string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, 0, ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || sel.Sel.Name != "GenerateKey" {
		return 0, 0, ""
	}
	switch imports[pkg.Name] {
	case "crypto/rsa":
		return rsaBitsArg, 1, "crypto/rsa.GenerateKey"
	case "crypto/ecdsa":
		return ecdsaCurveArg, 0, "crypto/ecdsa.GenerateKey"
	}
	return 0, 0, ""
}

func paramIndex(ft *ast.FuncType) map[string]int {
	out := map[string]int{}
	if ft.Params == nil {
		return out
	}
	i := 0
	for _, field := range ft.Params.List {
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, name := range field.Names {
			out[name.Name] = i
			i++
		}
	}
	return out
}

func scanGoFile(f *goFile, pkg *goScope, wrappers map[string]wrapper) []Use {
	var out []Use
	add := func(n ast.Node, algorithm string, bits int, api string) {
		out = append(out, Use{File: f.rel, Line: f.fset.Position(n.Pos()).Line, Language: "go", Algorithm: algorithm, KeyBits: bits, API: api})
	}
	visit := func(scope *goScope, body ast.Node) {
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				if w, ok := wrappers[id.Name]; ok && w.param < len(call.Args) {
					switch w.kind {
					case rsaBitsArg:
						if bits, ok := scope.intValue(call.Args[w.param], 0); ok {
							add(call, "RSA", bits, w.api+" via "+id.Name)
						}
					case ecdsaCurveArg:
						if curve := scope.curve(call.Args[w.param], f.imports, 0); curve != "" {
							add(call, "ECDSA-"+curve, curveBits(curve), w.api+" via "+id.Name)
						}
					}
				}
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgName, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			path, fn := f.imports[pkgName.Name], sel.Sel.Name
			switch {
			case path == "crypto/rsa" && fn == "GenerateKey":
				bits := 0
				if len(call.Args) > 1 {
					bits, _ = scope.intValue(call.Args[1], 0)
				}
				add(call, "RSA", bits, "crypto/rsa.GenerateKey")
			case path == "crypto/ecdh" && goCurves[fn] != "":
				add(call, "ECDH-"+goCurves[fn], curveBits(goCurves[fn]), "crypto/ecdh."+fn)
			case path == "crypto/ecdsa" && fn == "GenerateKey" && len(call.Args) > 0:
				if curve := scope.curve(call.Args[0], f.imports, 0); curve != "" {
					add(call, "ECDSA-"+curve, curveBits(curve), "crypto/ecdsa.GenerateKey")
				}
			case path == "crypto/ed25519" && fn == "GenerateKey":
				add(call, "Ed25519", 256, "crypto/ed25519.GenerateKey")
			case path == "crypto/des" && fn == "NewTripleDESCipher":
				add(call, "3DES", 168, "crypto/des.NewTripleDESCipher")
			case path == "crypto/des" && fn == "NewCipher":
				add(call, "DES", 56, "crypto/des.NewCipher")
			case path == "crypto/rc4" && fn == "NewCipher":
				add(call, "RC4", 0, "crypto/rc4.NewCipher")
			case path == "crypto/md5" && (fn == "New" || fn == "Sum"):
				add(call, "MD5", 0, "crypto/md5."+fn)
			case path == "crypto/sha1" && (fn == "New" || fn == "Sum"):
				add(call, "SHA1", 0, "crypto/sha1."+fn)
			case path == "crypto/mlkem" && strings.HasPrefix(fn, "GenerateKey"):
				add(call, "ML-KEM-"+strings.TrimPrefix(fn, "GenerateKey"), 0, "crypto/mlkem."+fn)
			}
			return true
		})
	}
	for _, decl := range f.file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				visit(functionScope(pkg, d.Body), d.Body)
			}
		case *ast.GenDecl:
			visit(pkg, d)
		}
	}
	return out
}

// goScope holds the names whose value the scan can read: constants, and
// variables assigned exactly once and never again.
type goScope struct {
	parent *goScope
	values map[string]ast.Expr
	// ambiguous names were declared more than once here; they resolve to
	// nothing rather than to either declaration.
	ambiguous map[string]bool
}

func newGoScope(parent *goScope) *goScope {
	return &goScope{parent: parent, values: map[string]ast.Expr{}, ambiguous: map[string]bool{}}
}

func (s *goScope) set(name string, value ast.Expr) {
	if name == "_" {
		return
	}
	if _, dup := s.values[name]; dup || s.ambiguous[name] {
		delete(s.values, name)
		s.ambiguous[name] = true
		return
	}
	s.values[name] = value
}

func (s *goScope) lookup(name string) (ast.Expr, bool) {
	for scope := s; scope != nil; scope = scope.parent {
		if scope.ambiguous[name] {
			return nil, false
		}
		if v, ok := scope.values[name]; ok {
			return v, true
		}
	}
	return nil, false
}

// declare records a const or var declaration. A const spec without values
// repeats the previous spec's expressions; iota is not evaluated, so such a
// group resolves only when it names no iota.
func (s *goScope) declare(gen *ast.GenDecl, reassigned map[string]bool) {
	if gen.Tok != token.CONST && gen.Tok != token.VAR {
		return
	}
	var previous []ast.Expr
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		values := vs.Values
		if gen.Tok == token.CONST && len(values) == 0 {
			values = previous
		}
		previous = values
		for i, name := range vs.Names {
			if (gen.Tok == token.VAR && reassigned[name.Name]) || len(values) != len(vs.Names) {
				s.set(name.Name, nil)
				continue
			}
			s.set(name.Name, values[i])
		}
	}
}

// functionScope reads a function body's single assignments: local consts,
// var x = v and x := v, for names never assigned again in the body.
func functionScope(pkg *goScope, body *ast.BlockStmt) *goScope {
	scope := newGoScope(pkg)
	reassigned := map[string]bool{}
	collectReassigned(body, reassigned)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false // a closure's names are its own
		case *ast.DeclStmt:
			if gen, ok := node.Decl.(*ast.GenDecl); ok {
				scope.declare(gen, reassigned)
			}
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE {
				return true
			}
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if reassigned[id.Name] || len(node.Rhs) != len(node.Lhs) {
					scope.set(id.Name, nil)
					continue
				}
				scope.set(id.Name, node.Rhs[i])
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{node.Key, node.Value} {
				if id, ok := e.(*ast.Ident); ok {
					scope.set(id.Name, nil)
				}
			}
		}
		return true
	})
	return scope
}

// collectReassigned names every identifier assigned after its declaration
// (=, op=, ++, --) or whose address is taken.
func collectReassigned(root ast.Node, out map[string]bool) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				return true
			}
			for _, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		case *ast.IncDecStmt:
			if id, ok := node.X.(*ast.Ident); ok {
				out[id.Name] = true
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := node.X.(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		}
		return true
	})
}

const (
	maxResolveDepth = 16
	maxKeySize      = 1 << 20
)

// intValue evaluates an integer constant expression: literals, names the
// scope resolves, parentheses, conversions, unary plus and + - * / % << >>.
func (s *goScope) intValue(e ast.Expr, depth int) (int, bool) {
	if depth > maxResolveDepth {
		return 0, false
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.INT {
			return 0, false
		}
		n, err := strconv.ParseInt(strings.ReplaceAll(x.Value, "_", ""), 0, 64)
		if err != nil || n < 0 || n > maxKeySize {
			return 0, false
		}
		return int(n), true
	case *ast.Ident:
		v, ok := s.lookup(x.Name)
		if !ok || v == nil {
			return 0, false
		}
		return s.intValue(v, depth+1)
	case *ast.ParenExpr:
		return s.intValue(x.X, depth+1)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && len(x.Args) == 1 && integerTypes[id.Name] {
			return s.intValue(x.Args[0], depth+1)
		}
	case *ast.UnaryExpr:
		if x.Op == token.ADD {
			return s.intValue(x.X, depth+1)
		}
	case *ast.BinaryExpr:
		return s.binaryValue(x, depth)
	}
	return 0, false
}

func (s *goScope) binaryValue(x *ast.BinaryExpr, depth int) (int, bool) {
	a, ok := s.intValue(x.X, depth+1)
	if !ok {
		return 0, false
	}
	b, ok := s.intValue(x.Y, depth+1)
	if !ok {
		return 0, false
	}
	var v int
	switch x.Op {
	case token.ADD:
		v = a + b
	case token.SUB:
		v = a - b
	case token.MUL:
		v = a * b
	case token.QUO, token.REM:
		if b == 0 {
			return 0, false
		}
		if x.Op == token.QUO {
			v = a / b
		} else {
			v = a % b
		}
	case token.SHL:
		if b > 20 {
			return 0, false
		}
		v = a << b
	case token.SHR:
		if b > 62 {
			return 0, false
		}
		v = a >> b
	default:
		return 0, false
	}
	if v < 0 || v > maxKeySize {
		return 0, false
	}
	return v, true
}

var integerTypes = map[string]bool{"int": true, "int32": true, "int64": true, "uint": true, "uint32": true, "uint64": true}

// curve resolves an elliptic.Px() call, directly or through a name assigned
// once.
func (s *goScope) curve(e ast.Expr, imports map[string]string, depth int) string {
	if depth > maxResolveDepth {
		return ""
	}
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := s.lookup(x.Name)
		if !ok || v == nil {
			return ""
		}
		return s.curve(v, imports, depth+1)
	case *ast.ParenExpr:
		return s.curve(x.X, imports, depth+1)
	}
	return ellipticCurve(e, imports)
}

func ellipticCurve(arg ast.Expr, imports map[string]string) string {
	call, ok := arg.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && imports[pkg.Name] == "crypto/elliptic" {
		return goCurves[sel.Sel.Name]
	}
	return ""
}

func curveBits(curve string) int {
	switch curve {
	case "P224":
		return 224
	case "P256", "X25519":
		return 256
	case "P384":
		return 384
	case "P521":
		return 521
	}
	return 0
}

// ---------------------------------------------------------------- Java and Python

type pattern struct {
	re    *regexp.Regexp
	use   func(m []string) (algorithm string, bits int)
	api   string
	sizes *regexp.Regexp // a key size on the same or the following lines
}

var javaPatterns = []pattern{
	{re: regexp.MustCompile(`KeyPairGenerator\.getInstance\(\s*"(RSA|EC|DSA|DH|Ed25519|X25519)"`), api: "KeyPairGenerator.getInstance",
		use: func(m []string) (string, int) { return m[1], 0 }, sizes: regexp.MustCompile(`\.initialize\(\s*(\d{3,5}|[A-Za-z_][A-Za-z0-9_]*)\s*[,)]`)},
	{re: regexp.MustCompile(`KeyAgreement\.getInstance\(\s*"(ECDH|DH|X25519|XDH)"`), api: "KeyAgreement.getInstance",
		use: func(m []string) (string, int) { return m[1], 0 }},
	{re: regexp.MustCompile(`Cipher\.getInstance\(\s*"(RSA|DESede|DES|RC4|AES)[/"]`), api: "Cipher.getInstance",
		use: func(m []string) (string, int) { return javaCipher(m[1]), 0 }},
	{re: regexp.MustCompile(`MessageDigest\.getInstance\(\s*"(MD5|SHA-1|SHA1)"`), api: "MessageDigest.getInstance",
		use: func(m []string) (string, int) { return strings.ReplaceAll(m[1], "-", ""), 0 }},
	{re: regexp.MustCompile(`new\s+ECGenParameterSpec\(\s*"(secp256r1|secp384r1|secp521r1|prime256v1)"`), api: "ECGenParameterSpec",
		use: func(m []string) (string, int) { c := pyCurve(m[1]); return "EC-" + c, curveBits(c) }},
}

var pythonPatterns = []pattern{
	{re: regexp.MustCompile(`rsa\.generate_private_key\(`), api: "rsa.generate_private_key",
		use: func([]string) (string, int) { return "RSA", 0 }, sizes: regexp.MustCompile(`key_size\s*=\s*(\d{3,5}|[A-Za-z_][A-Za-z0-9_]*)`)},
	{re: regexp.MustCompile(`ec\.ECDH\(\)`), api: "ec.ECDH", use: func([]string) (string, int) { return "ECDH", 0 }},
	{re: regexp.MustCompile(`ec\.generate_private_key\(\s*ec\.(SECP256R1|SECP384R1|SECP521R1)`), api: "ec.generate_private_key",
		use: func(m []string) (string, int) { c := pyCurve(m[1]); return "EC-" + c, curveBits(c) }},
	{re: regexp.MustCompile(`X25519PrivateKey\.generate\(\)`), api: "X25519PrivateKey.generate",
		use: func([]string) (string, int) { return "ECDH-X25519", 256 }},
	{re: regexp.MustCompile(`algorithms\.TripleDES\(`), api: "algorithms.TripleDES", use: func([]string) (string, int) { return "3DES", 168 }},
	{re: regexp.MustCompile(`hashlib\.(md5|sha1)\(`), api: "hashlib", use: func(m []string) (string, int) { return strings.ToUpper(m[1]), 0 }},
}

func javaCipher(name string) string {
	switch name {
	case "DESede":
		return "3DES"
	}
	return name
}

func pyCurve(name string) string {
	switch strings.ToLower(name) {
	case "secp256r1", "prime256v1":
		return "P256"
	case "secp384r1":
		return "P384"
	case "secp521r1":
		return "P521"
	}
	return strings.ToUpper(name)
}

func scanPatterns(path, rel, language string, patterns []pattern) []Use {
	src, err := os.ReadFile(path) // #nosec G304 -- a repository the operator named; reading its files is the product function (CWE-22)
	if err != nil {
		return nil
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 64*1024), maxSourceFileBytes)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	var out []Use
	var constants map[string]int
	for i, line := range lines {
		for _, p := range patterns {
			m := p.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			algorithm, bits := p.use(m)
			if p.sizes != nil && bits == 0 {
				for j := i; j < len(lines) && j <= i+5; j++ {
					if s := p.sizes.FindStringSubmatch(lines[j]); s != nil {
						if n, err := strconv.Atoi(s[1]); err == nil {
							bits = n
						} else {
							if constants == nil {
								constants = fileConstants(lines, language)
							}
							bits = constants[s[1]]
						}
						break
					}
				}
			}
			out = append(out, Use{File: rel, Line: i + 1, Language: language, Algorithm: algorithm, KeyBits: bits, API: p.api})
		}
	}
	return out
}

var (
	javaIntDecl   = regexp.MustCompile(`\b(?:int|Integer|long|Long)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{3,5})\s*;`)
	pythonIntDecl = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*int\s*)?=\s*(\d{3,5})\s*(?:#.*)?$`)
	assignedName  = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z_][A-Za-z0-9_.]*\s*)?(?:[-+*/%|&^]|<<|>>)?=[^=]`)
)

// fileConstants are a Java or Python file's key-size names (X6-L2): a name
// declared once with a number (Java int KEY_SIZE = 1024; Python KEY_BITS =
// 1024) and assigned nowhere else in the file. A name assigned twice
// resolves to nothing.
func fileConstants(lines []string, language string) map[string]int {
	decl := javaIntDecl
	if language == "python" {
		decl = pythonIntDecl
	}
	values := map[string]int{}
	assignments := map[string]int{}
	for _, line := range lines {
		for _, m := range assignedName.FindAllStringSubmatch(line, -1) {
			assignments[m[1]]++
		}
		for _, m := range decl.FindAllStringSubmatch(line, -1) {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				continue
			}
			if _, seen := values[m[1]]; seen {
				values[m[1]] = 0
				continue
			}
			values[m[1]] = n
		}
	}
	for name := range values {
		if assignments[name] != 1 {
			delete(values, name)
		}
	}
	return values
}

// ---------------------------------------------------------------- CycloneDX

// CBOM renders uses as a CycloneDX 1.6 BOM: one algorithm component per
// algorithm and size, with an evidence occurrence per use.
func CBOM(uses []Use, serialUUID string) ([]byte, error) {
	type occurrence struct {
		Location string `json:"location"`
		Line     int    `json:"line,omitempty"`
	}
	type component struct {
		Type             string         `json:"type"`
		BOMRef           string         `json:"bom-ref"`
		Name             string         `json:"name"`
		CryptoProperties map[string]any `json:"cryptoProperties"`
		Evidence         struct {
			Occurrences []occurrence `json:"occurrences"`
		} `json:"evidence"`
	}
	byKey := map[string]*component{}
	var order []string
	for _, u := range uses {
		name := u.Algorithm
		if u.KeyBits > 0 && !strings.Contains(name, "-") {
			name = fmt.Sprintf("%s-%d", u.Algorithm, u.KeyBits)
		}
		c := byKey[name]
		if c == nil {
			props := map[string]any{"assetType": "algorithm"}
			if u.KeyBits > 0 {
				props["algorithmProperties"] = map[string]any{"parameterSetIdentifier": strconv.Itoa(u.KeyBits)}
			}
			c = &component{Type: "cryptographic-asset", BOMRef: "alg:" + name, Name: name, CryptoProperties: props}
			byKey[name] = c
			order = append(order, name)
		}
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, occurrence{Location: u.File, Line: u.Line})
	}
	sort.Strings(order)
	components := make([]component, 0, len(order))
	for _, name := range order {
		components = append(components, *byKey[name])
	}
	return json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"serialNumber": "urn:uuid:" + serialUUID, "components": components,
	})
}
