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
			out = append(out, scanGo(path, rel)...)
		case ".java", ".kt":
			out = append(out, scanPatterns(path, rel, "java", javaPatterns)...)
		case ".py":
			out = append(out, scanPatterns(path, rel, "python", pythonPatterns)...)
		}
		return nil
	})
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

func scanGo(path, rel string) []Use {
	fset := token.NewFileSet()
	src, err := os.ReadFile(path) // #nosec G304 -- a repository the operator named; reading its files is the product function (CWE-22)
	if err != nil {
		return nil
	}
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	imports := map[string]string{} // local name → import path
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = p
	}
	var out []Use
	add := func(n ast.Node, algorithm string, bits int, api string) {
		out = append(out, Use{File: rel, Line: fset.Position(n.Pos()).Line, Language: "go", Algorithm: algorithm, KeyBits: bits, API: api})
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, fn := imports[pkg.Name], sel.Sel.Name
		switch {
		case path == "crypto/rsa" && fn == "GenerateKey":
			add(call, "RSA", intArg(call, 1), "crypto/rsa.GenerateKey")
		case path == "crypto/ecdh" && goCurves[fn] != "":
			add(call, "ECDH-"+goCurves[fn], curveBits(goCurves[fn]), "crypto/ecdh."+fn)
		case path == "crypto/ecdsa" && fn == "GenerateKey" && len(call.Args) > 0:
			if curve := ellipticCurve(call.Args[0], imports); curve != "" {
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
	return out
}

func intArg(call *ast.CallExpr, i int) int {
	if i >= len(call.Args) {
		return 0
	}
	if lit, ok := call.Args[i].(*ast.BasicLit); ok && lit.Kind == token.INT {
		n, _ := strconv.Atoi(lit.Value)
		return n
	}
	return 0
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
		use: func(m []string) (string, int) { return m[1], 0 }, sizes: regexp.MustCompile(`\.initialize\(\s*(\d{3,5})`)},
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
		use: func([]string) (string, int) { return "RSA", 0 }, sizes: regexp.MustCompile(`key_size\s*=\s*(\d{3,5})`)},
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
						bits, _ = strconv.Atoi(s[1])
						break
					}
				}
			}
			out = append(out, Use{File: rel, Line: i + 1, Language: language, Algorithm: algorithm, KeyBits: bits, API: p.api})
		}
	}
	return out
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
