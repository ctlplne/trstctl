// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CycloneDX CBOM import (X6): a CBOM another tool or a vendor published —
// an image or directory scanner, a source scanner, a product's own CBOM —
// merges into the inventory with its source recorded. Each cryptographic
// asset becomes one finding located at "<source>:<occurrence>", so the
// inventory says where it was seen and who reported it; classification is the
// same as for trstctl's own scans.

// Imported asset kinds, one per CycloneDX cryptographic asset type.
const (
	AssetImportedAlgorithm   AssetKind = "imported-algorithm"
	AssetImportedCertificate AssetKind = "imported-certificate"
	AssetImportedKey         AssetKind = "imported-key"
	AssetImportedProtocol    AssetKind = "imported-protocol"
	AssetImportedLibrary     AssetKind = "imported-library"
)

// ImportedCertificate is what an imported certificate component says about
// the certificate itself (X6-L6): who it names, who issued it, when it is
// valid, and its SHA-256 fingerprint when the BOM gives one (a 1.6
// component's hashes, or a 1.7 certificate's fingerprint). With a fingerprint
// and an expiry it is a certificate the inventory can hold; without a
// fingerprint it stays a CBOM row only, because the inventory is keyed by it.
type ImportedCertificate struct {
	Fingerprint string
	Subject     string
	Issuer      string
	Serial      string
	NotBefore   *time.Time
	NotAfter    *time.Time
}

// MaxImportComponents bounds one import. A real image scan is large: the
// operating system's CA bundle in a small Alpine image alone gives a scanner
// about 8,000 components (each certificate, its key and its algorithms).
const MaxImportComponents = 50000

// ImportedBOM is what an import read from the document.
type ImportedBOM struct {
	SerialNumber string
	Version      int
	SpecVersion  string
	Components   int
	Findings     []Finding
}

type importBOM struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	Components   []importComponent  `json:"components"`
	Dependencies []importDependency `json:"dependencies"`
}

// importDependency is one node of the BOM's dependency graph (X6-L5): what a
// component depends on, and — CycloneDX 1.6 — which crypto assets it provides.
type importDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
	Provides  []string `json:"provides"`
}

// dependencyGraph is what the import reads from dependencies[]: each asset's
// provider, labelled as the provider's name and version, and each
// component's direct dependencies. References to other BOMs (BOM-Link
// urn:cdx:...) are not followed.
type dependencyGraph struct {
	providedBy map[string]string
	dependsOn  map[string][]string
}

func readDependencyGraph(deps []importDependency, byRef map[string]importComponent) dependencyGraph {
	g := dependencyGraph{providedBy: map[string]string{}, dependsOn: map[string][]string{}}
	sorted := append([]importDependency(nil), deps...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Ref < sorted[j].Ref })
	for _, d := range sorted {
		provider, ok := byRef[d.Ref]
		if !ok {
			continue
		}
		g.dependsOn[d.Ref] = append(g.dependsOn[d.Ref], d.DependsOn...)
		label := strings.ToLower(strings.TrimSpace(provider.Name)) + versionSuffix(provider.Version)
		if strings.TrimSpace(provider.Name) == "" {
			continue
		}
		for _, ref := range d.Provides {
			if _, taken := g.providedBy[ref]; !taken {
				g.providedBy[ref] = label
			}
		}
	}
	return g
}

// algorithmVia finds the algorithm a component depends on: an algorithm
// component directly, or the algorithm of a key it depends on (one level).
func (g dependencyGraph) algorithmVia(ref string, byRef map[string]importComponent) (string, int, bool) {
	for depth, refs := 0, g.dependsOn[ref]; depth < 2; depth++ {
		var next []string
		for _, r := range refs {
			dep, ok := byRef[r]
			if !ok || dep.CryptoProperties == nil {
				continue
			}
			switch dep.CryptoProperties.AssetType {
			case "algorithm":
				alg, bits := importedAlgorithm(dep.Name, dep.CryptoProperties.AlgorithmProperties)
				return alg, bits, true
			case "related-crypto-material":
				next = append(next, r)
				if m := dep.CryptoProperties.RelatedCryptoMaterial; m != nil {
					if alg, ok := byRef[m.AlgorithmRef]; ok && alg.CryptoProperties != nil {
						name, bits := importedAlgorithm(alg.Name, alg.CryptoProperties.AlgorithmProperties)
						if m.Size > 0 {
							bits = m.Size
						}
						return name, bits, true
					}
				}
			}
		}
		refs = nil
		for _, r := range next {
			refs = append(refs, g.dependsOn[r]...)
		}
	}
	return "", 0, false
}

// issuerVia names the certificate a certificate depends on, as its issuer.
func (g dependencyGraph) issuerVia(ref string, byRef map[string]importComponent) string {
	for _, r := range g.dependsOn[ref] {
		dep, ok := byRef[r]
		if !ok || dep.CryptoProperties == nil || dep.CryptoProperties.AssetType != "certificate" {
			continue
		}
		if cert := dep.CryptoProperties.CertificateProperties; cert != nil && strings.TrimSpace(cert.SubjectName) != "" {
			return strings.TrimSpace(cert.SubjectName)
		}
		return strings.TrimSpace(dep.Name)
	}
	return ""
}

type importComponent struct {
	Type             string             `json:"type"`
	BOMRef           string             `json:"bom-ref"`
	Name             string             `json:"name"`
	Version          string             `json:"version"`
	CryptoProperties *importCryptoProps `json:"cryptoProperties"`
	Evidence         *importEvidence    `json:"evidence"`
	Components       []importComponent  `json:"components"`
	Hashes           []importHash       `json:"hashes"`
}

type importHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type importCryptoProps struct {
	AssetType             string                  `json:"assetType"`
	AlgorithmProperties   *importAlgorithmProps   `json:"algorithmProperties"`
	CertificateProperties *importCertificateProps `json:"certificateProperties"`
	RelatedCryptoMaterial *importMaterialProps    `json:"relatedCryptoMaterialProperties"`
	ProtocolProperties    *importProtocolProps    `json:"protocolProperties"`
	OID                   string                  `json:"oid"`
}

type importAlgorithmProps struct {
	Primitive              string `json:"primitive"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier"`
	Curve                  string `json:"curve"`
}

type importCertificateProps struct {
	SubjectName           string      `json:"subjectName"`
	IssuerName            string      `json:"issuerName"`
	NotValidBefore        string      `json:"notValidBefore"`
	NotValidAfter         string      `json:"notValidAfter"`
	SignatureAlgorithmRef string      `json:"signatureAlgorithmRef"`
	SubjectPublicKeyRef   string      `json:"subjectPublicKeyRef"`
	SerialNumber          string      `json:"serialNumber"` // CycloneDX 1.7
	Fingerprint           *importHash `json:"fingerprint"`  // CycloneDX 1.7
}

type importMaterialProps struct {
	Type         string `json:"type"`
	AlgorithmRef string `json:"algorithmRef"`
	Size         int    `json:"size"`
}

type importProtocolProps struct {
	Type         string `json:"type"`
	Version      string `json:"version"`
	CipherSuites []struct {
		Name string `json:"name"`
	} `json:"cipherSuites"`
}

type importEvidence struct {
	Occurrences []importOccurrence `json:"occurrences"`
}

type importOccurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line"`
}

var importSource = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)

// ParseCycloneDXImport reads a CycloneDX BOM (1.4 to 1.6) and returns one
// classified finding per cryptographic asset and crypto library, located at
// its occurrences under source. A document that is not a CycloneDX BOM, or
// that holds no cryptographic asset, is refused.
func ParseCycloneDXImport(data []byte, source string, p Policy) (ImportedBOM, error) {
	source = strings.TrimSpace(source)
	if !importSource.MatchString(source) {
		return ImportedBOM{}, errors.New("cbom: import source must be 1-200 characters of letters, digits and ._:/@+-")
	}
	var doc importBOM
	if err := json.Unmarshal(data, &doc); err != nil {
		return ImportedBOM{}, fmt.Errorf("cbom: not a CycloneDX JSON document: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" || !strings.HasPrefix(doc.SpecVersion, "1.") {
		return ImportedBOM{}, errors.New("cbom: the document is not a CycloneDX BOM")
	}
	flat := flattenComponents(doc.Components, nil)
	if len(flat) > MaxImportComponents {
		return ImportedBOM{}, fmt.Errorf("cbom: the BOM has %d components; an import holds at most %d", len(flat), MaxImportComponents)
	}
	byRef := map[string]importComponent{}
	for _, c := range flat {
		if c.BOMRef != "" {
			byRef[c.BOMRef] = c
		}
	}
	out := ImportedBOM{SerialNumber: strings.TrimSpace(doc.SerialNumber), Version: doc.Version, SpecVersion: doc.SpecVersion, Components: len(flat)}
	graph := readDependencyGraph(doc.Dependencies, byRef)
	for _, c := range flat {
		for _, f := range importFindings(c, byRef, graph, source) {
			out.Findings = append(out.Findings, f.Classified(p))
		}
	}
	if len(out.Findings) == 0 {
		return ImportedBOM{}, errors.New("cbom: the BOM holds no cryptographic asset or crypto library")
	}
	sort.SliceStable(out.Findings, func(i, j int) bool { return out.Findings[i].Location < out.Findings[j].Location })
	return out, nil
}

func flattenComponents(in []importComponent, out []importComponent) []importComponent {
	for _, c := range in {
		out = append(out, c)
		out = flattenComponents(c.Components, out)
	}
	return out
}

// cryptoLibraries are library components whose presence is itself a crypto fact.
var cryptoLibraries = map[string]bool{"openssl": true, "libressl": true, "boringssl": true, "gnutls": true, "nss": true,
	"bouncycastle": true, "bcprov-jdk18on": true, "libsodium": true, "wolfssl": true, "mbedtls": true, "cryptography": true}

func importFindings(c importComponent, byRef map[string]importComponent, graph dependencyGraph, source string) []Finding {
	locations := occurrenceLocations(c, source)
	var base Finding
	cp := c.CryptoProperties
	switch {
	case c.Type == "library" && cryptoLibraries[strings.ToLower(c.Name)]:
		base = Finding{Kind: AssetImportedLibrary, Library: strings.ToLower(c.Name) + versionSuffix(c.Version)}
	case c.Type != "cryptographic-asset" || cp == nil:
		return nil
	case cp.AssetType == "algorithm":
		algorithm, bits := importedAlgorithm(c.Name, cp.AlgorithmProperties)
		base = Finding{Kind: AssetImportedAlgorithm, Algorithm: algorithm, KeyBits: bits}
	case cp.AssetType == "related-crypto-material":
		base = Finding{Kind: AssetImportedKey}
		if m := cp.RelatedCryptoMaterial; m != nil {
			if ref, ok := byRef[m.AlgorithmRef]; ok && ref.CryptoProperties != nil {
				base.Algorithm, base.KeyBits = importedAlgorithm(ref.Name, ref.CryptoProperties.AlgorithmProperties)
			}
			if m.Size > 0 {
				base.KeyBits = m.Size
			}
		}
		if base.Algorithm == "" {
			if alg, bits, ok := graph.algorithmVia(c.BOMRef, byRef); ok {
				base.Algorithm = alg
				if base.KeyBits == 0 {
					base.KeyBits = bits
				}
			}
		}
		if base.Algorithm == "" {
			base.Algorithm, _ = importedAlgorithm(c.Name, nil)
		}
	case cp.AssetType == "certificate":
		base = Finding{Kind: AssetImportedCertificate}
		if cert := cp.CertificateProperties; cert != nil {
			base.Certificate = importedCertificate(c, cert)
			if key, ok := byRef[cert.SubjectPublicKeyRef]; ok && key.CryptoProperties != nil {
				if m := key.CryptoProperties.RelatedCryptoMaterial; m != nil {
					if alg, ok := byRef[m.AlgorithmRef]; ok && alg.CryptoProperties != nil {
						base.Algorithm, base.KeyBits = importedAlgorithm(alg.Name, alg.CryptoProperties.AlgorithmProperties)
					}
					if m.Size > 0 {
						base.KeyBits = m.Size
					}
				}
			}
			if base.Certificate.Issuer == "" {
				base.Certificate.Issuer = graph.issuerVia(c.BOMRef, byRef)
			}
		}
		if base.Algorithm == "" {
			if alg, bits, ok := graph.algorithmVia(c.BOMRef, byRef); ok {
				base.Algorithm, base.KeyBits = alg, bits
			}
		}
	case cp.AssetType == "protocol" && cp.ProtocolProperties != nil:
		var out []Finding
		pp := cp.ProtocolProperties
		library := source
		if provider := graph.providedBy[c.BOMRef]; provider != "" {
			library = provider
		}
		if v := importedProtocol(pp.Type, pp.Version); v != "" {
			for _, loc := range locations {
				out = append(out, Finding{Kind: AssetImportedProtocol, Location: loc, Protocol: v, Library: library})
			}
		}
		for _, suite := range pp.CipherSuites {
			for _, loc := range locations {
				out = append(out, Finding{Kind: AssetImportedProtocol, Location: loc, Cipher: suite.Name, Library: library})
			}
		}
		return out
	default:
		return nil
	}
	if provider := graph.providedBy[c.BOMRef]; provider != "" && base.Kind != AssetImportedLibrary {
		base.Library = provider
	}
	if base.Library == "" {
		base.Library = source
	}
	out := make([]Finding, 0, len(locations))
	for _, loc := range locations {
		f := base
		f.Location = loc
		out = append(out, f)
	}
	return out
}

func versionSuffix(v string) string {
	if v = strings.TrimSpace(v); v != "" {
		return " " + v
	}
	return ""
}

// occurrenceLocations names where the asset was seen: each evidence
// occurrence (with its line), or the component's reference when none is given.
func occurrenceLocations(c importComponent, source string) []string {
	var out []string
	if c.Evidence != nil {
		for _, o := range c.Evidence.Occurrences {
			loc := strings.TrimSpace(o.Location)
			if loc == "" {
				continue
			}
			if o.Line > 0 {
				loc += ":" + strconv.Itoa(o.Line)
			}
			out = append(out, source+":"+loc)
		}
	}
	if len(out) == 0 {
		ref := c.BOMRef
		if ref == "" {
			ref = c.Name
		}
		out = append(out, source+":"+ref)
	}
	return out
}

var trailingBits = regexp.MustCompile(`[-_ ]?(\d{3,5})$`)

// importedAlgorithm maps a CycloneDX algorithm name and parameters to the
// family name and size the classifier reads: "RSA-2048" → RSA, 2048;
// "ECDH" with curve P-256 → ECDH-P256, 256.
func importedAlgorithm(name string, props *importAlgorithmProps) (string, int) {
	name = strings.TrimSpace(name)
	upper := strings.ToUpper(name)
	bits := 0
	if props != nil {
		if n, err := strconv.Atoi(strings.TrimSpace(props.ParameterSetIdentifier)); err == nil {
			bits = n
		}
		if curve := strings.TrimSpace(props.Curve); curve != "" {
			family := upper
			if i := strings.IndexAny(family, "-_ "); i > 0 {
				family = family[:i]
			}
			return family + "-" + curveName(curve), curveBits(curve)
		}
	}
	if m := trailingBits.FindStringSubmatch(upper); m != nil && (strings.HasPrefix(upper, "RSA") || strings.HasPrefix(upper, "DSA") || strings.HasPrefix(upper, "DH")) {
		n, _ := strconv.Atoi(m[1])
		if bits == 0 {
			bits = n
		}
		return strings.TrimSuffix(upper[:len(upper)-len(m[0])], "-"), bits
	}
	return name, bits
}

func curveName(curve string) string {
	switch strings.ToLower(strings.ReplaceAll(curve, "-", "")) {
	case "p256", "secp256r1", "prime256v1":
		return "P256"
	case "p384", "secp384r1":
		return "P384"
	case "p521", "secp521r1":
		return "P521"
	case "x25519", "curve25519":
		return "X25519"
	}
	return strings.ToUpper(curve)
}

func curveBits(curve string) int {
	switch curveName(curve) {
	case "P256", "X25519":
		return 256
	case "P384":
		return 384
	case "P521":
		return 521
	}
	return 0
}

func importedProtocol(kind, version string) string {
	if !strings.EqualFold(kind, "tls") && kind != "" {
		return ""
	}
	switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v") {
	case "1.0", "1":
		return "TLSv1.0"
	case "1.1":
		return "TLSv1.1"
	case "1.2":
		return "TLSv1.2"
	case "1.3":
		return "TLSv1.3"
	}
	return ""
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// importedCertificate reads what a certificate component says about the
// certificate (X6-L6). A fingerprint counts only as a SHA-256 of 64 hex
// digits; a validity date only as RFC 3339.
func importedCertificate(c importComponent, cert *importCertificateProps) *ImportedCertificate {
	out := &ImportedCertificate{
		Subject: strings.TrimSpace(cert.SubjectName), Issuer: strings.TrimSpace(cert.IssuerName),
		Serial: strings.TrimSpace(cert.SerialNumber),
	}
	if out.Subject == "" {
		out.Subject = strings.TrimSpace(c.Name)
	}
	hashes := c.Hashes
	if cert.Fingerprint != nil {
		hashes = append([]importHash{*cert.Fingerprint}, hashes...)
	}
	for _, h := range hashes {
		content := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(h.Content), ":", ""))
		if strings.EqualFold(strings.TrimSpace(h.Alg), "SHA-256") && sha256Hex.MatchString(content) {
			out.Fingerprint = content
			break
		}
	}
	out.NotBefore = importedTime(cert.NotValidBefore)
	out.NotAfter = importedTime(cert.NotValidAfter)
	return out
}

func importedTime(value string) *time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
