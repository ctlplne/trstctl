// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CycloneDX 1.6 export of the crypto inventory (Q3). It is a pure
// transformation: every inventory asset becomes one cryptographic-asset
// component whose bom-ref is the asset's ID, with the algorithm, key size or
// protocol the inventory recorded, where it was observed, and the inventory's
// own classification as properties. The document states its coverage: it
// lists only what trstctl observed, marks itself incomplete, and says what
// it does not cover. It never claims FIPS or any other compliance; choosing
// an algorithm does not make a deployment compliant.

// CycloneDXSpecVersion is the CycloneDX specification the export follows.
const CycloneDXSpecVersion = "1.6"

// CycloneDXAsset is one inventory asset to export.
type CycloneDXAsset struct {
	ID                     string
	Kind                   string
	Location               string
	Algorithm              string
	KeyBits                int
	Protocol               string
	Cipher                 string
	Library                string
	CertificateFingerprint string
	Strength               string
	QuantumVulnerable      bool
	OutOfPolicy            bool
	Reasons                []string
	MigrationTarget        string
}

// CycloneDXMeta is the export's identity: its serial number (a UUID the
// caller derives from the dataset), its time and the tool version.
type CycloneDXMeta struct {
	SerialUUID  string
	GeneratedAt time.Time
	ToolVersion string
}

// CycloneDXBOM is a CycloneDX 1.6 BOM carrying the crypto inventory.
type CycloneDXBOM struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	Metadata     cdxMetadata        `json:"metadata"`
	Components   []CycloneDXAssetJS `json:"components"`
	Compositions []cdxComposition   `json:"compositions"`
}

type cdxMetadata struct {
	Timestamp  string        `json:"timestamp"`
	Tools      cdxTools      `json:"tools"`
	Properties []cdxProperty `json:"properties"`
}

type cdxTools struct {
	Components []cdxTool `json:"components"`
}

type cdxTool struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComposition struct {
	Aggregate  string   `json:"aggregate"`
	Assemblies []string `json:"assemblies"`
}

// CycloneDXAssetJS is one cryptographic-asset component.
type CycloneDXAssetJS struct {
	Type             string              `json:"type"`
	BOMRef           string              `json:"bom-ref"`
	Name             string              `json:"name"`
	CryptoProperties cdxCryptoProperties `json:"cryptoProperties"`
	Evidence         cdxEvidence         `json:"evidence"`
	Properties       []cdxProperty       `json:"properties"`
}

type cdxCryptoProperties struct {
	AssetType           string                  `json:"assetType"`
	AlgorithmProperties *cdxAlgorithmProperties `json:"algorithmProperties,omitempty"`
	ProtocolProperties  *cdxProtocolProperties  `json:"protocolProperties,omitempty"`
	OID                 string                  `json:"oid,omitempty"`
}

type cdxAlgorithmProperties struct {
	Primitive                string `json:"primitive"`
	ParameterSetIdentifier   string `json:"parameterSetIdentifier,omitempty"`
	Curve                    string `json:"curve,omitempty"`
	ClassicalSecurityLevel   int    `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int   `json:"nistQuantumSecurityLevel,omitempty"`
}

type cdxProtocolProperties struct {
	Type         string           `json:"type"`
	Version      string           `json:"version,omitempty"`
	CipherSuites []cdxCipherSuite `json:"cipherSuites,omitempty"`
}

type cdxCipherSuite struct {
	Name string `json:"name"`
}

type cdxEvidence struct {
	Occurrences []cdxOccurrence `json:"occurrences"`
}

type cdxOccurrence struct {
	Location string `json:"location"`
}

// CycloneDX builds the BOM for the inventory, components ordered by asset ID.
func CycloneDX(assets []CycloneDXAsset, meta CycloneDXMeta) CycloneDXBOM {
	sorted := append([]CycloneDXAsset(nil), assets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	components := make([]CycloneDXAssetJS, 0, len(sorted))
	refs := make([]string, 0, len(sorted))
	kinds := map[string]int{}
	locations := map[string]bool{}
	for _, a := range sorted {
		components = append(components, cycloneDXComponent(a))
		refs = append(refs, a.ID)
		kinds[a.Kind]++
		locations[a.Location] = true
	}
	kindNames := make([]string, 0, len(kinds))
	for k := range kinds {
		kindNames = append(kindNames, k+"="+strconv.Itoa(kinds[k]))
	}
	sort.Strings(kindNames)
	return CycloneDXBOM{
		BOMFormat: "CycloneDX", SpecVersion: CycloneDXSpecVersion, SerialNumber: "urn:uuid:" + meta.SerialUUID, Version: 1,
		Metadata: cdxMetadata{
			Timestamp: meta.GeneratedAt.UTC().Format(time.RFC3339),
			Tools:     cdxTools{Components: []cdxTool{{Type: "application", Name: "trstctl", Version: meta.ToolVersion}}},
			Properties: []cdxProperty{
				{Name: "trstctl:coverage:scope", Value: "assets trstctl observed: TLS endpoints and certificate keys at scanned addresses, and declared host crypto configuration"},
				{Name: "trstctl:coverage:assets", Value: strconv.Itoa(len(sorted))},
				{Name: "trstctl:coverage:asset_kinds", Value: strings.Join(kindNames, ",")},
				{Name: "trstctl:coverage:locations", Value: strconv.Itoa(len(locations))},
				{Name: "trstctl:coverage:not_covered", Value: "addresses and files no scan named; network traffic not observed passively; source code and container images not scanned"},
				{Name: "trstctl:coverage:compliance", Value: "none claimed: an algorithm choice is not a compliance determination"},
			},
		},
		Components: components,
		// The inventory lists what was observed; it never claims to be the
		// whole estate.
		Compositions: []cdxComposition{{Aggregate: "incomplete", Assemblies: refs}},
	}
}

func cycloneDXComponent(a CycloneDXAsset) CycloneDXAssetJS {
	c := CycloneDXAssetJS{
		Type: "cryptographic-asset", BOMRef: a.ID,
		Evidence: cdxEvidence{Occurrences: []cdxOccurrence{{Location: a.Location}}},
	}
	switch {
	case a.Kind == string(AssetCertKey) || (a.Algorithm != "" && a.Protocol == "" && a.Cipher == ""):
		c.Name, c.CryptoProperties = cycloneDXAlgorithm(a.Algorithm, a.KeyBits)
	case a.Cipher != "":
		c.Name = a.Cipher
		c.CryptoProperties = cdxCryptoProperties{AssetType: "protocol",
			ProtocolProperties: &cdxProtocolProperties{Type: "tls", CipherSuites: []cdxCipherSuite{{Name: a.Cipher}}}}
	default:
		version := strings.TrimPrefix(strings.TrimPrefix(a.Protocol, "TLSv"), "TLS ")
		c.Name = "TLS " + version
		c.CryptoProperties = cdxCryptoProperties{AssetType: "protocol", ProtocolProperties: &cdxProtocolProperties{Type: "tls", Version: version}}
	}
	c.Properties = []cdxProperty{
		{Name: "trstctl:asset_kind", Value: a.Kind},
		{Name: "trstctl:strength", Value: a.Strength},
		{Name: "trstctl:quantum_vulnerable", Value: strconv.FormatBool(a.QuantumVulnerable)},
		{Name: "trstctl:out_of_policy", Value: strconv.FormatBool(a.OutOfPolicy)},
	}
	if a.KeyBits > 0 {
		c.Properties = append(c.Properties, cdxProperty{Name: "trstctl:key_bits", Value: strconv.Itoa(a.KeyBits)})
	}
	for _, p := range []cdxProperty{
		{Name: "trstctl:certificate_fingerprint", Value: a.CertificateFingerprint},
		{Name: "trstctl:library", Value: a.Library},
		{Name: "trstctl:migration_target", Value: a.MigrationTarget},
	} {
		if p.Value != "" {
			c.Properties = append(c.Properties, p)
		}
	}
	for _, r := range a.Reasons {
		c.Properties = append(c.Properties, cdxProperty{Name: "trstctl:reason", Value: r})
	}
	return c
}

// cycloneDXAlgorithm names a key algorithm the way CycloneDX describes it:
// primitive, parameter set or curve, OID, and the classical and NIST quantum
// security levels where they are known. A family it does not recognize keeps
// its recorded name and no levels rather than a guess.
func cycloneDXAlgorithm(algorithm string, bits int) (string, cdxCryptoProperties) {
	level := func(n int) *int { return &n }
	up := strings.ToUpper(strings.TrimSpace(algorithm))
	props := cdxAlgorithmProperties{Primitive: "signature"}
	name, oid := strings.TrimSpace(algorithm), ""
	switch {
	case up == "":
		props.Primitive = "unknown"
	case strings.HasPrefix(up, "RSA"):
		name, oid = fmt.Sprintf("RSA-%d", bits), "1.2.840.113549.1.1.1"
		props.ParameterSetIdentifier, props.NISTQuantumSecurityLevel = strconv.Itoa(bits), level(0)
		props.ClassicalSecurityLevel = map[int]int{1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}[bits]
	case strings.HasPrefix(up, "ML-DSA"):
		props.ParameterSetIdentifier = strings.TrimPrefix(up, "ML-DSA-")
		props.NISTQuantumSecurityLevel = map[string]*int{"44": level(2), "65": level(3), "87": level(5)}[props.ParameterSetIdentifier]
		oid = map[string]string{"44": "2.16.840.1.101.3.4.3.17", "65": "2.16.840.1.101.3.4.3.18", "87": "2.16.840.1.101.3.4.3.19"}[props.ParameterSetIdentifier]
	case strings.HasPrefix(up, "ML-KEM"):
		props.Primitive, props.ParameterSetIdentifier = "kem", strings.TrimPrefix(up, "ML-KEM-")
		props.NISTQuantumSecurityLevel = map[string]*int{"512": level(1), "768": level(3), "1024": level(5)}[props.ParameterSetIdentifier]
		oid = map[string]string{"512": "2.16.840.1.101.3.4.4.1", "768": "2.16.840.1.101.3.4.4.2", "1024": "2.16.840.1.101.3.4.4.3"}[props.ParameterSetIdentifier]
	case strings.HasPrefix(up, "SLH-DSA"):
		switch {
		case strings.Contains(up, "128"):
			props.NISTQuantumSecurityLevel = level(1)
		case strings.Contains(up, "192"):
			props.NISTQuantumSecurityLevel = level(3)
		case strings.Contains(up, "256"):
			props.NISTQuantumSecurityLevel = level(5)
		}
	case strings.HasPrefix(up, "ED25519"):
		name, oid, props.Curve, props.ClassicalSecurityLevel, props.NISTQuantumSecurityLevel = "Ed25519", "1.3.101.112", "Ed25519", 128, level(0)
	case strings.HasPrefix(up, "ED448"):
		name, oid, props.Curve, props.ClassicalSecurityLevel, props.NISTQuantumSecurityLevel = "Ed448", "1.3.101.113", "Ed448", 224, level(0)
	case strings.HasPrefix(up, "DSA"):
		name, oid = fmt.Sprintf("DSA-%d", bits), "1.2.840.10040.4.1"
		props.ParameterSetIdentifier, props.NISTQuantumSecurityLevel = strconv.Itoa(bits), level(0)
	case strings.HasPrefix(up, "EC") || strings.Contains(up, "P-"):
		curve := map[int]string{256: "secp256r1", 384: "secp384r1", 521: "secp521r1"}[bits]
		name, oid, props.Curve, props.NISTQuantumSecurityLevel = fmt.Sprintf("ECDSA-P%d", bits), "1.2.840.10045.2.1", curve, level(0)
		props.ClassicalSecurityLevel = map[int]int{256: 128, 384: 192, 521: 256}[bits]
	default:
		props.Primitive = "unknown"
	}
	if name == "" {
		name = "unknown"
	}
	return name, cdxCryptoProperties{AssetType: "algorithm", AlgorithmProperties: &props, OID: oid}
}
