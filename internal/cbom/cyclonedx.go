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

// CycloneDXSupplement is what the export carries beside the inventory's
// assets (Q3-L2): the certificates the certificate inventory holds for the
// inventory's certificate keys, and what host agents and observers report —
// private keys in keystores and key files, crypto libraries, and observed
// handshakes. CutAt names a class that had more than its bound, and the
// bound it was cut at.
type CycloneDXSupplement struct {
	Certificates []CycloneDXCertificate
	Keys         []CycloneDXKeyMaterial
	Libraries    []CycloneDXLibrary
	Observations []CycloneDXObservation
	CutAt        map[string]int
}

// CycloneDXCertificate is a certificate the inventory holds for a CBOM key:
// KeyRefs are the bom-refs (asset IDs) of the inventory's certificate-key
// assets with its fingerprint, and Locations where they were observed.
type CycloneDXCertificate struct {
	Fingerprint string
	Subject     string
	Issuer      string
	Serial      string
	NotBefore   time.Time
	NotAfter    time.Time
	KeyRefs     []string
	Locations   []string
}

// CycloneDXKeyMaterial is a private key a host agent found in a keystore or a
// key file: its algorithm and size, never key bytes. Secret marks a keystore
// that holds secret keys only.
type CycloneDXKeyMaterial struct {
	ID          string
	Secret      bool
	Location    string
	Format      string
	Algorithm   string
	KeyBits     int
	Fingerprint string
	Encrypted   bool
	Weak        bool
	Reasons     []string
}

// CycloneDXLibrary is a crypto library a host agent identified, with whether
// its version can negotiate X25519MLKEM768 (yes, no, unknown).
type CycloneDXLibrary struct {
	ID       string
	Name     string
	Version  string
	Location string
	PQHybrid string
}

// CycloneDXObservation is a handshake a network or TLS session observer saw:
// the protocol (tls or ssh), its version, cipher suite and key exchange group.
type CycloneDXObservation struct {
	ID          string
	Observer    string
	Location    string
	Protocol    string
	Version     string
	CipherSuite string
	Group       string
	PQHybrid    bool
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

// CycloneDXAssetJS is one component: a cryptographic asset, or a crypto
// library (Q3-L2) with its version and no crypto properties.
type CycloneDXAssetJS struct {
	Type             string               `json:"type"`
	BOMRef           string               `json:"bom-ref"`
	Name             string               `json:"name"`
	Version          string               `json:"version,omitempty"`
	CryptoProperties *cdxCryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         cdxEvidence          `json:"evidence"`
	Properties       []cdxProperty        `json:"properties"`
}

type cdxCryptoProperties struct {
	AssetType                       string                      `json:"assetType"`
	AlgorithmProperties             *cdxAlgorithmProperties     `json:"algorithmProperties,omitempty"`
	CertificateProperties           *cdxCertificateProperties   `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *cdxRelatedCryptoProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties              *cdxProtocolProperties      `json:"protocolProperties,omitempty"`
	OID                             string                      `json:"oid,omitempty"`
}

type cdxCertificateProperties struct {
	SubjectName         string `json:"subjectName,omitempty"`
	IssuerName          string `json:"issuerName,omitempty"`
	NotValidBefore      string `json:"notValidBefore,omitempty"`
	NotValidAfter       string `json:"notValidAfter,omitempty"`
	SubjectPublicKeyRef string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat   string `json:"certificateFormat"`
}

type cdxRelatedCryptoProperties struct {
	Type   string `json:"type"`
	Size   int    `json:"size,omitempty"`
	Format string `json:"format,omitempty"`
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
	return CycloneDXWith(assets, CycloneDXSupplement{}, meta)
}

// CycloneDXWith builds the BOM for the inventory and what beside it the
// export carries (Q3-L2): the inventory's assets ordered by ID, then the
// certificates, the host keys, the crypto libraries and the observed
// handshakes, each class in a stable order.
func CycloneDXWith(assets []CycloneDXAsset, extra CycloneDXSupplement, meta CycloneDXMeta) CycloneDXBOM {
	sorted := append([]CycloneDXAsset(nil), assets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	components := make([]CycloneDXAssetJS, 0, len(sorted)+len(extra.Certificates)+len(extra.Keys)+len(extra.Libraries)+len(extra.Observations))
	kinds := map[string]int{}
	locations := map[string]bool{}
	for _, a := range sorted {
		components = append(components, cycloneDXComponent(a))
		kinds[a.Kind]++
		locations[a.Location] = true
	}
	certificates := append([]CycloneDXCertificate(nil), extra.Certificates...)
	sort.Slice(certificates, func(i, j int) bool { return certificates[i].Fingerprint < certificates[j].Fingerprint })
	for _, c := range certificates {
		components = append(components, cycloneDXCertificate(c))
		for _, l := range c.Locations {
			locations[l] = true
		}
	}
	keys := append([]CycloneDXKeyMaterial(nil), extra.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	for _, k := range keys {
		components = append(components, cycloneDXKeyMaterial(k))
		locations[k.Location] = true
	}
	libraries := append([]CycloneDXLibrary(nil), extra.Libraries...)
	sort.Slice(libraries, func(i, j int) bool { return libraries[i].ID < libraries[j].ID })
	for _, l := range libraries {
		components = append(components, cycloneDXLibrary(l))
		locations[l.Location] = true
	}
	observations := append([]CycloneDXObservation(nil), extra.Observations...)
	sort.Slice(observations, func(i, j int) bool { return observations[i].ID < observations[j].ID })
	for _, o := range observations {
		components = append(components, cycloneDXObservation(o))
		locations[o.Location] = true
	}
	refs := make([]string, 0, len(components))
	for _, c := range components {
		refs = append(refs, c.BOMRef)
	}
	kindNames := make([]string, 0, len(kinds))
	for k := range kinds {
		kindNames = append(kindNames, k+"="+strconv.Itoa(kinds[k]))
	}
	sort.Strings(kindNames)
	properties := []cdxProperty{
		{Name: "trstctl:coverage:scope", Value: "assets trstctl observed: TLS endpoints and certificate keys at scanned addresses, declared host crypto configuration, " +
			"imported CBOMs, the certificates the inventory holds for those keys, and what host agents and observers reported: keys in keystores and key files, " +
			"crypto libraries, and observed TLS and SSH handshakes"},
		{Name: "trstctl:coverage:assets", Value: strconv.Itoa(len(sorted))},
		{Name: "trstctl:coverage:asset_kinds", Value: strings.Join(kindNames, ",")},
		{Name: "trstctl:coverage:certificates", Value: strconv.Itoa(len(certificates))},
		{Name: "trstctl:coverage:host_keys", Value: strconv.Itoa(len(keys))},
		{Name: "trstctl:coverage:libraries", Value: strconv.Itoa(len(libraries))},
		{Name: "trstctl:coverage:observed_handshakes", Value: strconv.Itoa(len(observations))},
		{Name: "trstctl:coverage:locations", Value: strconv.Itoa(len(locations))},
	}
	var cut []string
	for class, n := range extra.CutAt {
		if n > 0 {
			cut = append(cut, class+"="+strconv.Itoa(n))
		}
	}
	sort.Strings(cut)
	if len(cut) > 0 {
		properties = append(properties, cdxProperty{Name: "trstctl:coverage:cut_at", Value: strings.Join(cut, ",")})
	}
	properties = append(properties,
		cdxProperty{Name: "trstctl:coverage:not_covered", Value: "addresses and files no scan named; network traffic outside the interfaces observer agents watch; source code and container images only as far as imported CBOMs cover them"},
		cdxProperty{Name: "trstctl:coverage:compliance", Value: "none claimed: an algorithm choice is not a compliance determination"},
	)
	return CycloneDXBOM{
		BOMFormat: "CycloneDX", SpecVersion: CycloneDXSpecVersion, SerialNumber: "urn:uuid:" + meta.SerialUUID, Version: 1,
		Metadata: cdxMetadata{
			Timestamp:  meta.GeneratedAt.UTC().Format(time.RFC3339),
			Tools:      cdxTools{Components: []cdxTool{{Type: "application", Name: "trstctl", Version: meta.ToolVersion}}},
			Properties: properties,
		},
		Components: components,
		// The inventory lists what was observed; it never claims to be the
		// whole estate.
		Compositions: []cdxComposition{{Aggregate: "incomplete", Assemblies: refs}},
	}
}

// cycloneDXCertificate is a certificate component: subject, issuer and
// validity, its key the inventory's certificate-key asset.
func cycloneDXCertificate(c CycloneDXCertificate) CycloneDXAssetJS {
	props := &cdxCertificateProperties{SubjectName: c.Subject, IssuerName: c.Issuer, CertificateFormat: "X.509"}
	if !c.NotBefore.IsZero() {
		props.NotValidBefore = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if !c.NotAfter.IsZero() {
		props.NotValidAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	if len(c.KeyRefs) > 0 {
		props.SubjectPublicKeyRef = c.KeyRefs[0]
	}
	name := c.Subject
	if name == "" {
		name = "certificate " + c.Fingerprint
	}
	out := CycloneDXAssetJS{
		Type: "cryptographic-asset", BOMRef: "certificate:" + c.Fingerprint, Name: name,
		CryptoProperties: &cdxCryptoProperties{AssetType: "certificate", CertificateProperties: props},
		Properties: []cdxProperty{
			{Name: "trstctl:asset_kind", Value: "certificate"},
			{Name: "trstctl:certificate_fingerprint", Value: c.Fingerprint},
		},
	}
	if c.Serial != "" {
		out.Properties = append(out.Properties, cdxProperty{Name: "trstctl:serial", Value: c.Serial})
	}
	for _, l := range c.Locations {
		out.Evidence.Occurrences = append(out.Evidence.Occurrences, cdxOccurrence{Location: l})
	}
	return out
}

// cycloneDXKeyMaterial is a private key a host agent found, as related
// crypto material: its type, size and container format.
func cycloneDXKeyMaterial(k CycloneDXKeyMaterial) CycloneDXAssetJS {
	material, label := "private-key", "private key"
	if k.Secret {
		material, label = "secret-key", "secret keys"
	}
	name := strings.TrimSpace(k.Algorithm)
	if name == "" || name == "unknown" {
		name = label
	} else {
		name += " " + label
	}
	out := CycloneDXAssetJS{
		Type: "cryptographic-asset", BOMRef: "crypto-material:" + k.ID, Name: name,
		CryptoProperties: &cdxCryptoProperties{AssetType: "related-crypto-material",
			RelatedCryptoMaterialProperties: &cdxRelatedCryptoProperties{Type: material, Size: k.KeyBits, Format: k.Format}},
		Evidence: cdxEvidence{Occurrences: []cdxOccurrence{{Location: k.Location}}},
		Properties: []cdxProperty{
			{Name: "trstctl:asset_kind", Value: "host-key"},
			{Name: "trstctl:algorithm", Value: k.Algorithm},
			{Name: "trstctl:encrypted", Value: strconv.FormatBool(k.Encrypted)},
			{Name: "trstctl:strength", Value: map[bool]string{true: "weak", false: "unrated"}[k.Weak]},
		},
	}
	if k.Fingerprint != "" {
		out.Properties = append(out.Properties, cdxProperty{Name: "trstctl:public_key_fingerprint", Value: k.Fingerprint})
	}
	for _, r := range k.Reasons {
		out.Properties = append(out.Properties, cdxProperty{Name: "trstctl:reason", Value: r})
	}
	return out
}

// cycloneDXLibrary is a crypto library component with its version.
func cycloneDXLibrary(l CycloneDXLibrary) CycloneDXAssetJS {
	name := strings.TrimSpace(l.Name)
	if name == "" {
		name = "crypto library"
	}
	return CycloneDXAssetJS{
		Type: "library", BOMRef: "library:" + l.ID, Name: name, Version: l.Version,
		Evidence: cdxEvidence{Occurrences: []cdxOccurrence{{Location: l.Location}}},
		Properties: []cdxProperty{
			{Name: "trstctl:asset_kind", Value: "crypto-library"},
			{Name: "trstctl:pq_hybrid_x25519mlkem768", Value: l.PQHybrid},
		},
	}
}

// cycloneDXObservation is an observed handshake as a protocol component.
func cycloneDXObservation(o CycloneDXObservation) CycloneDXAssetJS {
	protocol := &cdxProtocolProperties{Type: o.Protocol}
	name := strings.ToUpper(o.Protocol)
	if o.Protocol == "tls" {
		protocol.Version = strings.TrimPrefix(strings.TrimPrefix(o.Version, "TLSv"), "TLS ")
		name = "TLS " + protocol.Version
	}
	if o.CipherSuite != "" {
		protocol.CipherSuites = []cdxCipherSuite{{Name: o.CipherSuite}}
	}
	out := CycloneDXAssetJS{
		Type: "cryptographic-asset", BOMRef: "observed:" + o.ID, Name: name,
		CryptoProperties: &cdxCryptoProperties{AssetType: "protocol", ProtocolProperties: protocol},
		Evidence:         cdxEvidence{Occurrences: []cdxOccurrence{{Location: o.Location}}},
		Properties: []cdxProperty{
			{Name: "trstctl:asset_kind", Value: "observed-handshake"},
			{Name: "trstctl:observer", Value: o.Observer},
			{Name: "trstctl:pq_hybrid", Value: strconv.FormatBool(o.PQHybrid)},
		},
	}
	if o.Group != "" {
		out.Properties = append(out.Properties, cdxProperty{Name: "trstctl:key_exchange_group", Value: o.Group})
	}
	return out
}

func cycloneDXComponent(a CycloneDXAsset) CycloneDXAssetJS {
	c := CycloneDXAssetJS{
		Type: "cryptographic-asset", BOMRef: a.ID,
		Evidence: cdxEvidence{Occurrences: []cdxOccurrence{{Location: a.Location}}},
	}
	var props cdxCryptoProperties
	switch {
	case a.Kind == string(AssetCertKey) || (a.Algorithm != "" && a.Protocol == "" && a.Cipher == ""):
		c.Name, props = cycloneDXAlgorithm(a.Algorithm, a.KeyBits)
	case a.Cipher != "":
		c.Name = a.Cipher
		props = cdxCryptoProperties{AssetType: "protocol",
			ProtocolProperties: &cdxProtocolProperties{Type: "tls", CipherSuites: []cdxCipherSuite{{Name: a.Cipher}}}}
	default:
		version := strings.TrimPrefix(strings.TrimPrefix(a.Protocol, "TLSv"), "TLS ")
		c.Name = "TLS " + version
		props = cdxCryptoProperties{AssetType: "protocol", ProtocolProperties: &cdxProtocolProperties{Type: "tls", Version: version}}
	}
	c.CryptoProperties = &props
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
