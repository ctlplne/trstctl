// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

var oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

type extKeyUsageDef struct {
	name  string
	oid   asn1.ObjectIdentifier
	usage x509.ExtKeyUsage
}

var extKeyUsageDefs = []extKeyUsageDef{
	{name: "any", oid: asn1.ObjectIdentifier{2, 5, 29, 37, 0}, usage: x509.ExtKeyUsageAny},
	{name: "serverAuth", oid: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, usage: x509.ExtKeyUsageServerAuth},
	{name: "clientAuth", oid: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, usage: x509.ExtKeyUsageClientAuth},
	{name: "codeSigning", oid: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, usage: x509.ExtKeyUsageCodeSigning},
	{name: "emailProtection", oid: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, usage: x509.ExtKeyUsageEmailProtection},
	{name: "timeStamping", oid: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, usage: x509.ExtKeyUsageTimeStamping},
	{name: "ocspSigning", oid: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, usage: x509.ExtKeyUsageOCSPSigning},
}

func marshalExtKeyUsageExtension(names []string) (pkix.Extension, error) {
	oids, err := extKeyUsageOIDsFromNames(names)
	if err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("crypto: marshal extended key usage extension: %w", err)
	}
	return pkix.Extension{Id: oidExtensionExtendedKeyUsage, Value: value}, nil
}

func extKeyUsageOIDsFromNames(names []string) ([]asn1.ObjectIdentifier, error) {
	out := make([]asn1.ObjectIdentifier, 0, len(names))
	for _, name := range names {
		oid, err := extKeyUsageOID(name)
		if err != nil {
			return nil, err
		}
		out = append(out, oid)
	}
	return out, nil
}

func extKeyUsageOID(name string) (asn1.ObjectIdentifier, error) {
	for _, def := range extKeyUsageDefs {
		if name == def.name {
			return cloneOID(def.oid), nil
		}
	}
	oid, err := parseDottedOID(name)
	if err != nil {
		return nil, fmt.Errorf("crypto: unsupported extended key usage %q", name)
	}
	return oid, nil
}

func extKeyUsageNamesFromExtensions(exts []pkix.Extension) ([]string, error) {
	var out []string
	for _, ext := range exts {
		if !ext.Id.Equal(oidExtensionExtendedKeyUsage) {
			continue
		}
		names, err := extKeyUsageNamesFromDER(ext.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, names...)
	}
	return dedupeStrings(out), nil
}

func extKeyUsageNamesFromDER(raw []byte) ([]string, error) {
	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(raw, &oids)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse requested extended key usages: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("crypto: parse requested extended key usages: trailing data")
	}
	out := make([]string, 0, len(oids))
	for _, oid := range oids {
		out = append(out, extKeyUsageName(oid))
	}
	return dedupeStrings(out), nil
}

func leafExtKeyUsage(names []string) ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	if len(names) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nil, nil
	}
	var known []x509.ExtKeyUsage
	var custom []asn1.ObjectIdentifier
	for _, name := range names {
		if usage, ok := knownExtKeyUsage(name); ok {
			known = append(known, usage)
			continue
		}
		oid, err := parseDottedOID(name)
		if err != nil {
			return nil, nil, fmt.Errorf("unsupported extended key usage %q", name)
		}
		custom = append(custom, oid)
	}
	if len(known) == 0 && len(custom) == 0 {
		return nil, nil, fmt.Errorf("extended key usage profile resolved to an empty set")
	}
	return known, custom, nil
}

func knownExtKeyUsage(name string) (x509.ExtKeyUsage, bool) {
	for _, def := range extKeyUsageDefs {
		if name == def.name {
			return def.usage, true
		}
	}
	return 0, false
}

func extKeyUsageName(oid asn1.ObjectIdentifier) string {
	for _, def := range extKeyUsageDefs {
		if oid.Equal(def.oid) {
			return def.name
		}
	}
	return oid.String()
}

func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "oid:")
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID")
	}
	out := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid OID")
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID")
		}
		out = append(out, n)
	}
	if out[0] > 2 || (out[0] < 2 && out[1] > 39) {
		return nil, fmt.Errorf("invalid OID")
	}
	return out, nil
}

func cloneOID(in asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	out := make(asn1.ObjectIdentifier, len(in))
	copy(out, in)
	return out
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
