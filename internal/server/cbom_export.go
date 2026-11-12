// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/store"
)

// CycloneDXSupplement is what the CycloneDX export carries beside the CBOM
// inventory (Q3-L2): the certificates the certificate inventory holds for
// the inventory's certificate keys, joined by fingerprint, and the newest
// finding of each ref that host agents and observers reported — private keys
// in keystores and key files, crypto libraries, and observed TLS and SSH
// handshakes — each class at most store.MaxCBOMExportFindingsPerKind.
func (s *cbomService) CycloneDXSupplement(ctx context.Context, tenantID string, assets []cbom.CycloneDXAsset) (cbom.CycloneDXSupplement, error) {
	out := cbom.CycloneDXSupplement{CutAt: map[string]int{}}
	certificates, err := s.exportCertificates(ctx, tenantID, assets)
	if err != nil {
		return cbom.CycloneDXSupplement{}, err
	}
	out.Certificates = certificates

	keys, more, err := s.store.LatestDiscoveryFindingsOfKind(ctx, tenantID, "private_key", store.MaxCBOMExportFindingsPerKind)
	if err != nil {
		return cbom.CycloneDXSupplement{}, err
	}
	if more {
		out.CutAt["host_keys"] = store.MaxCBOMExportFindingsPerKind
	}
	for _, f := range keys {
		out.Keys = append(out.Keys, exportKeyMaterial(f))
	}

	libraries, more, err := s.store.LatestDiscoveryFindingsOfKind(ctx, tenantID, "crypto_library", store.MaxCBOMExportFindingsPerKind)
	if err != nil {
		return cbom.CycloneDXSupplement{}, err
	}
	if more {
		out.CutAt["libraries"] = store.MaxCBOMExportFindingsPerKind
	}
	for _, f := range libraries {
		meta := findingMetadata(f.Metadata)
		out.Libraries = append(out.Libraries, cbom.CycloneDXLibrary{ID: f.ID, Name: meta["library"], Version: meta["library_version"],
			Location: f.Ref, PQHybrid: meta["pq_hybrid_x25519mlkem768"]})
	}

	for _, kind := range []string{"tls_handshake", "ssh_kex", "tls_session"} {
		observed, more, err := s.store.LatestDiscoveryFindingsOfKind(ctx, tenantID, kind, store.MaxCBOMExportFindingsPerKind)
		if err != nil {
			return cbom.CycloneDXSupplement{}, err
		}
		if more {
			out.CutAt[kind] = store.MaxCBOMExportFindingsPerKind
		}
		for _, f := range observed {
			out.Observations = append(out.Observations, exportObservation(kind, f))
		}
	}
	return out, nil
}

// exportCertificates joins the inventory's certificate keys to the
// certificate inventory by fingerprint: one certificate per fingerprint, its
// key the first certificate-key asset (by ID) that carries it.
func (s *cbomService) exportCertificates(ctx context.Context, tenantID string, assets []cbom.CycloneDXAsset) ([]cbom.CycloneDXCertificate, error) {
	sorted := append([]cbom.CycloneDXAsset(nil), assets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	byFingerprint := map[string]*cbom.CycloneDXCertificate{}
	var fingerprints []string
	for _, a := range sorted {
		if a.CertificateFingerprint == "" {
			continue
		}
		c, ok := byFingerprint[a.CertificateFingerprint]
		if !ok {
			c = &cbom.CycloneDXCertificate{Fingerprint: a.CertificateFingerprint}
			byFingerprint[a.CertificateFingerprint] = c
			fingerprints = append(fingerprints, a.CertificateFingerprint)
		}
		c.KeyRefs = append(c.KeyRefs, a.ID)
		if !slices.Contains(c.Locations, a.Location) {
			c.Locations = append(c.Locations, a.Location)
		}
	}
	held, err := s.store.CertificatesByFingerprints(ctx, tenantID, fingerprints)
	if err != nil {
		return nil, fmt.Errorf("server: certificates for the CBOM export: %w", err)
	}
	out := make([]cbom.CycloneDXCertificate, 0, len(held))
	for _, fp := range fingerprints {
		row, ok := held[fp]
		if !ok {
			continue // a key whose certificate the inventory does not hold stays a key
		}
		c := *byFingerprint[fp]
		c.Subject, c.Issuer, c.Serial = row.Subject, row.Issuer, row.Serial
		if row.NotBefore != nil {
			c.NotBefore = *row.NotBefore
		}
		if row.NotAfter != nil {
			c.NotAfter = *row.NotAfter
		}
		out = append(out, c)
	}
	return out, nil
}

var trailingKeyBits = regexp.MustCompile(`(\d{3,5})$`)

// exportKeyMaterial maps a private_key finding (a keystore entry or a key
// file) to related crypto material: its container format, algorithm and
// size, never key bytes.
func exportKeyMaterial(f store.DiscoveryFinding) cbom.CycloneDXKeyMaterial {
	meta := findingMetadata(f.Metadata)
	k := cbom.CycloneDXKeyMaterial{ID: f.ID, Location: f.Ref, Format: meta["key_format"], Algorithm: meta["key_algorithm"],
		Fingerprint: f.Fingerprint, Encrypted: meta["encrypted"] == "true", Weak: meta["key_strength"] == "weak"}
	if bits, err := strconv.Atoi(meta["key_size_bits"]); err == nil && bits > 0 {
		k.KeyBits = bits
	} else if m := trailingKeyBits.FindStringSubmatch(k.Algorithm); m != nil {
		k.KeyBits, _ = strconv.Atoi(m[1])
	}
	if reason := meta["key_weak_reason"]; reason != "" {
		k.Reasons = strings.Split(reason, "; ")
	}
	// X2-L2: a keystore of secret keys only is reported once, as the store.
	k.Secret = meta["keystore_secret_keys"] != "" && f.Fingerprint == "" && (k.Algorithm == "" || k.Algorithm == "unknown") &&
		meta["keystore_state"] == "read"
	return k
}

// exportObservation maps an observer finding to a handshake: the network
// observer's TLS and SSH handshakes at a server, and the host session
// observer's TLS sessions of a process.
func exportObservation(kind string, f store.DiscoveryFinding) cbom.CycloneDXObservation {
	meta := findingMetadata(f.Metadata)
	o := cbom.CycloneDXObservation{ID: f.ID, Observer: "network-observer", Location: f.Ref, Protocol: "tls",
		Version: meta["tls_version"], CipherSuite: meta["cipher_suite"], Group: meta["group"], PQHybrid: meta["pq_hybrid"] == "true"}
	switch kind {
	case "ssh_kex":
		o.Protocol, o.Version, o.CipherSuite, o.Group = "ssh", "", meta["ssh_cipher"], meta["kex_algorithm"]
	case "tls_session":
		o.Observer = "tls-session-observer"
	}
	if server := meta["server"]; server != "" {
		o.Location = server
	}
	return o
}

// findingMetadata reads a finding's metadata as strings; a value that is not
// a string is rendered as its JSON text.
func findingMetadata(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return out
	}
	for k, v := range values {
		var s string
		if json.Unmarshal(v, &s) == nil {
			out[k] = s
			continue
		}
		out[k] = string(v)
	}
	return out
}
