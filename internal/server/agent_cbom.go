// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strconv"
	"strings"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/store"
)

// Host agents' crypto assets (X2-L5R). The TLS libraries, Go programs and
// Java installations a host agent inventories, the keys its keystores hold,
// and its private key files are CBOM assets too, at "<agent>:<path>", so the
// CBOM inventory lists them beside scanned and imported assets: a library
// classified by whether it can negotiate X25519MLKEM768, a key by its type
// and size. They are recorded as cbom.assets.observed events (AN-2), like
// every CBOM fact. Each report is the agent's whole inventory of its kind, so
// a library or key it no longer reports is retired by cbom.source.reconciled.

// agentCBOMFindings turns a host agent's recorded findings into CBOM
// findings, and names the reconciliation source; ok is false for a source
// that has none.
func agentCBOMFindings(agent, sourceKind string, findings []store.DiscoveryFinding) (out []cbom.Finding, reconcile string, ok bool) {
	keyKind := cbom.AssetKeystoreKey
	switch sourceKind {
	case agentdiscovery.SourceCryptoLibrary:
		reconcile = store.AgentCryptoLibrarySource
	case agentdiscovery.SourceKeystore:
		reconcile = store.AgentKeystoreSource
	case agentdiscovery.SourcePrivateKey:
		reconcile, keyKind = store.AgentPrivateKeySource, cbom.AssetKeyFile
	default:
		return nil, "", false
	}
	policy := cbom.DefaultPolicy()
	for _, f := range findings {
		ref := strings.TrimSpace(f.Ref)
		if ref == "" {
			continue
		}
		meta := findingMetadata(f.Metadata)
		var asset cbom.Finding
		switch kind := strings.TrimSpace(f.Kind); {
		case reconcile == store.AgentCryptoLibrarySource && kind == "crypto_library":
			library := meta["library"]
			if library == "" {
				continue
			}
			asset = cbom.Finding{Kind: cbom.AssetCryptoLibrary, Location: agent + ":" + ref, Library: library,
				ProductVersion: strings.TrimSpace(library + " " + meta["library_version"]),
				PQHybrid:       meta["pq_hybrid_x25519mlkem768"], PQBasis: meta["pq_basis"]}
		case reconcile != store.AgentCryptoLibrarySource && kind == "private_key":
			// A key names its type and size; a locked store or a store's
			// own summary names neither and is no key asset.
			algorithm, bits := keyAlgorithmAndSize(meta)
			if algorithm == "" {
				continue
			}
			asset = cbom.Finding{Kind: keyKind, Location: agent + ":" + ref, Algorithm: algorithm, KeyBits: bits}
			if meta["key_strength"] == "weak" && meta["key_weak_reason"] != "" {
				asset.KeyWeakReasons = strings.Split(meta["key_weak_reason"], "; ")
			}
		default:
			continue
		}
		out = append(out, asset.Classified(policy))
	}
	return out, reconcile, true
}

// keyAlgorithmAndSize reads a reported key's type and size: a keystore entry
// names them (key_type, key_size_bits), and a key file one algorithm
// (RSA-2048, ECDSA-P256, Ed25519).
func keyAlgorithmAndSize(meta map[string]string) (string, int) {
	if t := meta["key_type"]; t != "" {
		if bits, err := strconv.Atoi(meta["key_size_bits"]); err == nil && bits > 0 {
			return t, bits
		}
	}
	switch algorithm := meta["key_algorithm"]; algorithm {
	case "Ed25519":
		return algorithm, 256
	case "":
		return "", 0
	default:
		family, size, ok := strings.Cut(algorithm, "-")
		bits, err := strconv.Atoi(strings.TrimPrefix(size, "P"))
		if !ok || err != nil || bits <= 0 {
			return "", 0
		}
		return family, bits
	}
}

// recordAgentCBOM records a host agent's library or key report as CBOM
// assets and retires those of its host the report no longer names.
func (a *agentService) recordAgentCBOM(ctx context.Context, tenantID, agent, sourceKind string, findings []store.DiscoveryFinding) error {
	assets, reconcile, ok := agentCBOMFindings(agent, sourceKind, findings)
	if !ok || a.log == nil || a.store == nil {
		return nil
	}
	sink := &eventedCBOMSink{store: a.store, log: a.log, tenantID: tenantID}
	if len(assets) > 0 {
		if err := sink.RecordBatch(ctx, assets); err != nil {
			return err
		}
	}
	return sink.Reconcile(ctx, reconcile, agent)
}
