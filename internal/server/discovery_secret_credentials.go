// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/store"
)

// recordCredential records an API key, token or private key that content
// inspection found inside a stored secret (A172): the rule, the field, the
// masked display and the credential's fingerprint, never the value. The
// finding's identity includes the field, so one credential stored in two
// places is two findings that share a fingerprint.
func (s cloudSecretDiscoveryRunSink) recordCredential(ctx context.Context, location string, f cloudsecret.Found) error {
	c := f.Credential
	if c == nil {
		return errors.New("server: credential finding without its credential")
	}
	ref := location
	if c.Field != "" {
		ref += "#" + c.Field
	}
	metaMap := make(map[string]any, len(f.Metadata)+12)
	for k, v := range f.Metadata {
		metaMap[k] = v
	}
	for k, v := range map[string]any{
		"provider": f.Provider, "resource_id": f.ResourceID, "secret_name": f.SecretName, "location": f.Location,
		"field": c.Field, "rule": c.Rule, "credential_kind": c.Kind, "masked": c.Masked, "content_inspected": true,
	} {
		metaMap[k] = v
	}
	if c.Principal != "" {
		metaMap["principal"] = c.Principal
	}
	if c.Truncated {
		metaMap["credential_scan_truncated"] = true
	}
	// A172-L3: a private key carries its public key's SHA-256, which links it
	// to the certificate for that key.
	if c.SPKISHA256 != "" {
		metaMap["spki_sha256"] = c.SPKISHA256
	}
	meta, err := json.Marshal(metaMap)
	if err != nil {
		return err
	}
	_, err = s.orch.RecordDiscoveryFinding(ctx, s.tenantID, store.DiscoveryFinding{
		RunID: s.runID, SourceID: s.sourceID, Kind: cloudsecret.FindingKindAPIKey, Ref: ref,
		Provenance: f.Provenance, Fingerprint: c.Fingerprint, RiskScore: c.Risk, Metadata: meta,
	})
	return err
}
