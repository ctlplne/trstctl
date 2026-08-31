// SPDX-License-Identifier: MPL-2.0
package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/featureparity"
)

// ErrUnknownTool means a selector does not name a canonical product tool. An
// unknown selector must never silently turn into an unfiltered export.
var ErrUnknownTool = errors.New("audit: tool must name a supported canonical tool")

// Projector events inherit the canonical capability's tool. Runtime protocol
// events also have deliberately owned namespaces: they are not free-text
// searches in actor names, subjects, or error messages. Shared lifecycle events
// may appear in more than one tool; there remains one tenant audit stream.
var runtimeToolNamespaces = map[featureparity.CanonicalTool][]string{
	featureparity.ToolDiscover:             {"discovery.", "drift."},
	featureparity.ToolCertificates:         {"certificate.", "ca.", "acme.", "est.", "scep.", "cmp.", "ct.", "ocsp.", "crl.", "mdm."},
	featureparity.ToolWorkloadsMachines:    {"workload.", "attestation.", "ephemeral.", "spiffe.", "ssh.", "agent.", "broker.", "edge.", "pam."},
	featureparity.ToolSecrets:              {"secret.", "kmip.", "transit."},
	featureparity.ToolSoftwareTrust:        {"codesign.", "timestamp.", "tsa.", "cbom."},
	featureparity.ToolOperations:           {"incident.", "compromise.", "rotation.", "notification.", "owner.", "approval.", "policy.", "compliance.", "audit.", "privacy.", "graph.", "connector."},
	featureparity.ToolPlatformIntegrations: {"auth.", "access.", "tenant.", "license.", "plugin.", "federation.", "config.", "ai.", "mcp."},
}

var canonicalToolEvents = sync.OnceValues(func() (map[string]map[string]bool, error) {
	catalog, err := featureparity.LoadEmbedded()
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]bool, len(catalog.CanonicalTools))
	for _, tool := range catalog.CanonicalTools {
		result[string(tool)] = map[string]bool{}
	}
	for _, item := range catalog.Items {
		// Campaign bookkeeping and every other catalogued action use exact
		// server-owned event names, never a guessed execution namespace.
		types, _ := eventledger.EventTypesForFeatureAction(item.FeatureID, "")
		for _, typ := range types {
			result[string(item.Contract.Tool)][typ] = true
		}
	}
	return result, nil
})

// ValidateTool accepts the unscoped view or one server-owned canonical tool ID.
func ValidateTool(tool string) error {
	if tool == "" {
		return nil
	}
	tools, err := canonicalToolEvents()
	if err != nil {
		return err
	}
	if _, ok := tools[tool]; !ok {
		return ErrUnknownTool
	}
	return nil
}

type auditToolScope struct {
	tool    string
	types   map[string]bool
	objects map[string]bool
}

func newAuditToolScope(tool string) (*auditToolScope, error) {
	if err := ValidateTool(tool); err != nil {
		return nil, err
	}
	if tool == "" {
		return nil, nil
	}
	types, err := canonicalToolEvents()
	if err != nil {
		return nil, err
	}
	return &auditToolScope{tool: tool, types: types[tool], objects: map[string]bool{}}, nil
}

type auditObjectCoordinates struct {
	ID           string `json:"id"`
	IdentityID   string `json:"identity_id"`
	CredentialID string `json:"credential_id"`
	Fingerprint  string `json:"fingerprint"`
	Source       string `json:"source"`
	Kind         string `json:"kind"`
}

func workloadCertificateSource(source string) bool {
	return strings.HasPrefix(source, "attested:") || strings.HasPrefix(source, "ephemeral:") || strings.HasPrefix(source, "broker:") || source == "edge-delegation"
}

// Observe only the tenant's immutable object coordinates, including the retained
// prefix. A later revocation need not repeat a certificate's original source.
// Never infer membership from user-authored display names or private proof.
func (s *auditToolScope) observe(e events.Event) {
	if s == nil || s.tool != string(featureparity.ToolWorkloadsMachines) {
		return
	}
	if e.Type != "certificate.recorded" && e.Type != "identity.created" {
		return
	}
	var object auditObjectCoordinates
	if json.Unmarshal(e.Data, &object) != nil {
		return
	}
	if e.Type == "certificate.recorded" && workloadCertificateSource(object.Source) {
		if object.ID != "" {
			s.objects["certificate:"+object.ID] = true
		}
		if object.Fingerprint != "" {
			s.objects["fingerprint:"+object.Fingerprint] = true
		}
	}
	if e.Type == "identity.created" && (object.Kind == "workload_identity" || object.Kind == "ssh_certificate" || object.Kind == "ssh_key") && object.ID != "" {
		s.objects["identity:"+object.ID] = true
	}
}

func (s *auditToolScope) matches(e events.Event) bool {
	if s == nil {
		return true
	}
	if s.types[e.Type] {
		return true
	}
	for _, prefix := range runtimeToolNamespaces[featureparity.CanonicalTool(s.tool)] {
		if strings.HasPrefix(e.Type, prefix) {
			return true
		}
	}
	if s.tool != string(featureparity.ToolWorkloadsMachines) {
		return false
	}
	if !strings.HasPrefix(e.Type, "certificate.") && !strings.HasPrefix(e.Type, "identity.") {
		return false
	}
	var object auditObjectCoordinates
	if json.Unmarshal(e.Data, &object) != nil {
		return false
	}
	if strings.HasPrefix(e.Type, "certificate.") {
		return (e.Type == "certificate.recorded" && workloadCertificateSource(object.Source)) ||
			(object.ID != "" && s.objects["certificate:"+object.ID]) || (object.Fingerprint != "" && s.objects["fingerprint:"+object.Fingerprint])
	}
	return (object.ID != "" && s.objects["identity:"+object.ID]) || (object.IdentityID != "" && s.objects["identity:"+object.IdentityID])
}
