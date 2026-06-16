// Package azureimds is the Azure IMDS attested-data attester (S11.6, F30). Azure
// IMDS returns a PKCS#7 signature over an attested document describing the VM,
// signed by an Azure certificate. This attester verifies that signature against a
// trusted Azure root and establishes the VM as a verified subject; a forged or
// untrusted document is rejected (fail-closed).
package azureimds

import (
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// Document is the subset of the Azure attested document this attester uses.
type Document struct {
	VMID              string `json:"vmId"`
	SubscriptionID    string `json:"subscriptionId"`
	ResourceGroupName string `json:"resourceGroupName"`
	Location          string `json:"location"`
	Name              string `json:"name"`
}

// Attestor verifies Azure IMDS attested documents (PKCS#7 / CMS).
type Attestor struct {
	// Roots are the trusted Azure signing certificates (DER).
	Roots [][]byte
	// AllowedSubscriptions, if non-empty, restricts attestation to these subscriptions.
	AllowedSubscriptions map[string]bool
}

// Method implements attest.Attestor.
func (a *Attestor) Method() string { return "azure_imds" }

// Attest verifies the CMS-signed attested document and returns the attestation.
func (a *Attestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	content, err := crypto.VerifyCMSSignature(payload, a.Roots)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("azure_imds: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(content, &doc); err != nil {
		return attest.Attestation{}, fmt.Errorf("azure_imds: parse document: %w", err)
	}
	if doc.VMID == "" || doc.SubscriptionID == "" {
		return attest.Attestation{}, fmt.Errorf("azure_imds: document missing vmId/subscriptionId")
	}
	if len(a.AllowedSubscriptions) > 0 && !a.AllowedSubscriptions[doc.SubscriptionID] {
		return attest.Attestation{}, fmt.Errorf("azure_imds: subscription %s is not allowed", doc.SubscriptionID)
	}
	return attest.Attestation{
		Subject: doc.VMID,
		Selectors: []string{
			"azure:subscription:" + doc.SubscriptionID,
			"azure:resource-group:" + doc.ResourceGroupName,
			"azure:location:" + doc.Location,
			"azure:vm-id:" + doc.VMID,
		},
		Claims: map[string]string{
			"subscription_id": doc.SubscriptionID,
			"resource_group":  doc.ResourceGroupName,
			"location":        doc.Location,
			"vm_id":           doc.VMID,
		},
	}, nil
}
