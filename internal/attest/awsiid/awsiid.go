// Package awsiid is the AWS IMDSv2 instance-identity attester (S11.4, F30). AWS
// publishes a PKCS#7 signature over an instance's identity document, signed by a
// regional AWS certificate. This attester verifies that signature against a
// trusted AWS root and establishes the EC2 instance as a verified subject; a
// forged document or one signed by an untrusted key is rejected (fail-closed).
package awsiid

import (
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// Document is the subset of the AWS instance identity document this attester uses.
type Document struct {
	InstanceID   string `json:"instanceId"`
	AccountID    string `json:"accountId"`
	Region       string `json:"region"`
	InstanceType string `json:"instanceType"`
	ImageID      string `json:"imageId"`
	PendingTime  string `json:"pendingTime"`
}

// Attestor verifies AWS IMDSv2 identity documents (PKCS#7 / CMS).
type Attestor struct {
	// Roots are the trusted AWS regional signing certificates (DER).
	Roots [][]byte
	// AllowedAccounts, if non-empty, restricts attestation to these AWS accounts.
	AllowedAccounts map[string]bool
}

// Method implements attest.Attestor.
func (a *Attestor) Method() string { return "aws_iid" }

// Attest verifies the CMS-signed identity document and returns the attestation.
func (a *Attestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	content, err := crypto.VerifyCMSSignature(payload, a.Roots)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("aws_iid: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(content, &doc); err != nil {
		return attest.Attestation{}, fmt.Errorf("aws_iid: parse document: %w", err)
	}
	if doc.InstanceID == "" || doc.AccountID == "" {
		return attest.Attestation{}, fmt.Errorf("aws_iid: document missing instanceId/accountId")
	}
	if len(a.AllowedAccounts) > 0 && !a.AllowedAccounts[doc.AccountID] {
		return attest.Attestation{}, fmt.Errorf("aws_iid: account %s is not allowed", doc.AccountID)
	}
	return attest.Attestation{
		Subject: doc.InstanceID,
		Selectors: []string{
			"aws:account:" + doc.AccountID,
			"aws:region:" + doc.Region,
			"aws:instance-id:" + doc.InstanceID,
			"aws:image-id:" + doc.ImageID,
			"aws:instance-type:" + doc.InstanceType,
		},
		Claims: map[string]string{
			"account_id":  doc.AccountID,
			"region":      doc.Region,
			"instance_id": doc.InstanceID,
			"image_id":    doc.ImageID,
		},
	}, nil
}
