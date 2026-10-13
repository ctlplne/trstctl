// SPDX-License-Identifier: BUSL-1.1

// Package offline contains only public request validation and signer-safe
// emergency certificate construction. It does not link the control plane,
// datastore, event log, audit exporter or HTTP server into trstctl-signer.
package offline

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

type Bundle struct {
	Version          int               `json:"version,omitempty"`
	RequestID        string            `json:"request_id"`
	Subject          string            `json:"subject"`
	CertDER          []byte            `json:"cert_der"`
	Reason           string            `json:"reason"`
	Approvals        []string          `json:"approvals"`
	IssuedAt         time.Time         `json:"issued_at"`
	Signature        []byte            `json:"signature"`
	OfflineRequest   *OfflineRequest   `json:"offline_request,omitempty"`
	OfflineApprovals []OfflineApproval `json:"offline_approvals,omitempty"`
}

type legacyManifest struct {
	RequestID  string   `json:"request_id"`
	Subject    string   `json:"subject"`
	CertSHA256 string   `json:"cert_sha256"`
	Reason     string   `json:"reason"`
	Approvals  []string `json:"approvals"`
	IssuedAt   int64    `json:"issued_at"`
}

// ManifestBytes preserves the historical v1 encoding exactly while domain
// separating v2, which commits to the complete signed custodian evidence.
func ManifestBytes(b Bundle) ([]byte, error) {
	if b.Version == 2 {
		if b.OfflineRequest == nil {
			return nil, errors.New("breakglass: v2 bundle is missing its signed request")
		}
		return json.Marshal(struct {
			Domain     string            `json:"domain"`
			Request    OfflineRequest    `json:"request"`
			Approvals  []OfflineApproval `json:"approvals"`
			CertSHA256 string            `json:"cert_sha256"`
			IssuedAt   int64             `json:"issued_at_unix_nano"`
		}{"trstctl.breakglass.offline.bundle.v2", *b.OfflineRequest, b.OfflineApprovals,
			crypto.SHA256Hex(b.CertDER), b.IssuedAt.UTC().UnixNano()})
	}
	if b.Version != 0 && b.Version != 1 {
		return nil, fmt.Errorf("breakglass: unsupported bundle version %d", b.Version)
	}
	ap := append([]string(nil), b.Approvals...)
	sort.Strings(ap)
	return json.Marshal(legacyManifest{RequestID: b.RequestID, Subject: b.Subject,
		CertSHA256: crypto.SHA256Hex(b.CertDER), Reason: b.Reason, Approvals: ap, IssuedAt: b.IssuedAt.Unix()})
}

func Verify(b Bundle, caCertDER, pubDER []byte) error {
	message, err := ManifestBytes(b)
	if err != nil {
		return err
	}
	if err := crypto.VerifyMessage(pubDER, message, b.Signature); err != nil {
		return fmt.Errorf("breakglass: bundle manifest signature invalid: %w", err)
	}
	if err := crypto.VerifyLeafSignedByCA(b.CertDER, caCertDER); err != nil {
		return fmt.Errorf("breakglass: bundle certificate does not chain to the CA: %w", err)
	}
	return nil
}

// IssueDisconnected is called only inside the isolated signer after its sealed
// operation journal has committed an intent. It refuses a bare-name quorum.
func IssueDisconnected(policy OfflinePolicy, request OfflineRequest, approvals []OfflineApproval,
	caCertDER []byte, caSigner crypto.DigestSigner, now time.Time) (Bundle, error) {
	if caSigner == nil || len(caCertDER) == 0 || policy.TenantID != request.TenantID {
		return Bundle{}, errors.New("breakglass: offline signer authority is not bound to the request tenant")
	}
	if request.CAKeySHA256 != crypto.SHA256Hex(caSigner.Public().DER) {
		return Bundle{}, errors.New("breakglass: offline request was approved for another recovery CA")
	}
	if err := VerifyOfflineApprovals(policy, request, approvals, now); err != nil {
		return Bundle{}, err
	}
	names := make([]string, len(approvals))
	for i, approval := range approvals {
		names[i] = approval.CustodianID
	}
	certDER, err := crypto.SignLeafFromCSR(caCertDER, caSigner, request.CSRDER, time.Duration(request.TTLSeconds)*time.Second)
	if err != nil {
		return Bundle{}, fmt.Errorf("breakglass: sign disconnected emergency cert: %w", err)
	}
	b := Bundle{Version: 2, RequestID: request.ID, Subject: request.Subject, CertDER: certDER,
		Reason: request.Reason, Approvals: names, IssuedAt: now.UTC(), OfflineRequest: &request,
		OfflineApprovals: append([]OfflineApproval(nil), approvals...)}
	message, err := ManifestBytes(b)
	if err != nil {
		return Bundle{}, err
	}
	b.Signature, err = crypto.SignMessage(caSigner, message)
	if err != nil {
		return Bundle{}, fmt.Errorf("breakglass: sign disconnected bundle: %w", err)
	}
	return b, nil
}

func VerifyDisconnected(b Bundle, policy OfflinePolicy, caCertDER, pubDER []byte) error {
	if b.Version != 2 || b.OfflineRequest == nil {
		return errors.New("breakglass: disconnected recovery requires a v2 signed bundle")
	}
	r := *b.OfflineRequest
	if r.CAKeySHA256 != crypto.SHA256Hex(pubDER) {
		return errors.New("breakglass: offline bundle was approved for another recovery CA")
	}
	if b.RequestID != r.ID || b.Subject != r.Subject || b.Reason != r.Reason || len(b.Approvals) != len(b.OfflineApprovals) {
		return errors.New("breakglass: bundle does not describe its approved request")
	}
	for i, approval := range b.OfflineApprovals {
		if b.Approvals[i] != approval.CustodianID {
			return errors.New("breakglass: bundle custodian list differs from signatures")
		}
	}
	if err := VerifyOfflineApprovals(policy, r, b.OfflineApprovals, b.IssuedAt); err != nil {
		return err
	}
	if err := Verify(b, caCertDER, pubDER); err != nil {
		return err
	}
	return crypto.VerifyLeafBoundToCSR(b.CertDER, r.CSRDER, b.IssuedAt, time.Duration(r.TTLSeconds)*time.Second)
}
