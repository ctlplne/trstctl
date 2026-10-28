// SPDX-License-Identifier: BUSL-1.1

package cmdbexport

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	Destination    = "cmdb.certificate_export"
	EventRequested = "cmdb.certificate_export.requested"
	EventVerified  = "cmdb.certificate_export.verified"
)

// Command names public certificate identity and an operator-owned binding.
// Credentials and caller-selected destinations never enter this contract.
type Command struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	Fingerprint   string `json:"fingerprint"`
	BindingID     string `json:"binding_id"`
	BindingDigest string `json:"binding_digest"`
	RequestedBy   string `json:"requested_by,omitempty"`
}

// Receipt binds a successful independent read to the exact export command.
// ValuesDigest covers the complete metadata sent and independently read back.
type Receipt struct {
	OperationID       string    `json:"operation_id"`
	BindingID         string    `json:"binding_id"`
	BindingDigest     string    `json:"binding_digest"`
	CertificateID     string    `json:"certificate_id"`
	Fingerprint       string    `json:"fingerprint"`
	CertificateStatus string    `json:"certificate_status"`
	SystemID          string    `json:"sys_id"`
	ValuesDigest      string    `json:"values_digest"`
	CheckedAt         time.Time `json:"checked_at"`
}

// Validate checks the immutable command before append, replay or delivery.
func (c Command) Validate() error {
	for _, id := range []string{c.ID, c.CertificateID} {
		value, err := uuid.Parse(id)
		if err != nil || value == uuid.Nil || value.String() != id {
			return fmt.Errorf("CMDB export needs canonical command and certificate IDs")
		}
	}
	if !fingerprint(c.Fingerprint) || !strings.HasPrefix(c.BindingDigest, "sha256:") || len(c.BindingDigest) != 71 || !fingerprint(strings.TrimPrefix(c.BindingDigest, "sha256:")) || c.BindingID == "" {
		return fmt.Errorf("CMDB export binding or fingerprint is incomplete")
	}
	return nil
}
