// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

// EventSSHCertificateRevoked is appended by the SSH workflow when an operator
// revokes an SSH certificate by serial, key ID or both. The served KRL is
// rebuilt from these events; this projection keeps a row per revocation for
// the operations ledger (A245-L1).
const EventSSHCertificateRevoked = "ssh.cert.revoked"

// SSHCertificateRevoked is the payload of ssh.cert.revoked.
type SSHCertificateRevoked struct {
	Serial uint64 `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func init() {
	knownSchemaVersions[EventSSHCertificateRevoked] = map[int]bool{1: true}
}

func (p *Projector) applySSHCertificateRevocationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventSSHCertificateRevoked {
		return false, nil
	}
	var r SSHCertificateRevoked
	if err := json.Unmarshal(e.Data, &r); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	byKeyID := strings.TrimSpace(r.KeyID) != ""
	if r.Serial == 0 && !byKeyID {
		return true, errors.New("projections: an SSH certificate revocation names a serial or a key ID")
	}
	revokedBy := ""
	if e.Actor != nil {
		revokedBy = e.Actor.Subject
	}
	return true, p.store.ApplySSHCertificateRevokedTx(ctx, tx, e.TenantID, e.ID, r.Serial, byKeyID, r.Reason, revokedBy, e.Time, e.Sequence)
}
