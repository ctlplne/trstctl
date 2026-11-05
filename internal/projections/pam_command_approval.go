// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/accessrules"
)

// This domain event deliberately closes evidence to public command facts. The
// generic approval event permits free-form evidence, whose privacy rules differ.
const EventPAMCommandApprovalRequested = "pam.command.approval_requested"

func ValidatePAMCommandApprovalRequested(p ApprovalRequested) error {
	invalid := errors.New("projections: invalid public command approval facts")
	canonicalUUID := func(value string) bool {
		id, err := uuid.Parse(value)
		return err == nil && id != uuid.Nil && id.String() == value
	}
	action, ok := strings.CutPrefix(p.ResourceID, "pam-command:")
	if !ok || !canonicalUUID(action) || p.ResourceKind != "pam_command" || p.Action != "execute" || p.FromState != "held" || p.ToState != "authorized" || p.TargetVersion != 0 || p.RequiredApprovals < 1 || p.RequiredApprovals > 3 || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.Sub(p.CreatedAt) > 45*time.Second || len(p.EvidenceRefs) != 6 {
		return invalid
	}
	refs := map[string]string{}
	for _, ref := range p.EvidenceRefs {
		key, value, ok := strings.Cut(ref, ":")
		if !ok || value == "" || refs[key] != "" {
			return invalid
		}
		refs[key] = value
	}
	if !canonicalUUID(refs["pam-session"]) || refs["pam-action"] != action || !accessrules.ValidDigest(refs["pam-policy-sha256"]) || !accessrules.ValidDigest(refs["pam-message-sha256"]) {
		return invalid
	}
	ids := strings.Split(refs["pam-rule-ids"], ",")
	if len(ids) < 1 || len(ids) > accessrules.MaxRules || !slices.IsSorted(ids) {
		return invalid
	}
	for i, id := range ids {
		if !canonicalUUID(id) || i > 0 && id == ids[i-1] {
			return invalid
		}
	}
	ops := strings.Split(refs["pam-operations"], ",")
	if len(ops) < 1 || len(ops) > accessrules.MaxOperations || !slices.IsSorted(ops) {
		return invalid
	}
	known := accessrules.PostgresOperationNames()
	for i, op := range ops {
		if !slices.Contains(known, op) || i > 0 && op == ops[i-1] {
			return invalid
		}
	}
	return nil
}
