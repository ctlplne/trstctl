// SPDX-License-Identifier: BUSL-1.1

package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// Policy is the tenant and identity scoped recovery policy read from the
// event-derived serving projection. It carries public verification material only.
type Policy struct {
	TrustRootDER []byte
	Threshold    int
	Roster       []Approver
}

var (
	ErrPolicyRootMismatch   = errors.New("recovery: request trust root does not match configured policy")
	ErrPolicyQuorumMismatch = errors.New("recovery: authorization quorum does not match configured policy")
	ErrPolicyRosterMismatch = errors.New("recovery: authorization roster does not match configured policy")
)

// ValidatePolicy rejects an unusable or ambiguous m-of-n before it can become
// authority. Distinct IDs alone are insufficient: two IDs sharing a key would
// allow one custodian to satisfy both signatures.
func ValidatePolicy(policy Policy) error {
	if err := crypto.ValidatePublicKeyDER(policy.TrustRootDER); err != nil {
		return fmt.Errorf("recovery: trust root must be a usable public key: %w", err)
	}
	if policy.Threshold < 1 || len(policy.Roster) == 0 || policy.Threshold > len(policy.Roster) {
		return fmt.Errorf("%w: threshold must fit a nonempty roster", ErrThreshold)
	}
	ids := make(map[string]struct{}, len(policy.Roster))
	keys := make(map[string]struct{}, len(policy.Roster))
	for _, member := range policy.Roster {
		if strings.TrimSpace(member.ID) == "" || strings.TrimSpace(member.ID) != member.ID {
			return errors.New("recovery: each approver needs a canonical nonempty ID")
		}
		if _, duplicate := ids[member.ID]; duplicate {
			return errors.New("recovery: approver IDs must be distinct")
		}
		ids[member.ID] = struct{}{}
		if err := crypto.ValidatePublicKeyDER(member.PubDER); err != nil {
			return fmt.Errorf("recovery: approver %q needs a usable public key: %w", member.ID, err)
		}
		if _, duplicate := keys[string(member.PubDER)]; duplicate {
			return errors.New("recovery: approver public keys must be distinct")
		}
		keys[string(member.PubDER)] = struct{}{}
	}
	return nil
}

// VerifyConfiguredPolicy binds an authorization to the exact policy at the
// time of use. Both API admission and worker delivery call this function. A
// policy changed after enqueue therefore invalidates the old outbox request.
func VerifyConfiguredPolicy(policy Policy, requestRootDER []byte, auth RecoveryAuthorization, expected Expected, deploymentScope string) error {
	if err := ValidatePolicy(policy); err != nil {
		return err
	}
	if !bytes.Equal(requestRootDER, policy.TrustRootDER) {
		return ErrPolicyRootMismatch
	}
	if auth.Threshold != policy.Threshold {
		return ErrPolicyQuorumMismatch
	}
	if len(auth.Roster) != len(policy.Roster) {
		return ErrPolicyRosterMismatch
	}
	for i, member := range policy.Roster {
		if auth.Roster[i].ID != member.ID || !bytes.Equal(auth.Roster[i].PubDER, member.PubDER) {
			return ErrPolicyRosterMismatch
		}
	}
	if auth.Statement.DeploymentScope != deploymentScope {
		return ErrStatementMismatch
	}
	return VerifyAuthorization(auth, policy.TrustRootDER, expected)
}
