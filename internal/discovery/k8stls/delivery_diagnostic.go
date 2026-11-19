// SPDX-License-Identifier: BUSL-1.1

package k8stls

const (
	ListenerVerificationFailure = "the cluster agent wrote the Secret, but the listener at verify_address did not serve the new certificate"
	IdentityOwnerMismatch       = "this resource's identity belongs to another owner; set owner_id back to that owner or retire the identity"
	OwnerIncomplete             = "owner_application_model_is_incomplete"
	OwnerChanged                = "owner_application_model_changed_after_attestation"
	SigningValidityRefused      = "signing: the host reports a certificate-profile validity refusal; review the pinned profile and its NotBefore backdate before scheduling a new issuance or replacement; changing the active profile does not rewrite this job"
	SigningResultUnavailable    = "signing: this host did not receive a signed certificate from the control plane; inspect this attempt's issuance job before retrying"
)

// OwnershipDeliveryReason gives the action for the owner gate reached before
// a Kubernetes TLS resource can be queued for delivery.
func OwnershipDeliveryReason(code, ownerID string) string {
	owner := "the configured owner"
	attest := "attest the owner"
	if ownerID != "" {
		owner = "owner " + ownerID
		attest = "attest it (trstctl-cli owners attest " + ownerID + ")"
	}
	switch code {
	case OwnerIncomplete:
		return owner + " has no application ID or environment, which attesting ownership requires: complete the owner, " + attest + ", then run the source again"
	case OwnerChanged:
		if ownerID != "" {
			attest = "attest it again (trstctl-cli owners attest " + ownerID + ")"
		} else {
			attest = "attest it again"
		}
		return owner + " changed after it attested ownership: " + attest + ", then run the source again"
	default:
		return owner + " has not attested ownership, or its attestation is older than the attestation cadence: " + attest +
			" or record an ownership exception, then run the source again"
	}
}
