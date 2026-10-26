// SPDX-License-Identifier: BUSL-1.1

package server

import "strings"

// The operator-facing copy of an effect-free CA ceremony preview: what each
// operation will change, its risks, and how to verify it afterwards. Split out
// of ca_hierarchy.go for the served-surface file budget.

func ceremonyPreviewChanges(operation string) []string {
	switch operation {
	case "create_root":
		return []string{"Prepare an m-of-n ceremony for a new signer-backed root CA. No key or authority is created by this preview."}
	case "import_offline_root":
		return []string{"Prepare an m-of-n ceremony to trust the supplied public offline-root certificate. The offline private key stays outside trstctl."}
	case "import_existing_ca":
		return []string{"Prepare an m-of-n ceremony to bind the supplied public CA chain to an existing signer-held key handle."}
	case "import_ca_key":
		return []string{"Prepare an m-of-n ceremony to take the CA's existing private key into signer custody for the supplied public chain and profile. After quorum the signer offers a one-time import key; you seal the private key to it on your own machine, and only the sealed key reaches trstctl. No key is created or contacted by this preview."}
	case "prepare_existing_ca":
		return []string{"Prepare an m-of-n ceremony to create a tenant-bound signer-held CA key and public CSR for the reviewed external issuer chain. No key is created by this preview."}
	case "create_intermediate":
		return []string{"Prepare an m-of-n ceremony for a new signer-backed intermediate under the reviewed parent authority."}
	case "create_offline_intermediate":
		return []string{"Prepare an m-of-n ceremony for a signer-held intermediate CSR that an offline parent will sign."}
	case "issue_intermediate_csr":
		return []string{"Prepare an m-of-n ceremony to sign the reviewed external intermediate CSR with the reviewed parent authority."}
	case "rekey_ca":
		return []string{"Prepare an m-of-n ceremony to replace the reviewed authority key while retaining an auditable predecessor-to-successor lineage."}
	case "cross_sign_ca":
		return []string{"Prepare an m-of-n ceremony to cross-sign the reviewed public CA certificate with the reviewed signer-backed authority."}
	case "import_offline_cross_sign":
		return []string{"Prepare an m-of-n ceremony to verify and import the supplied public cross-certificate from the reviewed offline root."}
	case "rekey_offline_root":
		return []string{"Prepare an m-of-n ceremony to activate the supplied offline-root successor and its bidirectional public cross-signatures."}
	case "release_managed_ca_leaf":
		return []string{"Prepare a two-custodian disposition of the exact expired managed CA leaf, its original mint event and the operator's explicit external-use risk decision. The preview writes nothing."}
	case "revoke_ca":
		return []string{"Prepare an m-of-n ceremony to revoke the reviewed authority's key for the reviewed reason. Executing it makes the isolated signer refuse every signature with that key, stops the authority issuing, and revokes its certificate on a managed parent's CRL. The preview writes nothing and contacts no signer."}
	default:
		return []string{"Prepare the reviewed CA hierarchy ceremony without creating a ceremony, key, certificate, or external request during preview."}
	}
}

func ceremonyPreviewRisks(operation string) []string {
	if operation == "revoke_ca" {
		return []string{
			"Revocation is permanent: the key signs no certificate, CRL or OCSP response again, and its last published CRL stays until its next-update time.",
			"Certificates this authority issued stop validating only where relying parties check its parent's CRL; a root has no issuer, so it must be removed from trust stores.",
			"The server will require distinct custodian approvals and revalidate the exact authority, certificate, signer handle and reason before execution.",
		}
	}
	if operation == "release_managed_ca_leaf" {
		return []string{
			"The requester held this leaf's private key. Expiry and a local inventory record cannot prove it was never used outside this deployment.",
			"Releasing this exact dependency after two distinct custodian approvals permits a later retirement request; it does not revoke the certificate or destroy the CA key.",
		}
	}
	risks := []string{
		"A completed ceremony can authorize a later change to certificate trust or signing authority.",
		"The server will require distinct custodian approvals and revalidate the exact ceremony purpose before execution.",
	}
	if strings.Contains(operation, "offline") {
		risks = append(risks, "Only public certificate material is accepted; private-key material is rejected at the server boundary.")
	}
	if operation == "import_ca_key" {
		risks = append(risks, "The private key existed outside trstctl before this import and may still exist there; trstctl cannot prove other copies were destroyed.")
	}
	return risks
}

func ceremonyPreviewVerification(operation string) []string {
	if operation == "revoke_ca" {
		return []string{
			"Confirm the authority, its status and the reason match the intended revocation before opening the ceremony.",
			"After execution, verify the authority reads revoked, the signer reports its key revoked, and a managed parent's CRL lists its serial.",
			"Reissue what the authority issued from another active authority.",
		}
	}
	if operation == "release_managed_ca_leaf" {
		return []string{
			"Match the exact certificate ID, public DER digest, original mint event, CA key and explicit external-use risk decision before opening the ceremony.",
			"Verify two distinct custodian approval events authorize this exact disposition before executing the release.",
			"After release, read the retirement checklist for this CA key and verify the exact certificate is accounted for; retain the immutable release receipt and audit event.",
		}
	}
	steps := []string{
		"Confirm the operation, authority identity, CA profile, and required approval threshold match the intended change.",
		"After the ceremony starts, verify each distinct approval and the immutable ceremony event before executing the CA change.",
		"After execution, verify authority status, chain, expiry, signer custody, and the matching immutable audit event.",
	}
	if operation == "rekey_ca" || operation == "rekey_offline_root" || operation == "cross_sign_ca" || operation == "import_offline_cross_sign" {
		steps = append(steps, "Verify both predecessor and successor trust paths before retiring any old trust material.")
	}
	return steps
}
