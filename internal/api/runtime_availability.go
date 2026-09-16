// SPDX-License-Identifier: MPL-2.0

package api

// runtimeRouteAvailability answers a narrower question than the OpenAPI route
// registry: can this exact control-plane process run the operation right now?
//
// Routes for optional services remain in OpenAPI so an operator can discover the
// product contract. Many also remain mounted so a direct caller receives the
// handler's fail-closed problem response. The capability view uses this registry
// to stop a declared route from being mistaken for a configured service.
func (a *API) runtimeRouteAvailability(r route) (bool, string) {
	switch r.opID {
	case "createPolicyVersion", "activatePolicyVersion", "rollbackPolicyVersion":
		_, configured := a.liveLifecyclePolicy()
		return runtimeDependency(configured && a.log != nil && a.store != nil,
			"Live lifecycle policy is disabled or its durable storage is unavailable. Enable ca.policy.enabled before authoring or activating rules.")
	case "listPolicyVersions":
		return runtimeDependency(a.log != nil,
			"The policy event log is unavailable. Recorded versions alone do not prove runtime enforcement.")
	case "retryFirstIssuance":
		return runtimeDependency(a.firstIssuanceRetry != nil,
			"The first-certificate recovery service is not configured in this deployment.")
	case "executeIncident", "listIncidentExecutions", "getIncidentExecution",
		"startFleetReissuance", "listFleetReissuanceRuns", "getFleetReissuanceRun",
		"pauseFleetReissuance", "resumeFleetReissuance", "rollbackFleetReissuance", "exportFleetReissuanceEvidence",
		"listRemediationPlaybooks", "runRemediationPlaybook", "listRemediationPlaybookRuns", "getRemediationPlaybookRun",
		"listOwnerRemediationActions", "acceptOwnerRemediationAction", "dispatchResponseIntegrations":
		return runtimeDependency(a.remediation,
			"Automated response is turned off in this deployment. Configure the remediation service before running or reading response jobs.")

	case "getProtocolProfile", "activateProtocolProfile":
		return runtimeDependency(a.protocolProfile != nil,
			"The certificate protocol setup service is not configured in this deployment.")

	case "createCACeremony", "getCACeremony", "approveCACeremony",
		"listCAAuthorities", "createRootCA", "importOfflineRootCA", "importExistingCA", "createIntermediateCA",
		"createOfflineIntermediateCSR", "importOfflineIntermediateCA", "issueIntermediateCAFromCSR", "issueHierarchyLeaf",
		"rotateCAAuthority", "rekeyCAAuthority", "crossSignCAAuthority", "importOfflineRootCrossSign", "rekeyOfflineRoot":
		return runtimeDependency(a.caHierarchy != nil,
			"The native CA hierarchy service is not configured in this deployment.")
	case "listCADiscoveryInventory":
		return runtimeDependency(a.caHierarchy != nil || a.externalCAs != nil,
			"CA discovery needs either the native CA hierarchy or an external CA integration; neither is configured.")
	case "listEdgeSegmentPolicies", "putEdgeSegmentPolicy", "mintEdgeDelegation", "listEdgeDelegations",
		"getEdgeDelegation", "revokeEdgeDelegation", "reconcileEdgeDelegation":
		return runtimeDependency(a.edgeDelegations != nil,
			"Delegated edge CA service is not configured in this deployment.")
	case "listExternalCAs", "issueExternalCA":
		return runtimeDependency(a.externalCAs != nil,
			"No external CA service is configured in this deployment.")
	case "previewAttestedSVID", "issueAttestedSVID":
		return runtimeDependency(a.attestedIssuer != nil,
			"Attested workload issuance is not configured in this deployment.")
	case "getSSHStatus", "recordSSHTrustRollout", "previewSSHCertificate", "issueSSHCertificate", "previewAttestedSSHUserCert", "issueAttestedSSHUserCert", "revokeSSHCertificate", "retireSSHHost":
		return runtimeDependency(a.sshWorkflow != nil,
			"The SSH certificate workflow is not configured in this deployment.")
	case "issueBrokerAgentIdentity", "previewBrokerAgentIdentity":
		configured := a.broker != nil
		// The assembled server is attached before optional issuance services
		// are built. Its non-nil wrapper alone is not runtime availability.
		if source, ok := a.broker.(interface{ BrokerIdentityAvailable() bool }); ok {
			configured = source.BrokerIdentityAvailable()
		}
		return runtimeDependency(configured,
			"The short-lived agent identity broker is not configured in this deployment.")
	case "previewEphemeralCredential", "issueEphemeralCredential", "approveEphemeralCredential":
		return runtimeDependency(a.ephemeral != nil,
			"Attestation-gated temporary credential issuance is not configured in this deployment.")
	case "openPAMSession", "listPAMSessions", "getPAMSession":
		return runtimeDependency(a.pam != nil,
			"The just-in-time privileged access broker is not configured in this deployment.")
	case "listApprovalRequests":
		_, listReady := a.approvals.(ApprovalRequestLister)
		return runtimeDependency(a.approvals != nil && listReady,
			"The dual-control approval queue is not configured in this deployment.")
	case "approveApprovalRequest", "denyApprovalRequest":
		return runtimeDependency(a.approvals != nil,
			"The dual-control approval service is not configured in this deployment.")

	case "generateManagedKey", "approveManagedKeyAction", "rotateManagedKey", "revokeManagedKey", "zeroizeManagedKey":
		return runtimeDependency(a.managedKeys != nil,
			"Managed HSM or cloud KMS key lifecycle is not configured in this deployment.")
	case "listTransitKeys", "listTransitKeyVersions", "createTransitKey", "rotateTransitKey", "encryptTransit", "decryptTransit", "rewrapTransit",
		"hmacTransit", "signTransit", "verifyTransit":
		return runtimeDependency(a.transit != nil,
			"The Transit cryptography service is not configured in this deployment.")
	case "previewCodeArtifact", "previewCodeArtifactKeyless":
		return runtimeDependency(a.codeSigning != nil && a.commandMAC != nil,
			"Code-signing preview needs the signing runtime and server-keyed review evidence; one or both are not configured.")
	case "signCodeArtifact", "signCodeArtifactKeyless":
		return runtimeDependency(a.codeSigning != nil,
			"The code-signing service is not configured in this deployment.")
	case "submitCertificateTransparency":
		return runtimeDependency(a.ctSubmission != nil,
			"Certificate Transparency submission is not configured in this deployment.")

	case "previewSecretCreate", "previewSecretAccess", "createSecret", "listSecrets", "getSecret", "getSecretVersion", "recoverSecretAt", "rotateSecret", "deleteSecret",
		"rotateStaticSecret", "createSecretRotationSchedule", "listSecretRotationSchedules", "runDueSecretRotationSchedules",
		"previewSecretSync", "syncSecret", "receiveSecretRepositoryWebhook", "ingestThirdPartySecretScan", "scanSecrets", "approveSecretChange",
		"listDynamicSecretProviders", "previewDynamicSecretLease", "issueDynamicSecretLease", "getDynamicSecretLease", "renewDynamicSecretLease", "revokeDynamicSecretLease",
		"previewShare", "createShare", "redeemShare", "issuePKISecret", "previewMachineLogin", "machineLogin", "listMachineAuthMethods", "listMachineSessions",
		"revokeMachineSession", "disableMachineAuthMethod", "enableMachineAuthMethod":
		return runtimeDependency(a.secrets != nil,
			"The native secret store is turned off in this deployment. Enable it before storing, revealing, rotating, sharing, or leasing application secrets.")

	case "aiQuery", "aiRCA", "listMCPTools", "callMCPTool":
		return runtimeDependency(a.ai != nil,
			"The optional AI query service is turned off. Runtime status remains available without enabling model access.")
	case "previewCBOMScan", "startCBOMScan", "listCBOMAssets":
		return runtimeDependency(a.cbom != nil,
			"The cryptographic inventory scanner is not configured in this deployment.")
	case "getComplianceEvidencePack":
		return runtimeDependency(a.complianceEvidence != nil,
			"Signed compliance evidence export is not configured in this deployment.")
	default:
		return true, ""
	}
}

func runtimeDependency(ready bool, unavailableDetail string) (bool, string) {
	if ready {
		return true, ""
	}
	return false, unavailableDetail
}
