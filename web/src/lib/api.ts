// Typed client over the trstctl REST surface (S3.3 / S7.1 / S7.3). All requests
// carry the session cookie; a 401 surfaces as UnauthorizedError so the auth layer
// can redirect to login. Mutations send an Idempotency-Key (AN-5).
//
// FE↔BE contract (SURFACE-005 / EXC-WIRE-04): the resource shapes below are NOT
// hand-written — they are re-exported from ./api-types.gen.ts, which is generated
// from the SERVED OpenAPI contract (internal/api/testdata/openapi.golden.json, pinned
// == the live spec by the Go test TestOpenAPIGolden). So if the backend adds, renames,
// or removes a field, the generated types change and any code in the SPA that reads a
// now-missing field fails `tsc` — the drift cannot ship silently. Regenerate with
// `npm run gen:api`; `npm run build` runs `gen:api --check` first and fails on drift.
import { translateNow } from "@/i18n/I18nProvider";
import * as estate from "./estateApi";
import { downloadAuditExport as downloadAuditExportImpl } from "./auditExport";
import type {
  CapabilityView,
  CryptoReadiness,
  CryptoReadinessExport,
  CMDBReconcileSchedule,
  IssuanceRequest,
  IssuanceRequestInput,
  IssuanceRequestList,
  IssuanceRequestPreparation,
  IssuanceRequestPreview,
  MDMDeviceList,
  MDMDeviceTrace,
  MDMPollScheduleList,
  TicketIntakeSchedule,
  AgentUpgradeCampaign,
  OwnershipConflictList,
  DRPosture,
  SecretRotationScheduleRun,
  MDMSCEPPolicyRequest,
  MDMSCEPPolicy,
  AccessChangeDecisionRequest,
  AccessChangeRequest,
  AccessChangeRequestCreateRequest,
  AccessChangeRequestList,
  ACMEARIPosture,
  ACMEEABCredential,
  ACMEEABPosture,
  ACMEOperatorPlan,
  AgentJobPosture,
  BulkheadStats,
  IssuerCapabilityMatrix,
  ACMEDNS01Preflight,
  ACMEDNS01PreflightRequest,
  ACMEDNS01ProviderCatalog,
  ACMEDNS01ProviderCatalogItem,
  ACMEDNS01ProviderConfig,
  ACMEDNS01ProviderConfigList,
  ACMEUpstreamAuthorizationList,
  EndpointVerification,
  EndpointVerificationList,
  EndpointKeyCustodyList,
  EnrollmentDiagnostic,
  EnrollmentDiagnosticList,
  EnrollmentDiagnosticVerification,
  ACMEDNS01ProviderConfigRequest,
  ActiveActiveIssuancePlan,
  ADCSInventorySource as GenADCSInventorySource,
  ADCSEnrollmentService as GenADCSEnrollmentService,
  ADCSPosture as GenADCSPosture,
  ADCSDriftHistory as GenADCSDriftHistory,
  ADCSDatabaseList as GenADCSDatabaseList,
  ADCSTemplate as GenADCSTemplate,
  Agent as GenAgent,
  AgentList as GenAgentList,
  AgentCertRevocation,
  AgentCertRevocationRequest,
  AgentOffboardRequest,
  AgentOffboardResponse,
  AIAnswer as GenAIAnswer,
  AIQueryRequest,
  AIStatus as GenAIStatus,
  APIToken,
  APITokenCreateRequest,
  APITokenCreateResponse,
  APITokenList,
  Approval as GenApproval,
  ApprovalDecision as GenApprovalDecision,
  ApprovalRequestList as GenApprovalRequestList,
  ApprovalRequest,
  Attestation as GenAttestation,
  AttestedSVID as GenAttestedSVID,
  AttestedSVIDRequest,
  AuditBundle,
  AuditFeed,
  AuditFeedList,
  AuditFeedPreview,
  AuditFeedRequest,
  AuditEvent as GenAuditEvent,
  BreakglassBundle,
  BreakglassIssueRequest,
  BreakglassIssueResponse,
  BreakglassReconcileRequest,
  BreakglassReconcileResponse,
  BrokerAgentIdentity as GenBrokerAgentIdentity,
  BrokerAgentIdentityRequest,
  BulkRevokeRequest,
  BulkRevokeResult,
  CAAuthority,
  CAAuthorityList,
  CAAuthorityRekeyRequest,
  CAAuthorityRotation,
  CAAuthorityRotationPlanPreview,
  CAAuthorityRotationRequest,
  CACeremonyPlanPreview,
  CACeremonyStartRequest,
  CACreateIntermediateRequest,
  CACreateOfflineIntermediateCSRRequest,
  CACreateRootRequest,
  CADiscoveryInventory,
  CAImportExistingRequest,
  CAImportOfflineIntermediateRequest,
  CAImportOfflineRootRequest,
  CAIntermediateCSR,
  CAIssuedIntermediate,
  CAIssuedLeaf,
  CAIssueIntermediateRequest,
  CAIssueLeafRequest,
  CAKeyCeremony,
  CBOMAsset as GenCBOMAsset,
  CBOMInventory,
  CBOMMigrationProgress,
  CBOMScan,
  CBOMScanPreview,
  CBOMScanRequest,
  Certificate as GenCertificate,
  CertificateHealthDashboard as GenCertificateHealthDashboard,
  CertificateIngest,
  CertificateList,
  CloudSecretManagerIntegration,
  CodeSigningIdentity,
  CodeSigningIdentityList,
  CodeSigningKeylessRequest,
  CodeSigningRequest,
  CodeSigningSignature,
  ComplianceEvidencePack,
  ComplianceInventoryReport,
  ComplianceReportSchedule,
  ComplianceReportScheduleList,
  ComplianceReportScheduleRequest,
  ConnectorCatalog,
  ConnectorCatalogItem,
  ConnectorDelivery,
  ConnectorDeliveryList,
  ConnectorTargetActionRequest,
  RelayPluginRuntime,
  ContextualRiskPriorities as GenContextualRiskPriorities,
  UrgentRiskSummary as GenUrgentRiskSummary,
  ContextualRiskPriority as GenContextualRiskPriority,
  CredentialRisk as GenCredentialRisk,
  CredentialRiskList,
  CRLDistribution,
  CRLDistributionList,
  RevocationCachePosture,
  RevocationHealth,
  CTLogSubmission,
  CTLogSubmissionRequest,
  CTMonitoring,
  CTMonitoringRequest,
  DeploymentTarget,
  DeploymentTargetList,
  DeploymentTargetRequest,
  DiscoveryCapability,
  DiscoveryCapabilityCatalog,
  DiscoveryCapabilityField,
  DiscoveryCapabilityProvider,
  DiscoveryCoverage,
  DiscoveryFinding,
  DiscoveryFindingList,
  DiscoveryFindingTriageRequest,
  DiscoveryMonitoring,
  DiscoveryPlanPreview,
  DiscoveryRun,
  DiscoveryRunList,
  DiscoveryRunRequest,
  DiscoverySchedule,
  DiscoveryScheduleList,
  DiscoveryScheduleRequest,
  DiscoverySegment,
  DiscoverySegmentCoverage,
  DiscoverySegmentRequest,
  DiscoverySource,
  DiscoverySourceList,
  DiscoverySourceRequest,
  DriftRemediation,
  DriftRemediationDecision,
  DriftRemediationDecisionRequest,
  DriftRemediationFinding,
  DynamicLease,
  DynamicLeaseRenewRequest,
  DynamicLeaseRequest,
  EndpointBinding,
  EndpointBindingRequest,
  EnrollmentPlanPreview as GenEnrollmentPlanPreview,
  EnrollmentToken as GenEnrollmentToken,
  EnrollmentTokenRequest as GenEnrollmentTokenRequest,
  EnterpriseSupportStatus,
  EphemeralAPIKey,
  EphemeralAPIKeyRequest,
  EphemeralApproval,
  EphemeralApprovalRequest,
  EphemeralCredential,
  EphemeralCredentialPreview,
  EphemeralCredentialRequest,
  ExternalCA as GenExternalCA,
  ExternalCAIssuedCertificate,
  ExternalCAIssueRequest,
  ExternalCAList,
  FleetReissuanceActionRequest,
  FleetReissuanceEvidence,
  FleetReissuanceRequest,
  FleetReissuanceRun,
  FleetReissuanceRunList,
  GraphImpact,
  GraphTrustStores,
  MigrationAssessment,
  MigrationRun,
  MigrationRunActionRequest,
  MigrationRunList,
  MigrationRunStartRequest,
  UnownedQueue,
  RetirementChecklist,
  GraphNode,
  GraphQueryResult,
  GraphReachable,
  GraphResponse,
  Identity as GenIdentity,
  IdentityTransitionPreview as GenIdentityTransitionPreview,
  IdentityConnectorTargetRequest,
  IdentityRequest,
  IncidentExecution,
  IncidentExecutionList,
  IncidentExecutionRequest,
  Issuer as GenIssuer,
  IssuerRequest,
  ITSMTicket,
  KubernetesCSRSupport,
  KubernetesSecretOperator,
  KubernetesTrustBundleDistribution,
  MachineAuthMethod,
  MachineAuthMethodList,
  MachineAuthMethodOverride,
  MachineLoginRequest,
  MachineLoginResponse,
  MachineSession,
  MachineSessionList,
  ManagedKey,
  ManagedKeyCustodyPlan,
  ManagedKeyGenerateRequest,
  ManagedKeyGenerationPreview,
  ManagedKeyGenerationPreviewRequest,
  ManagedOfferingStatus,
  ManagedTenant,
  ManagedTenantProvisionRequest,
  MCPToolCall,
  MCPToolList,
  MCPToolResult,
  MDMSCEPChallengeRotationPreview,
  MDMSCEPChallengeRotated,
  MDMSCEPPolicyPreview,
  MDMSCEPPolicyList,
  MDMSCEPStatus,
  Member,
  MemberList,
  MemberRequest,
  NHIComplianceReport,
  NHIDecommissionRequest,
  NHIDecommissionResponse,
  NHIExposurePosture,
  NHIInventory,
  NHIInventoryItem,
  NHIOverPrivilegePosture,
  NHIPolicyCompliance,
  NHIReviewCampaign,
  NHIReviewCampaignList,
  NHIReviewCampaignStartRequest,
  NHIReviewDecisionRequest,
  NHIReviewItem,
  NHIShadowPosture,
  NHIStalePosture,
  NHIStaticPosture,
  Notification,
  NotificationChannel,
  NotificationChannelList,
  NotificationChannelRequest,
  NotificationChannelTest,
  NotificationChannelTestRequest,
  NotificationList,
  NotificationRoutingPolicy,
  NotificationRoutingPolicyList,
  NotificationRoutingPolicyRequest,
  NotificationRoutingPreview,
  OffboardMemberRequest,
  OffboardMemberResponse,
  OIDCMappingStatus,
  OutboxCircuit,
  OutboxCircuitList,
  Owner as GenOwner,
  OwnerRemediationAcceptRequest,
  OwnerRemediationQueue,
  OwnerRemediationRun,
  OwnershipAssignmentRequest,
  OwnershipAssignmentResult,
  OutboxReconciliationConflictList,
  OwnerRequest,
  OwnershipAttribution,
  OwnershipAttributionItem,
  OwnershipException,
  OwnershipExceptionList,
  OwnershipExceptionRequest,
  OwnershipExceptionRevokeRequest,
  PAMSession,
  PAMSessionList,
  PAMSessionRequest,
  PKISecret,
  PKISecretRequest,
  PlatformDistributionStatus,
  PolicyDryRun,
  PolicyDryRunRequest,
  PolicyVersion,
  PolicyVersionActionRequest,
  PolicyVersionList,
  PolicyVersionRequest,
  PrivacyArchiveErasureAttestation,
  PrivacyArchiveErasureAttestationList,
  PrivacyArchiveErasureAttestationRequest,
  PrivacyCatalog,
  PrivacyRetentionRun,
  PrivacyRetentionRunList,
  PrivacySubjectErasure,
  PrivacySubjectErasureList,
  PrivacySubjectErasureRequest,
  PrivacySubjectExport,
  PrivacySubjectExportRequest,
  PQCMigrationCampaign,
  PQCMigrationCampaignCloseRequest,
  PQCMigrationCampaignClosure,
  PQCMigrationCampaignFinding,
  PQCMigrationCampaignList,
  PQCMigrationCampaignReadinessRequest,
  PQCMigrationCampaignStartRequest,
  PQCMigrationCampaignUpdateRequest,
  PQCMigrationFindingDispositionRequest,
  PendingApprovalRequest as GenPendingApprovalRequest,
  Profile as GenProfile,
  ProfileApprovalResponse,
  ProfileRequest,
  ProfileRestorePreview,
  ProfileRestoreRequest,
  ProtocolProfileStatus,
  RCARequest,
  RemediationPlaybook,
  RemediationPlaybookCatalog,
  RemediationPlaybookRun,
  RemediationPlaybookRunList,
  RemediationPlaybookRunRequest,
  ResponseIntegrationDispatch,
  ResponseIntegrationDispatchRequest,
  RogueCertificatePosture,
  RoleList,
  RotationRun,
  RotationRunList,
  ScaleOrchestrationPlan,
  SecretApproval as GenSecretApproval,
  SecretApprovalRequest as GenSecretApprovalRequest,
  SecretMeta,
  SecretMetaList,
  SecretRecoverRequest,
  SecretRepositoryScanPosture,
  SecretRepositoryWebhookReceipt,
  SecretRepositoryWebhookRequest,
  SecretCreateRequest,
  SecretRotateRequest,
  SecretRotation,
  SecretRotationDueRun,
  SecretRotationRequest,
  SecretRotationSchedule,
  SecretRotationScheduleList,
  SecretRotationScheduleRequest,
  SecretScan,
  SecretScanRequest,
  SecretSync,
  SecretSyncRequest,
  SecretSyncTargetCatalog,
  SecretSyncWorkloadIdentitySource,
  SecretSyncWorkloadIdentitySourceList,
  SecretSyncWorkloadIdentitySourceRequest,
  SecretValue,
  SecretWorkloadInjection,
  ServiceNowTicketRequest,
  ShareRedeemRequest,
  ShareRequest,
  ShareToken,
  ShareValue,
  SystemReadout,
  TenantKeyDomainMigrateRequest,
  TenantKeyDomainSealReceipt,
  TenantKeyDomainStatus,
  SSHAttestedUserCert,
  SSHAttestedUserCertRequest,
  SSHFleetInventory,
  SSHHostRetirement,
  SSHHostRetireRequest,
  SSHRevokeCertificateRequest,
  SSHStatus,
  SSHTrustRollout,
  SSHTrustRolloutRequest,
  ThirdPartySecretScanIngestRequest,
  ThirdPartySecretScanPosture,
  ThirdPartySecretScanReceipt,
  TransitCiphertext,
  TransitDecryptRequest,
  TransitEncryptRequest,
  TransitHMAC,
  TransitHMACRequest,
  TransitionRequest,
  TransitKey,
  TransitKeyList,
  TransitKeyRequest,
  TransitPlaintext,
  TransitRewrapRequest,
  TransitRotateRequest,
  TransitSignature,
  TransitSignRequest,
  TransitVerify,
  TransitVerifyRequest,
  UnvaultedSecretPosture,
  WorkloadAttesterTrustSource,
  WorkloadAttesterTrustSourceList,
  WorkloadAttesterTrustSourceRequest,
  WorkloadAttesterTrustSourceRevoked,
  WorkloadAttesterTrustSourceRevokeRequest,
  WorkloadAttesterTrustSourceRotated,
  WorkloadAttesterTrustSourceRotateRequest,
  EdgeSegmentPolicyList,
  EdgeDelegationList,
  EdgeDelegationDetail,
} from "./api-types.gen";

// Re-export the generated, contract-bound resource types under the names the SPA uses.
export type Certificate = GenCertificate;
export type CertificateHealthDashboard = GenCertificateHealthDashboard;
export type CertificatePage = CertificateList;
export type CertificateIngestRequest = CertificateIngest;
export type CTSubmission = CTLogSubmission;
export type CTSubmissionRequest = CTLogSubmissionRequest;
// C4: XREC's authority-agreement surface.
//
// Hand-declared rather than generated. The route is licensed (Enterprise
// `reconcile`) and its schemas are contributed at attach time by ee/, so they
// are not in the core OpenAPI golden the generator reads. Keep this in step
// with ee/reconcile/api/openapi.go by hand.
export interface AuthorityWitnessClassCount {
  class: string;
  count: number;
}
export interface AuthorityAgreement {
  authority_id: string;
  witnesses: AuthorityWitnessClassCount[];
  total: number;
  last_witness_at?: string;
}
export interface AuthorityAgreementReport {
  authorities: AuthorityAgreement[];
  open_witnesses: number;
  /** How far the projection has consumed the log. Every count above is only as current as this. */
  replay_watermark: number;
  median_resolution_seconds: number;
  resolved_in_window: number;
  /** False means the zeros are the absence of collection, not the absence of disagreement. */
  configured: boolean;
  /** False means NO reconciliation schedule exists — nothing is looking for divergence at all. */
  collecting: boolean;
  detail: string;
  guidance: string;
}

/** L2 invoice evidence. Licensed route, so hand-declared like the block above. */
export interface UsageEvidenceLine {
  meter: string;
  kind: string;
  value: number;
  unit?: string;
}
export interface UsageEvidenceReconciliation {
  meter?: string;
  metered?: number;
  event_history?: number;
  /** An independent source existed and was consulted; false means "nothing to check against", not "checked and failed". */
  checked?: boolean;
  matches?: boolean;
  source?: string;
  note?: string;
}
export interface UsageEvidenceSignature {
  alg?: string;
  key_id?: string;
  jws?: string;
}
export interface UsageEvidence {
  customer_id: string;
  period_start: string;
  period_end: string;
  lines?: UsageEvidenceLine[];
  /** Read this BEFORE the numbers: false means the totals are a partial view, not an invoice. */
  signable: boolean;
  /** Why it may or may not be signed, in words a finance team can act on. */
  reason: string;
  observed_from?: string;
  observed_to?: string;
  /** Per-meter cross-check against the event history; part of what the signature attests. */
  reconciliation?: UsageEvidenceReconciliation[];
  digest: string;
  /** Detached JWS over the canonical bytes. Present ONLY when signable; its absence is itself information. */
  signature?: UsageEvidenceSignature;
  guidance?: string;
}

export type { CTMonitoring, CTMonitoringRequest };
export type { DRPosture, DRDrill } from "./api-types.gen";
export type { CryptoReadiness, CryptoReadinessAction, CryptoReadinessExport, CryptoReadinessRow, CryptoDependent } from "./api-types.gen";
export type { OwnershipConflictList, OwnershipConflict, OwnershipImportResult } from "./api-types.gen";
export type { CMDBReconcileSchedule } from "./api-types.gen";
export type { IssuanceRequestList, IssuanceRequest, IssuanceRequestInput, IssuanceRequestPreparation, IssuanceRequestPreview } from "./api-types.gen";
export type { TicketIntakeSchedule } from "./api-types.gen";
export type { MDMDeviceList, MDMDevice, MDMDeviceTrace, MDMPollScheduleList } from "./api-types.gen";
export type { AgentUpgradeCampaign } from "./api-types.gen";
export type { OutboxReconciliationConflict, OutboxReconciliationConflictList } from "./api-types.gen";
export type {
  CapabilityView,
  CapabilityViewItem,
  CapabilityViewStage,
  CapabilityViewActions,
  CapabilityUnavailableAction,
  CapabilityLicensePosture,
} from "./api-types.gen";
export type Owner = GenOwner;
export type { OwnershipException, OwnershipExceptionRequest, OwnershipExceptionRevokeRequest } from "./api-types.gen";
export type Issuer = GenIssuer;
export type ExternalCA = GenExternalCA;
export type CADiscovery = CADiscoveryInventory;
export type Identity = GenIdentity;
export type IdentityTransitionPreview = GenIdentityTransitionPreview;
export type ADCSPosture = GenADCSPosture;
export type ADCSDriftHistory = GenADCSDriftHistory;
export type ADCSInventorySource = GenADCSInventorySource;
export type ADCSEnrollmentService = GenADCSEnrollmentService;
export type ADCSDatabaseList = GenADCSDatabaseList;
export type ADCSTemplate = GenADCSTemplate;
export type Agent = GenAgent;
export type AgentList = GenAgentList;
export type EnrollmentPlanPreview = GenEnrollmentPlanPreview;
export type EnrollmentToken = GenEnrollmentToken;
export type EnrollmentTokenRequest = GenEnrollmentTokenRequest;
export type Attestation = GenAttestation;
export type AttestedSVID = GenAttestedSVID;
export type BrokerAgentIdentity = GenBrokerAgentIdentity;
export type CBOMAsset = GenCBOMAsset;
export type {
  PQCMigrationCampaign,
  PQCMigrationCampaignCloseRequest,
  PQCMigrationCampaignClosure,
  PQCMigrationCampaignFinding,
  PQCMigrationCampaignList,
  PQCMigrationCampaignReadinessRequest,
  PQCMigrationCampaignStartRequest,
  PQCMigrationCampaignUpdateRequest,
  PQCMigrationFindingDispositionRequest,
};
// These four shapes come from ee/pqcmigration's runtime OpenAPI schemas. They
// intentionally remain beside the browser client rather than in the core SDK
// golden: a core-only binary does not mount or advertise licensed routes.
export interface PQCMigrationRequest {
  asset_ids: string[];
  target_algorithm: "ML-DSA-65";
  protocol: "acme";
  rollback_on_failure: boolean;
}

export interface PQCMigrationPlanReissue {
  asset_id: string;
  location: string;
  current_algorithm: string;
  target_algorithm: string;
  effective_algorithm: string;
  protocol: string;
  rollback_on_failure: boolean;
}

export interface PQCMigrationPlanResidual {
  id: string;
  status: string;
  reason: string;
}

export interface PQCMigrationPlan {
  reissues: PQCMigrationPlanReissue[];
  tls_rollouts: Array<{
    asset_id: string;
    location: string;
    finding_kind: string;
    target_id: string;
    rollback_on_failure: boolean;
  }>;
  residuals: PQCMigrationPlanResidual[];
  reissue_count: number;
  tls_rollout_count: number;
}

export interface PQCMigrationRun {
  run_id: string;
  queued: number;
  certificate_reissues_queued: number;
  tls_findings_queued: number;
  target_algorithm: string;
  effective_algorithm: string;
  protocol: string;
  rollback_configured: boolean;
  migration_progress: CBOMMigrationProgress;
  queued_at: string;
}

export interface PQCMigrationFindingProgress {
  run_id: string;
  asset_id: string;
  finding_kind: string;
  target_id: string;
  target_revision: string;
  connector: string;
  status: string;
  failure?: string;
  updated_at: string;
}

export interface PQCMigrationProgress {
  run_id: string;
  total: number;
  queued: number;
  applied: number;
  failed: number;
  rolled_back: number;
  findings: PQCMigrationFindingProgress[];
}

export interface PQCMigrationRollback {
  run_id: string;
  queued: number;
  reason: string;
  migration_progress: CBOMMigrationProgress;
  queued_at: string;
}
export type AIAnswer = GenAIAnswer;
export type AIStatus = GenAIStatus;
export type CredentialRisk = GenCredentialRisk;
export type ContextualRiskPriorities = GenContextualRiskPriorities;
export type UrgentRiskSummary = GenUrgentRiskSummary;
export type ContextualRiskPriority = GenContextualRiskPriority;
export type Approval = GenApproval;
export type ApprovalAction = ApprovalRequest["action"];
export type PendingApprovalStatus = GenPendingApprovalRequest["status"];

/** AUD-77: one immutable approval intent served by the control plane.
 *
 * The request id says which approval object an operator is deciding. The
 * digest binds that decision to the exact resource version and operation
 * intent, so a later lifecycle change cannot silently reuse an older vote.
 * These aliases stay mechanically bound to the served OpenAPI schema. */
export type PendingApprovalRequest = GenPendingApprovalRequest;
export type PendingApprovalRequestList = GenApprovalRequestList;
export type ApprovalRequestDecision = GenApprovalDecision;
export type SecretApproval = GenSecretApproval;
export type SecretApprovalRequest = GenSecretApprovalRequest;
export type SecretApprovalAction = GenSecretApprovalRequest["action"];
export type AuditEvent = GenAuditEvent;
export type Profile = GenProfile;
export type ProfileMutationResult = Profile | ProfileApprovalResponse;
export type IssueCertificateInput = {
  name: string;
  ownerId?: string;
  issuerId?: string;
  wildcardBlastRadiusAcknowledged?: boolean;
  /** A PKCS#10 request the operator generated on the host that will use the
   * certificate. When supplied, trstctl signs it and generates no key, so the
   * private key never reaches the control plane. Omitting it uses the deprecated
   * server-side keygen path. */
  subjectCSRPEM?: string;
};
export type {
  SecretRotationScheduleRun,
  MDMSCEPChallengeRotationPreview,
  MDMSCEPPolicyRequest,
  MDMSCEPPolicy,
  MDMSCEPPolicyPreview,
  AccessChangeDecisionRequest,
  AccessChangeRequest,
  AccessChangeRequestCreateRequest,
  AccessChangeRequestList,
  ACMEARIPosture,
  ACMEEABCredential,
  ACMEEABPosture,
  ACMEOperatorPlan,
  AgentJobPosture,
  BulkheadStats,
  IssuerCapabilityMatrix,
  ACMEDNS01Preflight,
  ACMEDNS01PreflightRequest,
  ACMEDNS01ProviderCatalog,
  ACMEDNS01ProviderCatalogItem,
  ACMEDNS01ProviderConfig,
  ACMEDNS01ProviderConfigList,
  ACMEUpstreamAuthorizationList,
  EndpointVerification,
  EndpointVerificationList,
  EndpointKeyCustodyList,
  EnrollmentDiagnostic,
  EnrollmentDiagnosticList,
  EnrollmentDiagnosticVerification,
  ACMEDNS01ProviderConfigRequest,
  ActiveActiveIssuancePlan,
  AgentCertRevocation,
  AgentCertRevocationRequest,
  APIToken,
  APITokenCreateRequest,
  APITokenCreateResponse,
  APITokenList,
  AuditBundle,
  AuditFeed,
  AuditFeedList,
  AuditFeedPreview,
  AuditFeedRequest,
  BreakglassBundle,
  BreakglassIssueRequest,
  BreakglassIssueResponse,
  BreakglassReconcileRequest,
  BreakglassReconcileResponse,
  BulkRevokeRequest,
  BulkRevokeResult,
  CAAuthority,
  CAAuthorityList,
  CAAuthorityRotation,
  CAAuthorityRotationPlanPreview,
  CAAuthorityRotationRequest,
  CACeremonyPlanPreview,
  CACeremonyStartRequest,
  CACreateIntermediateRequest,
  CACreateOfflineIntermediateCSRRequest,
  CACreateRootRequest,
  CAImportExistingRequest,
  CAImportOfflineIntermediateRequest,
  CAImportOfflineRootRequest,
  CAIntermediateCSR,
  CAIssuedIntermediate,
  CAIssuedLeaf,
  CAIssueIntermediateRequest,
  CAIssueLeafRequest,
  CAKeyCeremony,
  CBOMInventory,
  CBOMMigrationProgress,
  CBOMScan,
  CBOMScanPreview,
  CBOMScanRequest,
  CloudSecretManagerIntegration,
  CodeSigningIdentity,
  CodeSigningIdentityList,
  CodeSigningKeylessRequest,
  CodeSigningRequest,
  CodeSigningSignature,
  ComplianceEvidencePack,
  ComplianceInventoryReport,
  ComplianceReportSchedule,
  ComplianceReportScheduleList,
  ComplianceReportScheduleRequest,
  ConnectorCatalog,
  ConnectorCatalogItem,
  ConnectorDelivery,
  ConnectorDeliveryList,
  ConnectorTargetActionRequest,
  RelayPluginRuntime,
  CRLDistribution,
  CRLDistributionList,
  RevocationCachePosture,
  RevocationHealth,
  DeploymentTarget,
  DeploymentTargetList,
  DeploymentTargetRequest,
  DiscoveryCapability,
  DiscoveryCapabilityCatalog,
  DiscoveryCapabilityField,
  DiscoveryCapabilityProvider,
  DiscoveryCoverage,
  DiscoveryFinding,
  DiscoveryFindingList,
  DiscoveryFindingTriageRequest,
  DiscoveryMonitoring,
  DiscoveryPlanPreview,
  DiscoveryRun,
  DiscoveryRunList,
  DiscoveryRunRequest,
  DiscoverySchedule,
  DiscoveryScheduleList,
  DiscoveryScheduleRequest,
  DiscoverySegment,
  DiscoverySegmentCoverage,
  DiscoverySegmentRequest,
  DiscoverySource,
  DiscoverySourceList,
  DiscoverySourceRequest,
  DriftRemediation,
  DriftRemediationDecision,
  DriftRemediationDecisionRequest,
  DriftRemediationFinding,
  DynamicLease,
  DynamicLeaseRenewRequest,
  DynamicLeaseRequest,
  EnterpriseSupportStatus,
  EphemeralAPIKey,
  EphemeralAPIKeyRequest,
  EphemeralApproval,
  EphemeralApprovalRequest,
  EphemeralCredential,
  EphemeralCredentialPreview,
  EphemeralCredentialRequest,
  ExternalCAIssuedCertificate,
  ExternalCAIssueRequest,
  FleetReissuanceActionRequest,
  FleetReissuanceEvidence,
  FleetReissuanceRequest,
  FleetReissuanceRun,
  FleetReissuanceRunList,
  GraphImpact,
  GraphTrustStores,
  MigrationAssessment,
  MigrationRun,
  MigrationRunActionRequest,
  MigrationRunList,
  MigrationRunStartRequest,
  UnownedQueue,
  RetirementChecklist,
  GraphNode,
  GraphQueryResult,
  GraphReachable,
  GraphResponse,
  IdentityConnectorTargetRequest,
  IncidentExecution,
  IncidentExecutionList,
  IncidentExecutionRequest,
  IssuerRequest,
  ITSMTicket,
  KubernetesCSRSupport,
  KubernetesSecretOperator,
  KubernetesTrustBundleDistribution,
  MachineAuthMethod,
  MachineAuthMethodList,
  MachineAuthMethodOverride,
  MachineLoginRequest,
  MachineLoginResponse,
  MachineSession,
  MachineSessionList,
  ManagedKey,
  ManagedKeyCustodyPlan,
  ManagedKeyGenerateRequest,
  ManagedKeyGenerationPreview,
  ManagedKeyGenerationPreviewRequest,
  ManagedOfferingStatus,
  ManagedTenant,
  ManagedTenantProvisionRequest,
  MDMSCEPChallengeRotated,
  MDMSCEPPolicyList,
  MDMSCEPStatus,
  Member,
  MemberList,
  MemberRequest,
  NHIComplianceReport,
  NHIDecommissionRequest,
  NHIDecommissionResponse,
  NHIExposurePosture,
  NHIInventory,
  NHIInventoryItem,
  NHIOverPrivilegePosture,
  NHIPolicyCompliance,
  NHIReviewCampaign,
  NHIReviewCampaignList,
  NHIReviewCampaignStartRequest,
  NHIReviewDecisionRequest,
  NHIReviewItem,
  NHIShadowPosture,
  NHIStalePosture,
  NHIStaticPosture,
  Notification,
  NotificationChannel,
  NotificationChannelList,
  NotificationChannelTest,
  NotificationChannelTestRequest,
  NotificationList,
  NotificationRoutingPolicy,
  NotificationRoutingPolicyList,
  NotificationRoutingPolicyRequest,
  NotificationRoutingPreview,
  OffboardMemberRequest,
  OffboardMemberResponse,
  OIDCMappingStatus,
  OutboxCircuit,
  OutboxCircuitList,
  OwnerRemediationAcceptRequest,
  OwnerRemediationQueue,
  OwnerRemediationRun,
  OwnershipAssignmentRequest,
  OwnershipAssignmentResult,
  OwnershipAttribution,
  OwnershipAttributionItem,
  PAMSession,
  PAMSessionList,
  PAMSessionRequest,
  PKISecret,
  PKISecretRequest,
  PlatformDistributionStatus,
  PolicyDryRun,
  PolicyDryRunRequest,
  PolicyVersion,
  PolicyVersionActionRequest,
  PolicyVersionList,
  PolicyVersionRequest,
  ProtocolProfileStatus,
  ProfileApprovalResponse,
  ProfileRestorePreview,
  ProfileRestoreRequest,
  PrivacyArchiveErasureAttestation,
  PrivacyArchiveErasureAttestationList,
  PrivacyArchiveErasureAttestationRequest,
  PrivacyCatalog,
  PrivacyRetentionRun,
  PrivacyRetentionRunList,
  PrivacySubjectErasure,
  PrivacySubjectErasureList,
  PrivacySubjectErasureRequest,
  PrivacySubjectExport,
  PrivacySubjectExportRequest,
  RemediationPlaybook,
  RemediationPlaybookCatalog,
  RemediationPlaybookRun,
  RemediationPlaybookRunList,
  RemediationPlaybookRunRequest,
  ResponseIntegrationDispatch,
  ResponseIntegrationDispatchRequest,
  RogueCertificatePosture,
  RoleList,
  RotationRun,
  RotationRunList,
  ScaleOrchestrationPlan,
  SecretMeta,
  SecretMetaList,
  SecretRecoverRequest,
  SecretRepositoryScanPosture,
  SecretRepositoryWebhookReceipt,
  SecretRepositoryWebhookRequest,
  SecretCreateRequest,
  SecretRotateRequest,
  SecretRotation,
  SecretRotationDueRun,
  SecretRotationRequest,
  SecretRotationSchedule,
  SecretRotationScheduleList,
  SecretRotationScheduleRequest,
  SecretScan,
  SecretScanRequest,
  SecretSync,
  SecretSyncRequest,
  SecretSyncTargetCatalog,
  SecretSyncWorkloadIdentitySource,
  SecretSyncWorkloadIdentitySourceList,
  SecretSyncWorkloadIdentitySourceRequest,
  SecretValue,
  SecretWorkloadInjection,
  ServiceNowTicketRequest,
  ShareRedeemRequest,
  ShareRequest,
  ShareToken,
  ShareValue,
  SystemReadout,
  TenantKeyDomainMigrateRequest,
  TenantKeyDomainSealReceipt,
  TenantKeyDomainStatus,
  SSHAttestedUserCert,
  SSHAttestedUserCertRequest,
  SSHFleetInventory,
  SSHHostRetirement,
  SSHHostRetireRequest,
  SSHRevokeCertificateRequest,
  SSHStatus,
  SSHTrustRollout,
  SSHTrustRolloutRequest,
  ThirdPartySecretScanIngestRequest,
  ThirdPartySecretScanPosture,
  ThirdPartySecretScanReceipt,
  TransitCiphertext,
  TransitDecryptRequest,
  TransitEncryptRequest,
  TransitHMAC,
  TransitHMACRequest,
  TransitKey,
  TransitKeyList,
  TransitKeyRequest,
  TransitPlaintext,
  TransitRewrapRequest,
  TransitRotateRequest,
  TransitSignature,
  TransitSignRequest,
  TransitVerify,
  TransitVerifyRequest,
  UnvaultedSecretPosture,
  WorkloadAttesterTrustSource,
  WorkloadAttesterTrustSourceList,
  WorkloadAttesterTrustSourceRequest,
  WorkloadAttesterTrustSourceRevoked,
  WorkloadAttesterTrustSourceRevokeRequest,
  WorkloadAttesterTrustSourceRotated,
  WorkloadAttesterTrustSourceRotateRequest,
};
// TransitionTo is the set of lifecycle targets the served contract accepts; the UI's
// transition actions are typed against it so an invalid target fails the build.
export type TransitionTo = TransitionRequest["to"];

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class ApiError extends Error {
  status: number;
  body: string;
  /** retryAfterSeconds is set for a 429 when the server sends Retry-After, so the UI
   * can surface a concrete "try again in N seconds" hint instead of a bare failure
   * (SURFACE-007; the server emits Retry-After on rate-limit at api.go). */
  retryAfterSeconds?: number;
  constructor(status: number, body: string, retryAfterSeconds?: number) {
    super(status === 429 ? `rate limited (429)${retryAfterSeconds != null ? ` — retry in ${retryAfterSeconds}s` : ""}` : `request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  /** isRateLimited is a convenience for the UI's special-case path. */
  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

/** parseRetryAfter reads a Retry-After header (RFC 7231: either delta-seconds or an
 * HTTP-date) into seconds, or undefined when absent/unparseable. */
function parseRetryAfter(h: string | null): number | undefined {
  if (!h) return undefined;
  const secs = Number(h);
  if (Number.isFinite(secs)) return Math.max(0, Math.round(secs));
  const when = Date.parse(h);
  if (!Number.isNaN(when)) return Math.max(0, Math.round((when - Date.now()) / 1000));
  return undefined;
}

function isUnsafeMethod(method: string | undefined): boolean {
  const m = (method ?? "GET").toUpperCase();
  return m !== "GET" && m !== "HEAD" && m !== "OPTIONS" && m !== "TRACE";
}

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return undefined;
}

// Exported for the audit-export workflow, which issues a blob fetch rather
// than a JSON request and so cannot go through req<T> (epic J1).
export function csrfHeaders(method: string | undefined): Record<string, string> {
  if (!isUnsafeMethod(method)) return {};
  const token = readCookie("trstctl_csrf");
  return token ? { "X-CSRF-Token": token } : {};
}

// Me is the browser-session principal returned by GET /auth/me. It is NOT a REST
// component schema (it comes from the auth/session layer, not the resource API), so it
// is hand-written here rather than generated — and stays minimal by design (subject +
// tenant; no token/secret ever crosses to the client; SURFACE-I01).
export interface Me {
  subject: string;
  tenant_id: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  locale?: string;
  time_zone?: string;
}

/** Public, boolean-only browser bootstrap metadata. No IdP endpoint, issuer,
 * tenant mapping, license content, or other pre-auth configuration detail is
 * included. */
export interface AuthMethods {
  oidc: boolean;
  saml: boolean;
  ldap: boolean;
  /** Boolean-only public preflight. Provider identity, license, and customer
   * metadata remain inside the separately authenticated Provider plane. */
  provider_plane: boolean;
}

export interface AuditQuery {
  type?: string;
  since?: string;
  until?: string;
  asOf?: number;
  q?: string;
  limit?: number;
}

export interface RiskQuery {
  sort?: "score" | "expiry";
  minScore?: number;
  privilege?: number;
  owner?: string;
}

export interface ProtocolRuntimeStatus {
  protocol: string;
  endpoint: string;
  enabled: boolean;
  served: boolean;
  status_code?: number;
  detail?: string;
}

export interface ProtocolRuntimeStatusList {
  source: "public_responder_probe";
  checked_at: string;
  items: ProtocolRuntimeStatus[];
}

export type ESTQualificationCheckID = "ca-chain" | "csr-rules" | "auth-gate";

export interface ESTQualificationCheck {
  id: ESTQualificationCheckID;
  method: "GET" | "POST";
  endpoint: string;
  expected: string;
  status_code?: number;
  passed: boolean;
  detail: string;
}

export interface ESTQualificationResult {
  checked_at: string;
  passed: boolean;
  checks: ESTQualificationCheck[];
}

export type SCEPQualificationCheckID = "capabilities" | "ca-material" | "empty-message-gate";

export interface SCEPQualificationCheck {
  id: SCEPQualificationCheckID;
  method: "GET" | "POST";
  endpoint: string;
  expected: string;
  status_code?: number;
  passed: boolean;
  detail: string;
}

export interface SCEPQualificationResult {
  checked_at: string;
  passed: boolean;
  checks: SCEPQualificationCheck[];
}

export interface CMPQualificationCheck {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
  recovery?: string;
}

export interface CMPQualification {
  checked_at: string;
  ready: boolean;
  effect_free: boolean;
  endpoint: string;
  profile: string;
  binding_mode: "subject-bound" | "registration-authority";
  client_trust_anchor_count: number;
  checks: CMPQualificationCheck[];
  preview_writes: string[];
  preview_external_effects: string[];
  preview_signer_calls: string[];
  proof: string[];
  blockers: string[];
}

export interface SPIFFEQualificationCheck {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
  recovery?: string;
}

export interface SPIFFEQualification {
  checked_at: string;
  ready: boolean;
  effect_free: boolean;
  trust_domain: string;
  socket_uri: string;
  transport: "unix";
  socket_mode: string;
  registration_entry_count: number;
  local_socket_deprecated: boolean;
  supported_operations: string[];
  checks: SPIFFEQualificationCheck[];
  preview_writes: string[];
  preview_external_effects: string[];
  preview_signer_calls: string[];
  proof: string[];
  blockers: string[];
  client_boundary: string;
}

export type EditionTier = "community" | "enterprise" | "provider";
export type EditionState = "community" | "active" | "grace" | "read_only";
export type FeatureMode = "enabled" | "read_only" | "off";

export interface EditionFeature {
  name: string;
  tier: EditionTier;
  licensed: boolean;
  mode: FeatureMode;
}

export interface UsageMeterDefinition {
  name: string;
  classification: string;
  primary_billable: boolean;
  notes?: string;
}

export interface EditionPackagingEntry {
  id: string;
  name: string;
  column: string;
  buyer_fit: string;
  license_boundary: string;
  billing: string;
  included: string[];
}

export interface ReferencePriceBand {
  id: string;
  label: string;
  annual_usd: number;
  unit: string;
}

export interface EditionPackaging {
  category_label: string;
  positioning: string;
  billable_unit: string;
  provider_billing_unit: string;
  no_per_certificate_billing: boolean;
  no_ephemeral_identity_billing: boolean;
  certificate_counters_classification: string;
  managed_boundary: string;
  pricing_posture: string;
  bundled_non_production_deployments: number;
  non_production_support_posture: string;
  reference_price_bands: ReferencePriceBand[];
  evidence_rail: string[];
  editions: EditionPackagingEntry[];
  meters: UsageMeterDefinition[];
}

export interface FIPSStatus {
  module_active: boolean;
  required: boolean;
  self_test_passed: boolean;
  capability_id?: string;
  validated_module_path?: boolean;
  standard?: string;
  module?: string;
  build_target?: string;
  runtime_activation?: string[];
  ci_gate?: string;
  crypto_boundary?: string;
  product_certification_residual?: string;
}

export interface EditionsInfo {
  tier: EditionTier;
  state: EditionState;
  customer?: string;
  license_id?: string;
  expires_at?: string;
  read_only_at?: string;
  deployment_entitlement?: {
    deployment_id?: string;
    environment: "production" | "non_production";
    production_units_consumed: number;
    bundled_non_production_deployments: number;
    registered_non_production_deployments: number;
    non_production_slots_remaining: number;
    legacy_unbound: boolean;
  };
  tenant_band?: number;
  managed_customer_band?: number;
  rights?: Array<"self_host" | "managed_service" | "resale">;
  features: EditionFeature[];
  fips: FIPSStatus;
  packaging: EditionPackaging;
}

interface ProtocolProbeSpec {
  protocol: string;
  endpoint: string;
  method?: "GET" | "HEAD";
  credentials?: RequestCredentials;
  accept?: string;
  methodMismatchMeansServed?: boolean;
  successDetail: string;
  methodMismatchDetail?: string;
}

const protocolStatusProbes: ProtocolProbeSpec[] = [
  {
    protocol: "acme",
    endpoint: "/directory",
    accept: "application/json",
    successDetail: "ACME directory responded.",
  },
  {
    protocol: "est",
    endpoint: "/.well-known/est/cacerts",
    credentials: "omit",
    accept: "application/pkcs7-mime, application/pkcs7, */*",
    successDetail: "EST CA-certs responder returned a chain.",
  },
  {
    protocol: "scep",
    endpoint: "/scep?operation=GetCACaps",
    accept: "text/plain, */*",
    successDetail: "SCEP capabilities responder returned caps.",
  },
  {
    protocol: "cmp",
    endpoint: "/cmp",
    method: "GET",
    methodMismatchMeansServed: true,
    successDetail: "CMP responder accepted the probe.",
    methodMismatchDetail: "CMP route is mounted and expects a PKIMessage request.",
  },
  {
    protocol: "ssh",
    endpoint: "/ssh/ca",
    accept: "text/plain, */*",
    successDetail: "SSH CA public-key endpoint responded.",
  },
  {
    protocol: "tsa",
    endpoint: "/tsa",
    method: "GET",
    methodMismatchMeansServed: true,
    successDetail: "TSA responder accepted the probe.",
    methodMismatchDetail: "TSA route is mounted and expects a timestamp request.",
  },
];

/** Preview transport isolation (mirrors probectl's demo model): while preview
 * mode is active, the client refuses EVERY server call before fetch — the
 * showcase runs entirely in the browser, so a hosted demo bundle can never
 * leak a request. The demo host's Worker 404s /api/* as belt-and-suspenders;
 * this is the wall. Set by AuthProvider on preview start/stop. */
let previewTransportIsolated = false;
export function setPreviewTransportIsolation(isolated: boolean): void {
  previewTransportIsolated = isolated;
}

/** Read the preview-isolation wall. A reader rather than an exported binding,
 * so this module stays the only writer (epic J1's audit download needs to
 * honour the same wall without being able to lower it). */
export function previewTransportIsIsolated(): boolean {
  return previewTransportIsolated;
}

const previewFixturesCompiled = import.meta.env.DEV || import.meta.env.VITE_TRSTCTL_DEMO === "1";

export function previewRefusal(): ApiError {
  const refusal = new ApiError(0, translateNow("preview.transportIsolated"));
  refusal.message = refusal.body;
  return refusal;
}

async function previewResponse(method: string): Promise<unknown> {
  // This branch is a compile-time constant. Vite removes both the import and
  // its chunk from the ordinary embedded product build; dev and the explicit
  // demo build retain it.
  if (previewFixturesCompiled) {
    const { previewRead } = await import("./previewData");
    const response = previewRead(method);
    if (response.matched) return response.value;
  }
  throw previewRefusal();
}

// Exported for the estate-shape workflow module (H1/H2/H4/I1), which must go
// through this same bounded transport.
export async function req<T>(path: string, init?: RequestInit): Promise<T> {
  if (previewTransportIsolated) {
    // api methods are intercepted before reaching req. Keep this second wall
    // for direct/internal callers and future code that accidentally bypasses
    // the exported client wrapper.
    throw previewRefusal();
  }
  const method = init?.method;
  const res = await fetch(path, {
    credentials: "include",
    ...init,
    headers: { Accept: "application/json", ...csrfHeaders(method), ...(init?.headers ?? {}) },
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (res.status === 429) {
    // Rate limited: surface Retry-After so the UI can show a concrete retry hint
    // (SURFACE-007). The server emits Retry-After on its per-tenant bulkhead/limit.
    throw new ApiError(429, await res.text(), parseRetryAfter(res.headers.get("Retry-After")));
  }
  if (!res.ok) throw new ApiError(res.status, await res.text());
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

async function protocolProbe(spec: ProtocolProbeSpec): Promise<ProtocolRuntimeStatus> {
  if (previewTransportIsolated) {
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: false,
      served: false,
      get detail() {
        return translateNow("preview.probesDisabled");
      },
    };
  }
  try {
    const res = await fetch(spec.endpoint, {
      method: spec.method ?? "GET",
      credentials: spec.credentials ?? "include",
      headers: { Accept: spec.accept ?? "*/*" },
    });
    const methodMismatchServed = spec.methodMismatchMeansServed === true && res.status === 405;
    const candidateStatus = res.ok || methodMismatchServed;
    const contentMatches = candidateStatus && (await protocolProbeContentMatches(spec, res));
    const ok = candidateStatus && contentMatches;
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: ok,
      served: ok,
      status_code: res.status,
      detail: ok
        ? methodMismatchServed
          ? (spec.methodMismatchDetail ?? "Responder is mounted and expects a protocol request.")
          : spec.successDetail
        : candidateStatus
          ? "Unexpected responder content; protocol status could not be verified."
          : protocolProbeFailureDetail(res),
    };
  } catch {
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: false,
      served: false,
      get detail() {
        return translateNow("source.responder.probe.failed.before.an.http.stat.e6657440c5");
      },
    };
  }
}

async function protocolProbeContentMatches(spec: ProtocolProbeSpec, res: Response): Promise<boolean> {
  const mediaType = (res.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > 1 << 20) return false;
  const text = new TextDecoder().decode(bytes);

  switch (spec.protocol) {
    case "acme": {
      if (mediaType !== "application/json") return false;
      try {
        const directory = JSON.parse(text) as Record<string, unknown>;
        return ["newNonce", "newAccount", "newOrder", "keyChange", "revokeCert"].every(
          (field) => typeof directory[field] === "string" && (directory[field] as string).length > 0,
        );
      } catch {
        return false;
      }
    }
    case "est": {
      if (mediaType !== "application/pkcs7-mime" || res.headers.get("Content-Transfer-Encoding")?.toLowerCase() !== "base64") return false;
      const encoded = text.replace(/\s/g, "");
      if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return false;
      try {
        const der = globalThis.atob(encoded);
        return der.length > 1 && der.charCodeAt(0) === 0x30;
      } catch {
        return false;
      }
    }
    case "scep": {
      if (mediaType !== "text/plain") return false;
      const capabilities = new Set(
        text
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean),
      );
      return ["POSTPKIOperation", "SHA-256", "SCEPStandard"].every((capability) => capabilities.has(capability));
    }
    case "cmp":
      return res.status === 405 && mediaType === "text/plain" && text.trim() === "cmp: POST required (RFC 6712)";
    case "ssh":
      return mediaType === "text/plain" && /^(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]+={0,3}(?:\s|$)/.test(text.trim());
    case "tsa":
      return (
        res.status === 405 &&
        mediaType === "text/plain" &&
        (res.headers.get("Allow") ?? "")
          .split(",")
          .map((method) => method.trim().toUpperCase())
          .includes("POST") &&
        text.trim() === "method not allowed"
      );
    default:
      return false;
  }
}

async function estQualification(): Promise<ESTQualificationResult> {
  const ca = await protocolProbe(protocolStatusProbes.find((spec) => spec.protocol === "est")!);
  const checks: ESTQualificationCheck[] = [
    {
      id: "ca-chain",
      method: "GET",
      endpoint: "/.well-known/est/cacerts",
      expected: "HTTP 200 with a base64 PKCS#7 CA chain",
      status_code: ca.status_code,
      passed: ca.served,
      detail: ca.served ? translateNow("protocols.estCheck.caPassed") : (ca.detail ?? translateNow("protocols.estCheck.caFailed")),
    },
  ];

  if (previewTransportIsolated) {
    checks.push(
      {
        id: "csr-rules",
        method: "GET",
        endpoint: "/.well-known/est/csrattrs",
        expected: "HTTP 204 or a valid CSR-attributes response",
        passed: false,
        detail: translateNow("preview.probesDisabled"),
      },
      {
        id: "auth-gate",
        method: "POST",
        endpoint: "/.well-known/est/simpleenroll",
        expected: "HTTP 401 with a Bearer authentication challenge",
        passed: false,
        detail: translateNow("preview.probesDisabled"),
      },
    );
    return { checked_at: new Date().toISOString(), passed: false, checks };
  }

  try {
    const response = await fetch("/.well-known/est/csrattrs", {
      method: "GET",
      credentials: "omit",
      headers: { Accept: "application/csrattrs, */*" },
    });
    const passed = response.status === 204;
    checks.push({
      id: "csr-rules",
      method: "GET",
      endpoint: "/.well-known/est/csrattrs",
      expected: "HTTP 204 or a valid CSR-attributes response",
      status_code: response.status,
      passed,
      detail: passed ? translateNow("protocols.estCheck.csrPassed") : translateNow("protocols.estCheck.csrHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "csr-rules",
      method: "GET",
      endpoint: "/.well-known/est/csrattrs",
      expected: "HTTP 204 or a valid CSR-attributes response",
      passed: false,
      detail: translateNow("protocols.estCheck.csrNetworkFailed"),
    });
  }

  try {
    const response = await fetch("/.well-known/est/simpleenroll", {
      method: "POST",
      credentials: "omit",
      headers: { Accept: "application/pkcs7-mime, */*", "Content-Type": "application/pkcs10" },
    });
    const challenge = response.headers.get("WWW-Authenticate") ?? "";
    const passed = response.status === 401 && /^Bearer(?:\s|$)/i.test(challenge);
    checks.push({
      id: "auth-gate",
      method: "POST",
      endpoint: "/.well-known/est/simpleenroll",
      expected: "HTTP 401 with a Bearer authentication challenge",
      status_code: response.status,
      passed,
      detail: passed
        ? translateNow("protocols.estCheck.authPassed")
        : response.status === 401
          ? translateNow("protocols.estCheck.authChallengeFailed")
          : translateNow("protocols.estCheck.authHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "auth-gate",
      method: "POST",
      endpoint: "/.well-known/est/simpleenroll",
      expected: "HTTP 401 with a Bearer authentication challenge",
      passed: false,
      detail: translateNow("protocols.estCheck.authNetworkFailed"),
    });
  }

  return {
    checked_at: new Date().toISOString(),
    passed: checks.every((check) => check.passed),
    checks,
  };
}

function isDefiniteLengthDERSequence(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 3 || bytes.byteLength > 1 << 20 || bytes[0] !== 0x30) return false;
  const firstLength = bytes[1];
  if (firstLength < 0x80) return 2 + firstLength === bytes.byteLength;
  const lengthOctets = firstLength & 0x7f;
  if (lengthOctets === 0 || lengthOctets > 4 || bytes.byteLength < 2 + lengthOctets) return false;
  if (bytes[2] === 0) return false;
  let contentLength = 0;
  for (let index = 0; index < lengthOctets; index += 1) contentLength = contentLength * 256 + bytes[2 + index];
  return 2 + lengthOctets + contentLength === bytes.byteLength;
}

async function scepQualification(): Promise<SCEPQualificationResult> {
  if (previewTransportIsolated) throw previewRefusal();

  const checks: SCEPQualificationCheck[] = [];
  try {
    const response = await fetch("/scep?operation=GetCACaps", {
      method: "GET",
      credentials: "omit",
      headers: { Accept: "text/plain" },
    });
    const mediaType = (response.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
    const capabilities = new Set(
      (await response.text())
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    );
    const passed =
      response.status === 200 &&
      mediaType === "text/plain" &&
      ["POSTPKIOperation", "SHA-256", "SCEPStandard"].every((capability) => capabilities.has(capability));
    checks.push({
      id: "capabilities",
      method: "GET",
      endpoint: "/scep?operation=GetCACaps",
      expected: "HTTP 200 with POSTPKIOperation, SHA-256, and SCEPStandard",
      status_code: response.status,
      passed,
      detail: passed
        ? translateNow("protocols.scepCheck.capabilitiesPassed")
        : translateNow("protocols.scepCheck.capabilitiesHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "capabilities",
      method: "GET",
      endpoint: "/scep?operation=GetCACaps",
      expected: "HTTP 200 with POSTPKIOperation, SHA-256, and SCEPStandard",
      passed: false,
      detail: translateNow("protocols.scepCheck.capabilitiesNetworkFailed"),
    });
  }

  try {
    const response = await fetch("/scep?operation=GetCACert", {
      method: "GET",
      credentials: "omit",
      headers: { Accept: "application/x-x509-ca-cert, application/x-x509-ca-ra-cert" },
    });
    const mediaType = (response.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
    const bytes = new Uint8Array(await response.arrayBuffer());
    const passed =
      response.status === 200 &&
      (mediaType === "application/x-x509-ca-cert" || mediaType === "application/x-x509-ca-ra-cert") &&
      isDefiniteLengthDERSequence(bytes);
    checks.push({
      id: "ca-material",
      method: "GET",
      endpoint: "/scep?operation=GetCACert",
      expected: "HTTP 200 with a structurally valid CA certificate or CA/RA bundle",
      status_code: response.status,
      passed,
      detail: passed ? translateNow("protocols.scepCheck.caPassed") : translateNow("protocols.scepCheck.caHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "ca-material",
      method: "GET",
      endpoint: "/scep?operation=GetCACert",
      expected: "HTTP 200 with a structurally valid CA certificate or CA/RA bundle",
      passed: false,
      detail: translateNow("protocols.scepCheck.caNetworkFailed"),
    });
  }

  try {
    const response = await fetch("/scep?operation=PKIOperation", {
      method: "POST",
      credentials: "omit",
      headers: { Accept: "text/plain", "Content-Type": "application/x-pki-message" },
    });
    const mediaType = (response.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
    const body = await response.text();
    const passed = response.status === 400 && mediaType === "text/plain" && body.trim() === "scep: empty PKIOperation body";
    checks.push({
      id: "empty-message-gate",
      method: "POST",
      endpoint: "/scep?operation=PKIOperation",
      expected: "HTTP 400 before an empty PKI message can reach enrollment",
      status_code: response.status,
      passed,
      detail: passed ? translateNow("protocols.scepCheck.emptyPassed") : translateNow("protocols.scepCheck.emptyHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "empty-message-gate",
      method: "POST",
      endpoint: "/scep?operation=PKIOperation",
      expected: "HTTP 400 before an empty PKI message can reach enrollment",
      passed: false,
      detail: translateNow("protocols.scepCheck.emptyNetworkFailed"),
    });
  }

  return { checked_at: new Date().toISOString(), passed: checks.every((check) => check.passed), checks };
}

function protocolProbeFailureDetail(res: Response): string {
  if (res.status === 404) return "Responder path was not mounted by this control plane.";
  if (res.status === 503) return "Responder is mounted but currently unavailable.";
  if (res.status === 401 || res.status === 403) return "Responder rejected the browser session.";
  return res.statusText || `Responder returned HTTP ${res.status}.`;
}

/** newIdempotencyKey returns a fresh key so a retried mutation cannot execute
 * twice (AN-5). */
function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** mutate issues a state-changing request with an optional JSON body and an
 * Idempotency-Key. */
export function mutate<T>(method: string, path: string, body?: unknown, idempotencyKey = newIdempotencyKey()): Promise<T> {
  return req<T>(path, {
    method,
    headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// AUD-42: this licensed command is intentionally typed beside the shared HTTP
// client. Community builds can still compile the thin client, but an unlicensed
// server has no POST route and therefore fails closed before any command exists.
export interface CARetirementRequest {
  final_epoch: number;
  confirm_irreversible: true;
}

export interface CARetirementReceipt {
  key_id: string;
  command_event_id: string;
  status: string;
  ledger_position: number;
  final_epoch: number;
}

function enrollmentTokenRequest(input?: EnrollmentTokenRequest): EnrollmentTokenRequest | undefined {
  const allowedIdentity = input?.allowed_identity?.trim();
  const roles = input?.roles ?? [];
  // A2: the capability grant must reach the wire. This builder once rebuilt the
  // body from allowed_identity alone and silently dropped roles — the console's
  // role selector minted host-only tokens no matter what the operator chose,
  // and the page test missed it because it asserted against a mocked client.
  // The wire-level test in api.test.ts is what pins this now.
  if (!allowedIdentity && roles.length === 0) return undefined;
  return {
    ...(allowedIdentity ? { allowed_identity: allowedIdentity } : {}),
    ...(roles.length > 0 ? { roles } : {}),
  };
}

/** postRead sends a read-only POST. These endpoints accept structured bodies but do
 * not mutate state, so they deliberately do not carry Idempotency-Key. */
function postRead<T>(path: string, body?: unknown): Promise<T> {
  return req<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function firstCertificateIdentityRequest(input: IssueCertificateInput, ownerId: string): IdentityRequest {
  const wildcardAttrs =
    input.name.trim().startsWith("*.") && input.wildcardBlastRadiusAcknowledged
      ? {
          attributes: {
            validation_method: "dns-01",
            wildcard_blast_radius_acknowledged: true,
          },
        }
      : {};
  return {
    kind: "x509_certificate",
    name: input.name,
    owner_id: ownerId,
    ...(input.issuerId ? { issuer_id: input.issuerId } : {}),
    ...wildcardAttrs,
  };
}

/** Api is the client surface the UI depends on; it is mockable in tests. The
 * request inputs are the OpenAPI-generated request bodies (OwnerRequest,
 * IssuerRequest, IdentityRequest, TransitionRequest) so a mutation cannot send a
 * field the server does not accept — the same contract guarantee as the responses. */
export interface Api {
  me(): Promise<Me>;
  authMethods(): Promise<AuthMethods>;
  logout(): Promise<void>;
  /** Server-derived product posture for the current principal. Source paths and QA evidence never cross this boundary. */
  capabilities(): Promise<CapabilityView>;
  editions(): Promise<EditionsInfo>;
  enterpriseSupportStatus(): Promise<EnterpriseSupportStatus>;
  managedOfferingStatus(): Promise<ManagedOfferingStatus>;
  scaleOrchestration(): Promise<ScaleOrchestrationPlan>;
  platformSystem(): Promise<SystemReadout>;
  /** J2: when the backup last VERIFIED, and what the last restore drill found. */
  drPosture(): Promise<DRPosture>;
  tenantKeyDomain(): Promise<TenantKeyDomainStatus>;
  migrateTenantKeyDomain(input: TenantKeyDomainMigrateRequest): Promise<TenantKeyDomainStatus>;
  sealTenantKeyDomain(): Promise<TenantKeyDomainSealReceipt>;
  unsealTenantKeyDomain(): Promise<TenantKeyDomainStatus>;
  activeActiveIssuance(): Promise<ActiveActiveIssuancePlan>;
  provisionManagedTenant(input: ManagedTenantProvisionRequest): Promise<ManagedTenant>;
  certificates(): Promise<Certificate[]>;
  certificatePage(options?: { limit?: number; cursor?: string; expiringBefore?: string }): Promise<CertificatePage>;
  certificateHealth(): Promise<CertificateHealthDashboard>;
  crlDistributions(): Promise<CRLDistributionList>;
  revocationCaches(): Promise<RevocationCachePosture>;
  revocationHealth(): Promise<RevocationHealth>;
  rogueCertificates(): Promise<RogueCertificatePosture>;
  submitCertificateTransparency(input: CTSubmissionRequest): Promise<CTSubmission>;
  ctMonitoring(): Promise<CTMonitoring>;
  /** C4: whether the configured authorities agree. Licensed; 402/403 when not entitled. */
  authorityAgreement(): Promise<AuthorityAgreementReport>;
  usageEvidence(periodStart: string, periodEnd: string): Promise<UsageEvidence>;
  /** M2: crypto assets sequenced for migration by observed dependency, not severity alone. */
  cryptoReadiness(): Promise<CryptoReadiness>;
  cryptoReadinessExport(): Promise<CryptoReadinessExport>;
  /** I2: ownership an import refused to overwrite, and changes it made and recorded. */
  ownershipConflicts(): Promise<OwnershipConflictList>;
  /** I2: close a disagreement. The reason is required — see the route's own guard. */
  resolveOwnershipConflict(id: string, resolution: string): Promise<unknown>;
  /** I2: whether ownership is actually being re-read from the CMDB, and why the last read failed. */
  cmdbSchedule(): Promise<CMDBReconcileSchedule>;
  /** I3: the request queue, including the denied and expired rows an audit needs. */
  issuanceRequests(): Promise<IssuanceRequestList>;
  /** I3/AUD-78: open a request without pretending it is already an identity. */
  createIssuanceRequest(input: IssuanceRequestInput): Promise<IssuanceRequest>;
  /** F4: validate and normalize the exact request without writing state or contacting a CA. */
  previewIssuanceRequest(input: IssuanceRequestInput): Promise<IssuanceRequestPreview>;
  /** I3: record an independent approval. Approval is a decision, not issuance. */
  approveIssuanceRequest(id: string): Promise<IssuanceRequest>;
  /** I3: deny one exact request with a reason the requester can act on. */
  denyIssuanceRequest(id: string, reason: string): Promise<IssuanceRequest>;
  /** I3: let the original requester withdraw a request they no longer need. */
  cancelIssuanceRequest(id: string): Promise<IssuanceRequest>;
  /** I3: create or recover the exact requested identity without claiming it is issued. */
  prepareIssuanceRequest(id: string): Promise<IssuanceRequestPreparation>;
  /** I3: close only after matching signer-backed certificate evidence exists. */
  completeIssuanceRequest(id: string): Promise<IssuanceRequest>;
  /** I3/AUD-47: one provider's durable relay cursor, coverage, terminal run, and failure. */
  ticketIntakeSchedule(system?: "servicenow" | "jira"): Promise<TicketIntakeSchedule>;
  /** I5: read-only MDM device correlation; unobserved is counted apart from failed. */
  mdmDevices(): Promise<MDMDeviceList>;
  /** I5/AUD-45: relay-only Intune/Jamf schedules, including waiting/failure state. */
  mdmPollSchedules(): Promise<MDMPollScheduleList>;
  /** I5: evidence-backed requested/issued/installed/renewing trace for one device. */
  mdmDeviceTrace(mdm: string, id: string): Promise<MDMDeviceTrace>;
  /** A5: staged rollout state, ring assignment, and the fleet version histogram. */
  agentUpgradeCampaign(): Promise<AgentUpgradeCampaign>;
  updateCTMonitoring(input: CTMonitoringRequest): Promise<CTMonitoring>;
  acmeARIPosture(options?: { limit?: number; cursor?: string }): Promise<ACMEARIPosture>;
  /** F5: server-owned, effect-free ACME readiness, next action, and recovery plan. */
  acmeOperatorPlan(): Promise<ACMEOperatorPlan>;
  acmeEABCredentials(): Promise<ACMEEABPosture>;
  setACMEEABCredentialDisabled(kid: string, disabled: boolean): Promise<ACMEEABCredential>;
  acmeDNS01Providers(): Promise<ACMEDNS01ProviderCatalog>;
  acmeDNS01ProviderConfigs(): Promise<ACMEDNS01ProviderConfigList>;
  acmeUpstreamAuthorizations(): Promise<ACMEUpstreamAuthorizationList>;
  endpointVerifications(): Promise<EndpointVerificationList>;
  // B2: where each deployment target's private key is generated.
  endpointKeyCustody(): Promise<EndpointKeyCustodyList>;
  // I4: recent enrolment refusals, classified.
  enrollmentDiagnostics(): Promise<EnrollmentDiagnosticList>;
  /** I4/AUD-49: queue one network relay to re-check the exact failed target. */
  proveEnrollmentDiagnosticFixed(id: string): Promise<EnrollmentDiagnosticVerification>;
  getCertificate(id: string): Promise<Certificate>;
  ingestCertificate(input: CertificateIngestRequest): Promise<Certificate>;
  owners(): Promise<Owner[]>;
  createOwner(input: OwnerRequest): Promise<Owner>;
  assignOwnership(input: OwnershipAssignmentRequest): Promise<OwnershipAssignmentResult>;
  attestOwner(id: string): Promise<Owner>;
  ownershipExceptions(identityId: string): Promise<OwnershipException[]>;
  grantOwnershipException(identityId: string, input: OwnershipExceptionRequest): Promise<OwnershipException>;
  revokeOwnershipException(identityId: string, exceptionId: string, input: OwnershipExceptionRevokeRequest): Promise<OwnershipException>;
  issuers(): Promise<Issuer[]>;
  issuerCapabilities(): Promise<IssuerCapabilityMatrix>;
  createIssuer(input: IssuerRequest): Promise<Issuer>;
  protocolProfileStatus(): Promise<ProtocolProfileStatus>;
  activateProtocolProfile(): Promise<ProtocolProfileStatus>;
  externalCAs(): Promise<ExternalCA[]>;
  issueExternalCA(id: string, input: ExternalCAIssueRequest): Promise<ExternalCAIssuedCertificate>;
  caDiscoveryInventory(): Promise<CADiscovery>;
  identities(): Promise<Identity[]>;
  /** AUD-77: real pending intents only; lifecycle inventory is not an approval queue. */
  approvalRequests(): Promise<PendingApprovalRequest[]>;
  /** AUD-77: bind the vote to both the immutable request id and its intent digest. */
  approveApprovalRequest(id: string, intentDigest: string): Promise<ApprovalRequestDecision>;
  /** AUD-77: deny the immutable request itself; never mutate its target resource. */
  denyApprovalRequest(id: string, intentDigest: string, reason: string): Promise<ApprovalRequestDecision>;
  nhiInventory(): Promise<NHIInventory>;
  nhiShadowPosture(): Promise<NHIShadowPosture>;
  nhiPolicyCompliance(): Promise<NHIPolicyCompliance>;
  nhiOverPrivilegePosture(): Promise<NHIOverPrivilegePosture>;
  nhiStalePosture(): Promise<NHIStalePosture>;
  nhiStaticPosture(): Promise<NHIStaticPosture>;
  nhiExposurePosture(): Promise<NHIExposurePosture>;
  decommissionNHI(input: NHIDecommissionRequest): Promise<NHIDecommissionResponse>;
  ownershipAttribution(): Promise<OwnershipAttribution>;
  getIdentity(id: string): Promise<Identity>;
  createIdentity(input: IdentityRequest): Promise<Identity>;
  previewIdentityTransition(id: string, to: TransitionRequest["to"], reason?: string, subjectCSRPEM?: string): Promise<IdentityTransitionPreview>;
  transitionIdentity(
    id: string,
    to: TransitionRequest["to"],
    reason?: string,
    subjectCSRPEM?: string,
    idempotencyKey?: string,
    expectedVersion?: number,
  ): Promise<Identity>;
  /** Compatibility route for identity decisions; the complete immutable request
   * binding is mandatory, just like the canonical approval-request route. */
  approveIdentityAction(id: string, input: ApprovalRequest): Promise<Approval>;
  /** issueCertificate is the one-call convenience the wizard and the "issue"
   * action use: it ensures an owner, creates the identity, and issues it. */
  issueCertificate(input: IssueCertificateInput): Promise<Identity>;
  agents(): Promise<Agent[]>;
  agentPage(options?: { limit?: number; cursor?: string }): Promise<AgentList>;
  previewEnrollmentPlan(input?: EnrollmentTokenRequest): Promise<EnrollmentPlanPreview>;
  createEnrollmentToken(input?: EnrollmentTokenRequest): Promise<EnrollmentToken>;
  offboardAgent(id: string, input: AgentOffboardRequest): Promise<AgentOffboardResponse>;
  discoveryCapabilities(): Promise<DiscoveryCapabilityCatalog>;
  previewDiscoveryPlan(input: DiscoverySourceRequest): Promise<DiscoveryPlanPreview>;
  preflightDiscoverySource(id: string): Promise<DiscoveryPlanPreview>;
  createDiscoverySegment(input: DiscoverySegmentRequest): Promise<DiscoverySegment>;
  discoverySources(options?: { limit?: number; cursor?: string }): Promise<DiscoverySourceList>;
  createDiscoverySource(input: DiscoverySourceRequest): Promise<DiscoverySource>;
  discoverySchedules(options?: { limit?: number; cursor?: string }): Promise<DiscoveryScheduleList>;
  createDiscoverySchedule(input: DiscoveryScheduleRequest): Promise<DiscoverySchedule>;
  discoveryRuns(options?: { limit?: number; cursor?: string }): Promise<DiscoveryRunList>;
  getDiscoveryRun(id: string): Promise<DiscoveryRun>;
  startDiscoveryRun(input: DiscoveryRunRequest): Promise<DiscoveryRun>;
  retryDiscoveryRun(id: string): Promise<DiscoveryRun>;
  discoveryMonitoring(): Promise<DiscoveryMonitoring>;
  /** F1: AD CS certificate template posture observed by an in-domain relay. */
  adcsPosture(): Promise<ADCSPosture>;
  adcsDrift(): Promise<ADCSDriftHistory>;
  /** F4: per-CA certificate-database lifecycle visibility. */
  adcsDatabases(): Promise<ADCSDatabaseList>;
  discoveryCoverage(options?: { class?: string; sourceKind?: string }): Promise<DiscoveryCoverage>;
  driftRemediation(): Promise<DriftRemediation>;
  decideDriftRemediation(id: string, input: DriftRemediationDecisionRequest): Promise<DriftRemediationDecision>;
  discoveryFindings(options?: { limit?: number; cursor?: string; runId?: string }): Promise<DiscoveryFindingList>;
  claimDiscoveryFinding(id: string, input: DiscoveryFindingTriageRequest): Promise<DiscoveryFinding>;
  dismissDiscoveryFinding(id: string, input: DiscoveryFindingTriageRequest): Promise<DiscoveryFinding>;
  connectorCatalog(options?: { limit?: number; cursor?: string }): Promise<ConnectorCatalog>;
  connectorTargets(): Promise<DeploymentTargetList>;
  createConnectorTarget(input: DeploymentTargetRequest): Promise<DeploymentTarget>;
  createEndpointBinding(input: EndpointBindingRequest): Promise<EndpointBinding>;
  bindIdentityConnectorTarget(id: string, input: IdentityConnectorTargetRequest): Promise<Identity>;
  testConnectorTarget(id: string): Promise<ConnectorDelivery>;
  deployConnectorTarget(id: string, input: ConnectorTargetActionRequest): Promise<Identity>;
  rollbackConnectorTarget(id: string, input: ConnectorTargetActionRequest): Promise<ConnectorDelivery>;
  connectorDeliveries(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<ConnectorDeliveryList>;
  rotationRuns(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<RotationRunList>;
  executeIncident(input: IncidentExecutionRequest): Promise<IncidentExecution>;
  dispatchResponseIntegrations(input: ResponseIntegrationDispatchRequest): Promise<ResponseIntegrationDispatch>;
  createServiceNowTicket(input: ServiceNowTicketRequest): Promise<ITSMTicket>;
  incidentExecutions(options?: { limit?: number; cursor?: string; identityId?: string }): Promise<IncidentExecutionList>;
  outboxReconciliationConflicts(): Promise<OutboxReconciliationConflictList>;
  getIncidentExecution(id: string): Promise<IncidentExecution>;
  remediationPlaybooks(): Promise<RemediationPlaybookCatalog>;
  runRemediationPlaybook(id: string, input: RemediationPlaybookRunRequest): Promise<RemediationPlaybookRun>;
  remediationPlaybookRuns(options?: { limit?: number; cursor?: string; playbookId?: string }): Promise<RemediationPlaybookRunList>;
  getRemediationPlaybookRun(id: string): Promise<RemediationPlaybookRun>;
  ownerRemediationActions(options?: { ownerId?: string }): Promise<OwnerRemediationQueue>;
  acceptOwnerRemediationAction(id: string, input: OwnerRemediationAcceptRequest): Promise<OwnerRemediationRun>;
  startFleetReissuance(input: FleetReissuanceRequest): Promise<FleetReissuanceRun>;
  fleetReissuanceRuns(options?: { limit?: number; cursor?: string; issuerId?: string }): Promise<FleetReissuanceRunList>;
  getFleetReissuanceRun(id: string): Promise<FleetReissuanceRun>;
  pauseFleetReissuance(id: string, input: FleetReissuanceActionRequest): Promise<FleetReissuanceRun>;
  resumeFleetReissuance(id: string, input: FleetReissuanceActionRequest): Promise<FleetReissuanceRun>;
  rollbackFleetReissuance(id: string, input: FleetReissuanceActionRequest): Promise<FleetReissuanceRun>;
  exportFleetReissuanceEvidence(id: string): Promise<FleetReissuanceEvidence>;
  breakglassIssue(input: BreakglassIssueRequest): Promise<BreakglassIssueResponse>;
  breakglassReconcile(input: BreakglassReconcileRequest): Promise<BreakglassReconcileResponse>;
  signCode(input: CodeSigningRequest): Promise<CodeSigningSignature>;
  signCodeKeyless(input: CodeSigningKeylessRequest): Promise<CodeSigningSignature>;
  codeSigningIdentities(): Promise<CodeSigningIdentityList>;
  risk(options?: RiskQuery): Promise<CredentialRisk[]>;
  contextualRiskPriorities(): Promise<ContextualRiskPriorities>;
  profiles(): Promise<Profile[]>;
  getProfileVersion(name: string, version: number): Promise<Profile>;
  createProfile(input: ProfileRequest): Promise<ProfileMutationResult>;
  previewProfileRestore(name: string, version: number, input: ProfileRestoreRequest): Promise<ProfileRestorePreview>;
  restoreProfileVersion(name: string, version: number, input: ProfileRestoreRequest): Promise<ProfileMutationResult>;
  previewCACeremony(input: CACeremonyStartRequest): Promise<CACeremonyPlanPreview>;
  createCACeremony(input: CACeremonyStartRequest): Promise<CAKeyCeremony>;
  approveCACeremony(id: string): Promise<CAKeyCeremony>;
  importOfflineRootCA(input: CAImportOfflineRootRequest): Promise<CAAuthority>;
  importExistingCA(input: CAImportExistingRequest): Promise<CAAuthority>;
  createOfflineIntermediateCSR(id: string, input: CACreateOfflineIntermediateCSRRequest): Promise<CAIntermediateCSR>;
  importOfflineIntermediateCA(id: string, input: CAImportOfflineIntermediateRequest): Promise<CAAuthority>;
  previewCAAuthorityRotation(id: string, input: CAAuthorityRotationRequest): Promise<CAAuthorityRotationPlanPreview>;
  rotateCAAuthority(id: string, input: CAAuthorityRotationRequest): Promise<CAAuthorityRotation>;
  rekeyCAAuthority(id: string, input: CAAuthorityRekeyRequest): Promise<CAAuthorityRotation>;
  managedKeyCustody(): Promise<ManagedKeyCustodyPlan>;
  previewManagedKeyGeneration(input: ManagedKeyGenerationPreviewRequest): Promise<ManagedKeyGenerationPreview>;
  generateManagedKey(input: ManagedKeyGenerateRequest): Promise<ManagedKey>;
  rotateManagedKey(keyId: string): Promise<ManagedKey>;
  revokeManagedKey(keyId: string): Promise<ManagedKey>;
  zeroizeManagedKey(keyId: string): Promise<ManagedKey>;
  accessRoles(): Promise<RoleList>;
  oidcMappingStatus(): Promise<OIDCMappingStatus>;
  members(options?: { limit?: number; cursor?: string; includeOffboarded?: boolean }): Promise<MemberList>;
  upsertMember(subject: string, input: MemberRequest): Promise<Member>;
  offboardMember(subject: string, input: OffboardMemberRequest): Promise<OffboardMemberResponse>;
  accessChangeRequests(options?: { limit?: number; cursor?: string }): Promise<AccessChangeRequestList>;
  createAccessChangeRequest(input: AccessChangeRequestCreateRequest): Promise<AccessChangeRequest>;
  getAccessChangeRequest(id: string): Promise<AccessChangeRequest>;
  decideAccessChangeRequest(id: string, input: AccessChangeDecisionRequest): Promise<AccessChangeRequest>;
  nhiReviewCampaigns(options?: { limit?: number; cursor?: string }): Promise<NHIReviewCampaignList>;
  startNHIReviewCampaign(input: NHIReviewCampaignStartRequest): Promise<NHIReviewCampaign>;
  getNHIReviewCampaign(id: string): Promise<NHIReviewCampaign>;
  decideNHIReviewItem(campaignId: string, itemId: string, input: NHIReviewDecisionRequest): Promise<NHIReviewCampaign>;
  apiTokens(options?: { limit?: number; cursor?: string; subject?: string; includeRevoked?: boolean }): Promise<APITokenList>;
  createAPIToken(input: APITokenCreateRequest): Promise<APITokenCreateResponse>;
  revokeAPIToken(id: string): Promise<void>;
  erasePrivacySubject(input: PrivacySubjectErasureRequest): Promise<PrivacySubjectErasure>;
  privacySubjectErasures(options?: { limit?: number; cursor?: string }): Promise<PrivacySubjectErasureList>;
  exportPrivacySubject(input: PrivacySubjectExportRequest): Promise<PrivacySubjectExport>;
  enforcePrivacyRetention(): Promise<PrivacyRetentionRun>;
  privacyRetentionRuns(options?: { limit?: number; cursor?: string }): Promise<PrivacyRetentionRunList>;
  privacyCatalog(): Promise<PrivacyCatalog>;
  auditEvents(options?: AuditQuery): Promise<AuditEvent[]>;
  exportAudit(options?: AuditQuery): Promise<AuditBundle>;
  auditFeeds(): Promise<AuditFeedList>;
  previewAuditFeed(id: string, input: AuditFeedRequest): Promise<AuditFeedPreview>;
  putAuditFeed(id: string, input: AuditFeedRequest): Promise<AuditFeed>;
  // J1: download a record stream (ndjson/csv/splunk-hec/sentinel) as a file.
  downloadAuditExport(options: AuditQuery | undefined, format: string): Promise<string>;
  complianceEvidencePack(framework: ComplianceEvidencePack["framework"]): Promise<ComplianceEvidencePack>;
  complianceInventoryReport(): Promise<ComplianceInventoryReport>;
  nhiComplianceReport(): Promise<NHIComplianceReport>;
  complianceReportSchedules(options?: { limit?: number; cursor?: string }): Promise<ComplianceReportScheduleList>;
  createComplianceReportSchedule(input: ComplianceReportScheduleRequest): Promise<ComplianceReportSchedule>;
  policyVersions(): Promise<PolicyVersionList>;
  createPolicyVersion(input: PolicyVersionRequest): Promise<PolicyVersion>;
  activatePolicyVersion(id: string, input: PolicyVersionActionRequest): Promise<PolicyVersion>;
  rollbackPolicyVersion(id: string, input: PolicyVersionActionRequest): Promise<PolicyVersion>;
  policyDryRun(input: PolicyDryRunRequest): Promise<PolicyDryRun>;
  graph(): Promise<GraphResponse>;
  graphBlastRadius(id: string): Promise<GraphImpact>;
  // H1: which discovered trust stores carry this CA's anchor, and where.
  graphTrustStores(id: string): Promise<GraphTrustStores>;
  // H2: read-only assessment of a migration plan.
  assessMigration(request: unknown): Promise<MigrationAssessment>;
  startMigrationRun(request: MigrationRunStartRequest): Promise<MigrationRun>;
  migrationRuns(): Promise<MigrationRunList>;
  migrationRun(id: string): Promise<MigrationRun>;
  pauseMigrationRun(id: string, request?: MigrationRunActionRequest): Promise<MigrationRun>;
  resumeMigrationRun(id: string): Promise<MigrationRun>;
  rollbackMigrationRun(id: string, request?: MigrationRunActionRequest): Promise<MigrationRun>;
  // I1: managed identities whose ownership cannot answer an incident question.
  unownedIdentities(): Promise<UnownedQueue>;
  // H4: what blocks a CA key's destruction.
  caRetirementChecklist(keyId: string): Promise<RetirementChecklist>;
  retireCAKey(keyId: string, input: CARetirementRequest): Promise<CARetirementReceipt>;
  graphReachable(id: string): Promise<GraphReachable>;
  graphQuery(query: string): Promise<GraphQueryResult>;
  // CLI parity (S3.3): console flows for every remaining core API operation.
  pamSessions(options?: { limit?: number; cursor?: string }): Promise<PAMSessionList>;
  pamSession(id: string): Promise<PAMSession>;
  openPAMSession(input: PAMSessionRequest): Promise<PAMSession>;
  acmeDNS01ProviderConfig(id: string): Promise<ACMEDNS01ProviderConfig>;
  updateACMEDNS01ProviderConfig(id: string, input: ACMEDNS01ProviderConfigRequest): Promise<ACMEDNS01ProviderConfig>;
  deleteACMEDNS01ProviderConfig(id: string): Promise<void>;
  acmeDNS01Preflight(input: ACMEDNS01PreflightRequest): Promise<ACMEDNS01Preflight>;
  revokeAgentCert(id: string, input: AgentCertRevocationRequest): Promise<AgentCertRevocation>;
  caCeremony(id: string): Promise<CAKeyCeremony>;
  caAuthorities(): Promise<CAAuthorityList>;
  edgeSegmentPolicies(): Promise<EdgeSegmentPolicyList>;
  edgeDelegations(): Promise<EdgeDelegationList>;
  edgeDelegation(id: string): Promise<EdgeDelegationDetail>;
  createRootCA(input: CACreateRootRequest): Promise<CAAuthority>;
  createIntermediateCA(input: CACreateIntermediateRequest): Promise<CAAuthority>;
  signIntermediateCSR(id: string, input: CAIssueIntermediateRequest): Promise<CAIssuedIntermediate>;
  issueLeafFromCA(id: string, input: CAIssueLeafRequest): Promise<CAIssuedLeaf>;
  bulkRevokeCertificates(input: BulkRevokeRequest): Promise<BulkRevokeResult>;
  bulkRevokeIdentities(input: BulkRevokeRequest): Promise<BulkRevokeResult>;
  connectorTarget(id: string): Promise<DeploymentTarget>;
  updateConnectorTarget(id: string, input: DeploymentTargetRequest): Promise<DeploymentTarget>;
  deleteConnectorTarget(id: string): Promise<void>;
  outboxCircuits(): Promise<OutboxCircuitList>;
  agentJobPosture(): Promise<AgentJobPosture>;
  bulkheadStats(): Promise<BulkheadStats>;
  connectorDelivery(id: string): Promise<ConnectorDelivery>;
  previewEphemeralCredential(input: EphemeralCredentialRequest): Promise<EphemeralCredentialPreview>;
  requestEphemeralCredential(input: EphemeralCredentialRequest): Promise<EphemeralCredential>;
  approveEphemeralCredential(id: string, input: EphemeralApprovalRequest): Promise<EphemeralApproval>;
  issuer(id: string): Promise<Issuer>;
  rotationRun(id: string): Promise<RotationRun>;
  mdmSCEPPolicy(id: string): Promise<MDMSCEPPolicy>;
  previewMDMSCEPPolicy(input: MDMSCEPPolicyRequest): Promise<MDMSCEPPolicyPreview>;
  previewMDMSCEPPolicyUpdate(id: string, input: MDMSCEPPolicyRequest): Promise<MDMSCEPPolicyPreview>;
  createMDMSCEPPolicy(input: MDMSCEPPolicyRequest): Promise<MDMSCEPPolicy>;
  updateMDMSCEPPolicy(id: string, input: MDMSCEPPolicyRequest): Promise<MDMSCEPPolicy>;
  deleteMDMSCEPPolicy(id: string): Promise<void>;
  previewMDMSCEPChallengeRotation(id: string): Promise<MDMSCEPChallengeRotationPreview>;
  rotateMDMSCEPChallenge(id: string): Promise<MDMSCEPChallengeRotated>;
  notification(id: string): Promise<Notification>;
  owner(id: string): Promise<Owner>;
  updateOwner(id: string, input: OwnerRequest): Promise<Owner>;
  deleteOwner(id: string): Promise<void>;
  platformDistribution(): Promise<PlatformDistributionStatus>;
  privacyArchiveAttestations(options?: { limit?: number; cursor?: string; subjectRef?: string }): Promise<PrivacyArchiveErasureAttestationList>;
  recordPrivacyArchiveAttestation(input: PrivacyArchiveErasureAttestationRequest): Promise<PrivacyArchiveErasureAttestation>;
  remediationOwnerActions(ownerId?: string): Promise<OwnerRemediationQueue>;
  runSecretRotation(input: SecretRotationRequest): Promise<SecretRotation>;
  createSecretRotationSchedule(input: SecretRotationScheduleRequest): Promise<SecretRotationSchedule>;
  secretRotationSchedules(options?: { limit?: number; cursor?: string }): Promise<SecretRotationScheduleList>;
  runDueSecretRotations(): Promise<SecretRotationDueRun>;
  aiStatus(): Promise<AIStatus>;
  aiQuery(input: AIQueryRequest): Promise<AIAnswer>;
  aiRCA(input: RCARequest): Promise<AIAnswer>;
  mcpTools(): Promise<MCPToolList>;
  callMCPTool(tool: string, input: MCPToolCall): Promise<MCPToolResult>;
  listCBOMAssets(): Promise<CBOMInventory>;
  previewCBOMScan(input: CBOMScanRequest): Promise<CBOMScanPreview>;
  startCBOMScan(input: CBOMScanRequest): Promise<CBOMScan>;
  pqcCampaigns(options?: { limit?: number; cursor?: string }): Promise<PQCMigrationCampaignList>;
  pqcCampaign(id: string): Promise<PQCMigrationCampaign>;
  createPQCCampaign(input: PQCMigrationCampaignStartRequest): Promise<PQCMigrationCampaign>;
  createCryptoReadinessAction(input: PQCMigrationCampaignStartRequest): Promise<PQCMigrationCampaign>;
  updatePQCCampaign(id: string, input: PQCMigrationCampaignUpdateRequest): Promise<PQCMigrationCampaign>;
  setPQCCampaignReadiness(id: string, input: PQCMigrationCampaignReadinessRequest): Promise<PQCMigrationCampaign>;
  dispositionPQCCampaignFinding(id: string, findingId: string, input: PQCMigrationFindingDispositionRequest): Promise<PQCMigrationCampaign>;
  closePQCCampaign(id: string, input?: PQCMigrationCampaignCloseRequest): Promise<PQCMigrationCampaign>;
  pqcCampaignEvidence(id: string): Promise<PQCMigrationCampaignClosure>;
  planPQCMigration(input: PQCMigrationRequest): Promise<PQCMigrationPlan>;
  startPQCMigration(input: PQCMigrationRequest): Promise<PQCMigrationRun>;
  getPQCMigrationProgress(runId: string): Promise<PQCMigrationProgress>;
  rollbackPQCMigration(runId: string, assetIds: string[], reason: string): Promise<PQCMigrationRollback>;
  issueBrokerAgentIdentity(input: BrokerAgentIdentityRequest): Promise<BrokerAgentIdentity>;
  workloadAttesterTrustSources(): Promise<WorkloadAttesterTrustSourceList>;
  createWorkloadAttesterTrustSource(input: WorkloadAttesterTrustSourceRequest): Promise<WorkloadAttesterTrustSource>;
  updateWorkloadAttesterTrustSource(id: string, input: WorkloadAttesterTrustSourceRequest): Promise<WorkloadAttesterTrustSource>;
  rotateWorkloadAttesterTrustSource(id: string, input: WorkloadAttesterTrustSourceRotateRequest): Promise<WorkloadAttesterTrustSourceRotated>;
  revokeWorkloadAttesterTrustSource(id: string, input: WorkloadAttesterTrustSourceRevokeRequest): Promise<WorkloadAttesterTrustSourceRevoked>;
  deleteWorkloadAttesterTrustSource(id: string): Promise<void>;
  issueAttestedSVID(input: AttestedSVIDRequest): Promise<AttestedSVID>;
  sshStatus(): Promise<SSHStatus>;
  sshFleet(): Promise<SSHFleetInventory>;
  recordSSHTrustRollout(input: SSHTrustRolloutRequest): Promise<SSHTrustRollout>;
  issueAttestedSSHUserCert(input: SSHAttestedUserCertRequest): Promise<SSHAttestedUserCert>;
  revokeSSHCertificate(input: SSHRevokeCertificateRequest): Promise<SSHStatus>;
  retireSSHHost(input: SSHHostRetireRequest): Promise<SSHHostRetirement>;
  protocolStatuses(): Promise<ProtocolRuntimeStatusList>;
  /** F22: effect-free, credential-free proof of the public EST CA, CSR-rules, and authentication surfaces. */
  estQualification(): Promise<ESTQualificationResult>;
  /** F23: effect-free proof of public SCEP capabilities, CA material, and the empty-message refusal wall. */
  scepQualification(): Promise<SCEPQualificationResult>;
  /** F55: server-owned, tenant-scoped CMP gate qualification with no PKIMessage, signer call, external call, or write. */
  cmpQualification(): Promise<CMPQualification>;
  /** F24: server-owned SPIFFE UDS posture without dialing the socket, requesting an SVID, calling the signer, or writing. */
  spiffeQualification(): Promise<SPIFFEQualification>;
  mdmSCEPStatus(): Promise<MDMSCEPStatus>;
  mdmSCEPPolicies(): Promise<MDMSCEPPolicyList>;
  secretPage(options?: { limit?: number; cursor?: string }): Promise<SecretMetaList>;
  createSecret(input: SecretCreateRequest): Promise<SecretMeta>;
  getSecret(name: string, options?: { resolve?: boolean }): Promise<SecretValue>;
  /** Read one secret as the granted workload credential, without falling back
   * to the browser's human session cookie. The caller must discard the value. */
  getSecretWithToken(name: string, token: string): Promise<SecretValue>;
  getSecretVersion(name: string, version: number): Promise<SecretValue>;
  recoverSecret(name: string, input: SecretRecoverRequest): Promise<SecretMeta>;
  rotateSecret(name: string, input: SecretRotateRequest): Promise<SecretMeta>;
  deleteSecret(name: string): Promise<void>;
  approveSecretChange(name: string, input: SecretApprovalRequest): Promise<SecretApproval>;
  secretRepositoryScanning(): Promise<SecretRepositoryScanPosture>;
  receiveSecretRepositoryWebhook(provider: string, input: SecretRepositoryWebhookRequest): Promise<SecretRepositoryWebhookReceipt>;
  thirdPartySecretScanning(): Promise<ThirdPartySecretScanPosture>;
  ingestThirdPartySecretScan(provider: string, input: ThirdPartySecretScanIngestRequest): Promise<ThirdPartySecretScanReceipt>;
  scanSecrets(input: SecretScanRequest): Promise<SecretScan>;
  syncSecret(input: SecretSyncRequest): Promise<SecretSync>;
  cloudSecretManagers(): Promise<CloudSecretManagerIntegration>;
  secretSyncTargets(): Promise<SecretSyncTargetCatalog>;
  secretSyncWorkloadIdentitySources(): Promise<SecretSyncWorkloadIdentitySourceList>;
  createSecretSyncWorkloadIdentitySource(input: SecretSyncWorkloadIdentitySourceRequest): Promise<SecretSyncWorkloadIdentitySource>;
  updateSecretSyncWorkloadIdentitySource(id: string, input: SecretSyncWorkloadIdentitySourceRequest): Promise<SecretSyncWorkloadIdentitySource>;
  deleteSecretSyncWorkloadIdentitySource(id: string): Promise<void>;
  kubernetesCSRSupport(): Promise<KubernetesCSRSupport>;
  kubernetesTrustBundles(): Promise<KubernetesTrustBundleDistribution>;
  kubernetesSecretOperator(): Promise<KubernetesSecretOperator>;
  secretWorkloadInjection(): Promise<SecretWorkloadInjection>;
  unvaultedSecrets(): Promise<UnvaultedSecretPosture>;
  issueDynamicLease(input: DynamicLeaseRequest): Promise<DynamicLease>;
  getDynamicLease(leaseId: string): Promise<DynamicLease>;
  renewDynamicLease(leaseId: string, input: DynamicLeaseRenewRequest): Promise<DynamicLease>;
  revokeDynamicLease(leaseId: string): Promise<DynamicLease>;
  issueEphemeralAPIKey(input: EphemeralAPIKeyRequest): Promise<EphemeralAPIKey>;
  issuePKISecret(input: PKISecretRequest): Promise<PKISecret>;
  machineLogin(input: MachineLoginRequest): Promise<MachineLoginResponse>;
  /** C-S2 (DA-02): secret-free projection of the configured machine-auth methods. */
  machineAuthMethods(): Promise<MachineAuthMethodList>;
  /** C-S3 (DA-02): the event-sourced issued-session ledger. */
  machineSessions(options?: { limit?: number }): Promise<MachineSessionList>;
  revokeMachineSession(id: string): Promise<MachineSession>;
  disableMachineAuthMethod(name: string): Promise<MachineAuthMethodOverride>;
  enableMachineAuthMethod(name: string): Promise<MachineAuthMethodOverride>;
  createShare(input: ShareRequest): Promise<ShareToken>;
  redeemShare(input: ShareRedeemRequest): Promise<ShareValue>;
  transitKeys(): Promise<TransitKeyList>;
  createTransitKey(input: TransitKeyRequest): Promise<TransitKey>;
  rotateTransitKey(input: TransitRotateRequest): Promise<TransitKey>;
  encryptTransit(input: TransitEncryptRequest): Promise<TransitCiphertext>;
  decryptTransit(input: TransitDecryptRequest): Promise<TransitPlaintext>;
  hmacTransit(input: TransitHMACRequest): Promise<TransitHMAC>;
  rewrapTransit(input: TransitRewrapRequest): Promise<TransitCiphertext>;
  signTransit(input: TransitSignRequest): Promise<TransitSignature>;
  verifyTransit(input: TransitVerifyRequest): Promise<TransitVerify>;
  notifications(options?: { limit?: number; cursor?: string; status?: Notification["status"] }): Promise<NotificationList>;
  notificationChannels(): Promise<NotificationChannelList>;
  createNotificationChannel(input: NotificationChannelRequest): Promise<NotificationChannel>;
  getNotificationChannel(id: string): Promise<NotificationChannel>;
  updateNotificationChannel(id: string, input: NotificationChannelRequest): Promise<NotificationChannel>;
  deleteNotificationChannel(id: string): Promise<void>;
  notificationRoutingPolicies(): Promise<NotificationRoutingPolicyList>;
  notificationRoutingPreview(options: {
    workspace?: string;
    owner_ref?: string;
    asset_ref?: string;
    severity?: "low" | "informational" | "warning" | "critical";
  }): Promise<NotificationRoutingPreview>;
  createNotificationRoutingPolicy(input: NotificationRoutingPolicyRequest): Promise<NotificationRoutingPolicy>;
  updateNotificationRoutingPolicy(id: string, input: NotificationRoutingPolicyRequest): Promise<NotificationRoutingPolicy>;
  deleteNotificationRoutingPolicy(id: string): Promise<void>;
  testNotificationChannel(id: string, input: NotificationChannelTestRequest): Promise<NotificationChannelTest>;
  markNotificationRead(id: string): Promise<Notification>;
  requeueNotification(id: string): Promise<Notification>;
}

async function allPendingApprovalRequests(): Promise<PendingApprovalRequest[]> {
  const items: PendingApprovalRequest[] = [];
  const seen = new Set<string>();
  let cursor = "";
  do {
    const query = new URLSearchParams();
    query.set("status", "pending");
    query.set("limit", "100");
    if (cursor) query.set("cursor", cursor);
    const page = await req<PendingApprovalRequestList>(`/api/v1/approval-requests?${query.toString()}`);
    items.push(...(page.items ?? []));
    const next = page.next_cursor ?? "";
    if (next && seen.has(next)) throw new Error("approval queue returned a repeated cursor");
    if (next) seen.add(next);
    cursor = next;
  } while (cursor);
  return items;
}

const liveApi: Api = {
  me: () => req<Me>("/auth/me"),
  authMethods: () => req<AuthMethods>("/auth/methods"),
  logout: () => req<void>("/auth/logout", { method: "POST" }),
  capabilities: () => req<CapabilityView>("/api/v1/capabilities"),
  editions: () => req<EditionsInfo>("/api/v1/editions"),
  enterpriseSupportStatus: () => req<EnterpriseSupportStatus>("/api/v1/support/enterprise"),
  managedOfferingStatus: () => req<ManagedOfferingStatus>("/api/v1/managed-offering/status"),
  scaleOrchestration: () => req<ScaleOrchestrationPlan>("/api/v1/scale/orchestration"),
  platformSystem: () => req<SystemReadout>("/api/v1/platform/system"),
  // J2: when the backup was last VERIFIED by re-hashing its artifacts, and what
  // the last restore drill established. Both, because they answer different
  // questions: verification says the bytes still match, a drill says they
  // reproduce state.
  drPosture: () => req<DRPosture>("/api/v1/platform/dr-posture"),
  authorityAgreement: () => req<AuthorityAgreementReport>("/api/v1/reconcile/agreement"),
  // No customer_id: the route serves the caller's own tenancy and refuses a
  // query naming anyone else, so sending one could only ever be a 403.
  usageEvidence: (periodStart, periodEnd) =>
    req<UsageEvidence>(`/api/v1/provider/usage-evidence?period_start=${encodeURIComponent(periodStart)}&period_end=${encodeURIComponent(periodEnd)}`),
  cryptoReadiness: () => req<CryptoReadiness>("/api/v1/graph/crypto-readiness"),
  cryptoReadinessExport: () => req<CryptoReadinessExport>("/api/v1/graph/crypto-readiness/export"),
  ownershipConflicts: () => req<OwnershipConflictList>("/api/v1/owners/ownership-conflicts"),
  // Through mutate(), not a hand-rolled req(): mutate is what attaches the
  // Idempotency-Key (AN-5). Rolling the request by hand skipped it, and a
  // retried resolve would have been a second decision on the same conflict
  // rather than a replay of the first.
  resolveOwnershipConflict: (id: string, resolution: string) =>
    mutate<unknown>("POST", `/api/v1/owners/ownership-conflicts/${encodeURIComponent(id)}/resolve`, {
      resolution,
    }),
  cmdbSchedule: () => req<CMDBReconcileSchedule>("/api/v1/owners/cmdb-schedule"),
  issuanceRequests: () => req<IssuanceRequestList>("/api/v1/issuance-requests"),
  previewIssuanceRequest: (input) => postRead<IssuanceRequestPreview>("/api/v1/issuance-requests/preview", input),
  createIssuanceRequest: (input) => mutate<IssuanceRequest>("POST", "/api/v1/issuance-requests", input),
  approveIssuanceRequest: (id) => mutate<IssuanceRequest>("POST", `/api/v1/issuance-requests/${encodeURIComponent(id)}/approve`),
  denyIssuanceRequest: (id, reason) => mutate<IssuanceRequest>("POST", `/api/v1/issuance-requests/${encodeURIComponent(id)}/deny`, { reason }),
  cancelIssuanceRequest: (id) => mutate<IssuanceRequest>("POST", `/api/v1/issuance-requests/${encodeURIComponent(id)}/cancel`),
  prepareIssuanceRequest: (id) =>
    mutate<IssuanceRequestPreparation>("POST", `/api/v1/issuance-requests/${encodeURIComponent(id)}/prepare`, undefined, `issuance-request-prepare:${id}`),
  completeIssuanceRequest: (id) =>
    mutate<IssuanceRequest>("POST", `/api/v1/issuance-requests/${encodeURIComponent(id)}/complete`, undefined, `issuance-request-complete:${id}`),
  ticketIntakeSchedule: (system = "servicenow") => req<TicketIntakeSchedule>(`/api/v1/issuance-requests/intake-schedule?system=${encodeURIComponent(system)}`),
  mdmDevices: () => req<MDMDeviceList>("/api/v1/mdm/devices"),
  mdmPollSchedules: () => req<MDMPollScheduleList>("/api/v1/mdm/poll-schedule"),
  mdmDeviceTrace: (mdm, id) => req<MDMDeviceTrace>(`/api/v1/mdm/${encodeURIComponent(mdm)}/devices/${encodeURIComponent(id)}/trace`),
  agentUpgradeCampaign: () => req<AgentUpgradeCampaign>("/api/v1/agents/upgrade-campaign"),
  tenantKeyDomain: () => req<TenantKeyDomainStatus>("/api/v1/platform/tenant-key-domain"),
  migrateTenantKeyDomain: (input) => mutate<TenantKeyDomainStatus>("POST", "/api/v1/platform/tenant-key-domain/migrate", input),
  sealTenantKeyDomain: () => mutate<TenantKeyDomainSealReceipt>("POST", "/api/v1/platform/tenant-key-domain/seal"),
  unsealTenantKeyDomain: () => mutate<TenantKeyDomainStatus>("POST", "/api/v1/platform/tenant-key-domain/unseal"),
  activeActiveIssuance: () => req<ActiveActiveIssuancePlan>("/api/v1/scale/ha-issuance"),
  provisionManagedTenant: (input) => mutate<ManagedTenant>("POST", "/api/v1/managed-offering/tenants", input),
  certificatePage: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    if (options?.expiringBefore) qs.set("expiring_before", options.expiringBefore);
    const suffix = qs.toString();
    return req<CertificatePage>(`/api/v1/certificates${suffix ? `?${suffix}` : ""}`);
  },
  certificates: () => api.certificatePage().then((r) => r.items ?? []),
  certificateHealth: () => req<CertificateHealthDashboard>("/api/v1/certificates/health"),
  crlDistributions: () => req<CRLDistributionList>("/api/v1/revocation/crls"),
  revocationCaches: () => req<RevocationCachePosture>("/api/v1/revocation/caches"),
  revocationHealth: () => req<RevocationHealth>("/api/v1/revocation/health"),
  rogueCertificates: () => req<RogueCertificatePosture>("/api/v1/revocation/rogue-certificates"),
  submitCertificateTransparency: (input) => mutate<CTSubmission>("POST", "/api/v1/revocation/ct-submissions", input),
  ctMonitoring: () => req<CTMonitoring>("/api/v1/discovery/ct-monitoring"),
  updateCTMonitoring: (input) => mutate<CTMonitoring>("PUT", "/api/v1/discovery/ct-monitoring", input),
  acmeARIPosture: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    const suffix = qs.toString();
    return req<ACMEARIPosture>(`/api/v1/acme/ari/posture${suffix ? `?${suffix}` : ""}`);
  },
  acmeOperatorPlan: () => req<ACMEOperatorPlan>("/api/v1/acme/operator-plan"),
  acmeEABCredentials: () => req<ACMEEABPosture>("/api/v1/acme/eab-credentials"),
  setACMEEABCredentialDisabled: (kid, disabled) =>
    mutate<ACMEEABCredential>("POST", `/api/v1/acme/eab-credentials/${encodeURIComponent(kid)}/${disabled ? "disable" : "enable"}`, {}),
  acmeDNS01Providers: () => req<ACMEDNS01ProviderCatalog>("/api/v1/acme/dns-01/providers"),
  acmeDNS01ProviderConfigs: () => req<ACMEDNS01ProviderConfigList>("/api/v1/acme/dns-01/provider-configs"),
  acmeUpstreamAuthorizations: () => req<ACMEUpstreamAuthorizationList>("/api/v1/acme/dns-01/upstream-authorizations"),
  endpointVerifications: () => req<EndpointVerificationList>("/api/v1/endpoints/verifications"),
  endpointKeyCustody: () => req<EndpointKeyCustodyList>("/api/v1/endpoints/key-custody"),
  enrollmentDiagnostics: () => req<EnrollmentDiagnosticList>("/api/v1/enrollment/diagnostics"),
  proveEnrollmentDiagnosticFixed: (id) =>
    mutate<EnrollmentDiagnosticVerification>("POST", `/api/v1/enrollment/diagnostics/${encodeURIComponent(id)}/prove-fixed`, {}),
  mdmSCEPStatus: () => req<MDMSCEPStatus>("/api/v1/mdm/scep/status"),
  mdmSCEPPolicies: () => req<MDMSCEPPolicyList>("/api/v1/mdm/scep/policies"),
  getCertificate: (id) => req<Certificate>(`/api/v1/certificates/${encodeURIComponent(id)}`),
  ingestCertificate: (input) => mutate<Certificate>("POST", "/api/v1/certificates", input),
  owners: () => req<{ items: Owner[] }>("/api/v1/owners").then((r) => r.items ?? []),
  createOwner: (input) => mutate<Owner>("POST", "/api/v1/owners", input),
  assignOwnership: (input) => mutate<OwnershipAssignmentResult>("POST", "/api/v1/ownership/assignments", input),
  attestOwner: (id) => mutate<Owner>("POST", `/api/v1/owners/${encodeURIComponent(id)}/attest`, {}),
  ownershipExceptions: (identityId) =>
    req<OwnershipExceptionList>(`/api/v1/identities/${encodeURIComponent(identityId)}/ownership-exceptions`).then((result) => result.items ?? []),
  grantOwnershipException: (identityId, input) =>
    mutate<OwnershipException>("POST", `/api/v1/identities/${encodeURIComponent(identityId)}/ownership-exceptions`, input),
  revokeOwnershipException: (identityId, exceptionId, input) =>
    mutate<OwnershipException>(
      "POST",
      `/api/v1/identities/${encodeURIComponent(identityId)}/ownership-exceptions/${encodeURIComponent(exceptionId)}/revoke`,
      input,
    ),
  issuers: () => req<{ items: Issuer[] }>("/api/v1/issuers").then((r) => r.items ?? []),
  issuerCapabilities: () => req<IssuerCapabilityMatrix>("/api/v1/issuers/capabilities"),
  createIssuer: (input) => mutate<Issuer>("POST", "/api/v1/issuers", input),
  protocolProfileStatus: () => req<ProtocolProfileStatus>("/api/v1/setup/protocols"),
  activateProtocolProfile: () => mutate<ProtocolProfileStatus>("POST", "/api/v1/setup/protocols/activate"),
  externalCAs: () => req<ExternalCAList>("/api/v1/external-cas").then((r) => r.items ?? []),
  issueExternalCA: (id, input) => mutate<ExternalCAIssuedCertificate>("POST", `/api/v1/external-cas/${encodeURIComponent(id)}/issue`, input),
  caDiscoveryInventory: () => req<CADiscovery>("/api/v1/ca/discovery"),
  identities: () => req<{ items: Identity[] }>("/api/v1/identities").then((r) => r.items ?? []),
  approvalRequests: allPendingApprovalRequests,
  approveApprovalRequest: (id, intentDigest) =>
    mutate<ApprovalRequestDecision>("POST", `/api/v1/approval-requests/${encodeURIComponent(id)}/approvals`, { intent_digest: intentDigest }),
  denyApprovalRequest: (id, intentDigest, reason) =>
    mutate<ApprovalRequestDecision>("POST", `/api/v1/approval-requests/${encodeURIComponent(id)}/denials`, {
      intent_digest: intentDigest,
      reason,
    }),
  nhiInventory: () => req<NHIInventory>("/api/v1/nhi/inventory"),
  nhiShadowPosture: () => req<NHIShadowPosture>("/api/v1/nhi/posture/shadow"),
  nhiPolicyCompliance: () => req<NHIPolicyCompliance>("/api/v1/nhi/policy/compliance"),
  nhiOverPrivilegePosture: () => req<NHIOverPrivilegePosture>("/api/v1/nhi/posture/overprivilege"),
  nhiStalePosture: () => req<NHIStalePosture>("/api/v1/nhi/posture/stale"),
  nhiStaticPosture: () => req<NHIStaticPosture>("/api/v1/nhi/posture/static-credentials"),
  nhiExposurePosture: () => req<NHIExposurePosture>("/api/v1/nhi/posture/exposure"),
  decommissionNHI: (input) => mutate<NHIDecommissionResponse>("POST", "/api/v1/nhi/decommission", input),
  ownershipAttribution: () => req<OwnershipAttribution>("/api/v1/ownership/attribution"),
  getIdentity: (id) => req<Identity>(`/api/v1/identities/${encodeURIComponent(id)}`),
  createIdentity: (input) => mutate<Identity>("POST", "/api/v1/identities", input),
  previewIdentityTransition: (id, to, reason, subjectCSRPEM) =>
    postRead<IdentityTransitionPreview>(`/api/v1/identities/${encodeURIComponent(id)}/transitions/preview`, {
      to,
      reason,
      ...(subjectCSRPEM ? { subject_csr_pem: subjectCSRPEM } : {}),
    }),
  transitionIdentity: (id, to, reason, subjectCSRPEM, idempotencyKey, expectedVersion) =>
    mutate<Identity>(
      "POST",
      `/api/v1/identities/${encodeURIComponent(id)}/transitions`,
      {
        to,
        reason,
        ...(subjectCSRPEM ? { subject_csr_pem: subjectCSRPEM } : {}),
        ...(expectedVersion == null ? {} : { expected_version: expectedVersion }),
      },
      idempotencyKey,
    ),
  approveIdentityAction: (id, input) => mutate<Approval>("POST", `/api/v1/identities/${encodeURIComponent(id)}/approvals`, input),
  issueCertificate: async (input) => {
    let ownerId = input.ownerId;
    if (!ownerId) {
      const owner = await api.createOwner({ kind: "workload", name: input.name });
      ownerId = owner.id;
    }
    const identity = await api.createIdentity(firstCertificateIdentityRequest(input, ownerId));
    return api.transitionIdentity(
      identity.id,
      "issued",
      input.subjectCSRPEM ? "first issuance via UI from an operator-supplied CSR" : "first issuance via UI",
      input.subjectCSRPEM,
    );
  },
  agents: () => req<{ agents: Agent[] }>("/api/v1/agents").then((r) => r.agents ?? []),
  agentPage: (options) => req<AgentList>(`/api/v1/agents${pageQueryString(options)}`),
  previewEnrollmentPlan: (input) =>
    req<EnrollmentPlanPreview>("/api/v1/agents/enrollment-tokens/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(enrollmentTokenRequest(input) ?? {}),
    }),
  createEnrollmentToken: (input) => mutate<EnrollmentToken>("POST", "/api/v1/agents/enrollment-tokens", enrollmentTokenRequest(input)),
  offboardAgent: (id, input) => mutate<AgentOffboardResponse>("POST", `/api/v1/agents/${encodeURIComponent(id)}/offboard`, input),
  discoveryCapabilities: () => req<DiscoveryCapabilityCatalog>("/api/v1/discovery/capabilities"),
  previewDiscoveryPlan: (input) => mutate<DiscoveryPlanPreview>("POST", "/api/v1/discovery/plans/preview", input),
  preflightDiscoverySource: (id) => req<DiscoveryPlanPreview>(`/api/v1/discovery/sources/${encodeURIComponent(id)}/preflight`),
  createDiscoverySegment: (input) => mutate<DiscoverySegment>("POST", "/api/v1/discovery/segments", input),
  discoverySources: (options) => req<DiscoverySourceList>(`/api/v1/discovery/sources${pageQueryString(options)}`),
  createDiscoverySource: (input) => mutate<DiscoverySource>("POST", "/api/v1/discovery/sources", input),
  discoverySchedules: (options) => req<DiscoveryScheduleList>(`/api/v1/discovery/schedules${pageQueryString(options)}`),
  createDiscoverySchedule: (input) => mutate<DiscoverySchedule>("POST", "/api/v1/discovery/schedules", input),
  discoveryRuns: (options) => req<DiscoveryRunList>(`/api/v1/discovery/runs${pageQueryString(options)}`),
  getDiscoveryRun: (id) => req<DiscoveryRun>(`/api/v1/discovery/runs/${encodeURIComponent(id)}`),
  startDiscoveryRun: (input) => mutate<DiscoveryRun>("POST", "/api/v1/discovery/runs", input),
  retryDiscoveryRun: (id) => mutate<DiscoveryRun>("POST", `/api/v1/discovery/runs/${encodeURIComponent(id)}/retry`),
  discoveryMonitoring: () => req<DiscoveryMonitoring>("/api/v1/discovery/monitoring"),
  adcsPosture: () => req<ADCSPosture>("/api/v1/posture/adcs"),
  adcsDrift: () => req<ADCSDriftHistory>("/api/v1/posture/adcs/drift"),
  adcsDatabases: () => req<ADCSDatabaseList>("/api/v1/adcs/ca-database"),
  discoveryCoverage: (options) => {
    const qs = new URLSearchParams();
    if (options?.class) qs.set("class", options.class);
    if (options?.sourceKind) qs.set("source_kind", options.sourceKind);
    const suffix = qs.toString();
    return req<DiscoveryCoverage>(`/api/v1/discovery/coverage${suffix ? `?${suffix}` : ""}`);
  },
  driftRemediation: () => req<DriftRemediation>("/api/v1/discovery/drift-remediation"),
  decideDriftRemediation: (id, input) =>
    mutate<DriftRemediationDecision>("POST", `/api/v1/discovery/drift-remediation/${encodeURIComponent(id)}/decision`, input),
  discoveryFindings: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    if (options?.runId) qs.set("run_id", options.runId);
    const suffix = qs.toString();
    return req<DiscoveryFindingList>(`/api/v1/discovery/findings${suffix ? `?${suffix}` : ""}`);
  },
  claimDiscoveryFinding: (id, input) => mutate<DiscoveryFinding>("POST", `/api/v1/discovery/findings/${encodeURIComponent(id)}/claim`, input),
  dismissDiscoveryFinding: (id, input) => mutate<DiscoveryFinding>("POST", `/api/v1/discovery/findings/${encodeURIComponent(id)}/dismiss`, input),
  connectorCatalog: (options) => req<ConnectorCatalog>("/api/v1/connectors/catalog" + pageQueryString(options)),
  connectorTargets: () => req<DeploymentTargetList>("/api/v1/connectors/targets"),
  createConnectorTarget: (input) => mutate<DeploymentTarget>("POST", "/api/v1/connectors/targets", input),
  createEndpointBinding: (input) => mutate<EndpointBinding>("POST", "/api/v1/lifecycle/endpoint-bindings", input),
  bindIdentityConnectorTarget: (id, input) => mutate<Identity>("POST", `/api/v1/identities/${encodeURIComponent(id)}/connector-target`, input),
  testConnectorTarget: (id) => mutate<ConnectorDelivery>("POST", `/api/v1/connectors/targets/${encodeURIComponent(id)}/test`),
  deployConnectorTarget: (id, input) => mutate<Identity>("POST", `/api/v1/connectors/targets/${encodeURIComponent(id)}/deploy`, input),
  rollbackConnectorTarget: (id, input) => mutate<ConnectorDelivery>("POST", `/api/v1/connectors/targets/${encodeURIComponent(id)}/rollback`, input),
  connectorDeliveries: (options) => req<ConnectorDeliveryList>(`/api/v1/connectors/deliveries${pageQueryString(options, options?.identityId)}`),
  rotationRuns: (options) => req<RotationRunList>(`/api/v1/lifecycle/rotation-runs${pageQueryString(options, options?.identityId)}`),
  executeIncident: (input) => mutate<IncidentExecution>("POST", "/api/v1/incidents/executions", input),
  dispatchResponseIntegrations: (input) => mutate<ResponseIntegrationDispatch>("POST", "/api/v1/incidents/response-integrations/dispatch", input),
  createServiceNowTicket: (input) => mutate<ITSMTicket>("POST", "/api/v1/itsm/servicenow/tickets", input),
  incidentExecutions: (options) => req<IncidentExecutionList>(`/api/v1/incidents/executions${pageQueryString(options, options?.identityId)}`),
  outboxReconciliationConflicts: () => req<OutboxReconciliationConflictList>("/api/v1/incidents/outbox-reconciliation-conflicts"),
  getIncidentExecution: (id) => req<IncidentExecution>(`/api/v1/incidents/executions/${encodeURIComponent(id)}`),
  remediationPlaybooks: () => req<RemediationPlaybookCatalog>("/api/v1/remediation/playbooks"),
  runRemediationPlaybook: (id, input) => mutate<RemediationPlaybookRun>("POST", `/api/v1/remediation/playbooks/${encodeURIComponent(id)}/runs`, input),
  remediationPlaybookRuns: (options) =>
    req<RemediationPlaybookRunList>(`/api/v1/remediation/playbook-runs${pageQueryString(options, options?.playbookId, "playbook_id")}`),
  getRemediationPlaybookRun: (id) => req<RemediationPlaybookRun>(`/api/v1/remediation/playbook-runs/${encodeURIComponent(id)}`),
  ownerRemediationActions: (options) =>
    req<OwnerRemediationQueue>(`/api/v1/remediation/owner-actions${options?.ownerId ? `?owner_id=${encodeURIComponent(options.ownerId)}` : ""}`),
  acceptOwnerRemediationAction: (id, input) => mutate<OwnerRemediationRun>("POST", `/api/v1/remediation/owner-actions/${encodeURIComponent(id)}/accept`, input),
  startFleetReissuance: (input) => mutate<FleetReissuanceRun>("POST", "/api/v1/incidents/fleet-reissuance-runs", input),
  fleetReissuanceRuns: (options) =>
    req<FleetReissuanceRunList>(`/api/v1/incidents/fleet-reissuance-runs${pageQueryString(options, options?.issuerId, "issuer_id")}`),
  getFleetReissuanceRun: (id) => req<FleetReissuanceRun>(`/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}`),
  pauseFleetReissuance: (id, input) => mutate<FleetReissuanceRun>("POST", `/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/pause`, input),
  resumeFleetReissuance: (id, input) => mutate<FleetReissuanceRun>("POST", `/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/resume`, input),
  rollbackFleetReissuance: (id, input) =>
    mutate<FleetReissuanceRun>("POST", `/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/rollback`, input),
  exportFleetReissuanceEvidence: (id) => req<FleetReissuanceEvidence>(`/api/v1/incidents/fleet-reissuance-runs/${encodeURIComponent(id)}/evidence`),
  breakglassIssue: (input) => mutate<BreakglassIssueResponse>("POST", "/api/v1/breakglass/issue", input),
  breakglassReconcile: (input) => mutate<BreakglassReconcileResponse>("POST", "/api/v1/breakglass/reconcile", input),
  signCode: (input) => mutate<CodeSigningSignature>("POST", "/api/v1/code-signing/sign", input),
  signCodeKeyless: (input) => mutate<CodeSigningSignature>("POST", "/api/v1/code-signing/keyless", input),
  codeSigningIdentities: () => req<CodeSigningIdentityList>("/api/v1/code-signing/identities"),
  risk: (options) => req<CredentialRiskList>(`/api/v1/risk/credentials${riskQueryString(options)}`).then((r) => r.credentials ?? []),
  contextualRiskPriorities: () => req<ContextualRiskPriorities>("/api/v1/risk/contextual-priorities"),
  profiles: () => req<{ items: Profile[] }>("/api/v1/profiles").then((r) => r.items ?? []),
  getProfileVersion: (name, version) => req<Profile>(`/api/v1/profiles/${encodeURIComponent(name)}/versions/${version}`),
  createProfile: (input) => mutate<ProfileMutationResult>("POST", "/api/v1/profiles", input),
  previewProfileRestore: (name, version, input) =>
    postRead<ProfileRestorePreview>(`/api/v1/profiles/${encodeURIComponent(name)}/versions/${version}/restore/preview`, input),
  restoreProfileVersion: (name, version, input) =>
    mutate<ProfileMutationResult>("POST", `/api/v1/profiles/${encodeURIComponent(name)}/versions/${version}/restore`, input),
  previewCACeremony: (input) => postRead<CACeremonyPlanPreview>("/api/v1/ca/ceremonies/preview", input),
  createCACeremony: (input) => mutate<CAKeyCeremony>("POST", "/api/v1/ca/ceremonies", input),
  approveCACeremony: (id) => mutate<CAKeyCeremony>("POST", `/api/v1/ca/ceremonies/${encodeURIComponent(id)}/approvals`),
  importOfflineRootCA: (input) => mutate<CAAuthority>("POST", "/api/v1/ca/authorities/offline-roots", input),
  importExistingCA: (input) => mutate<CAAuthority>("POST", "/api/v1/ca/authorities/imported", input),
  createOfflineIntermediateCSR: (id, input) =>
    mutate<CAIntermediateCSR>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/offline-intermediates/csr`, input),
  importOfflineIntermediateCA: (id, input) => mutate<CAAuthority>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/offline-intermediates`, input),
  previewCAAuthorityRotation: (id, input) => postRead<CAAuthorityRotationPlanPreview>(`/api/v1/ca/authorities/${encodeURIComponent(id)}/rotate/preview`, input),
  rotateCAAuthority: (id, input) => mutate<CAAuthorityRotation>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/rotate`, input),
  rekeyCAAuthority: (id, input) => mutate<CAAuthorityRotation>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/rekey`, input),
  managedKeyCustody: () => req<ManagedKeyCustodyPlan>("/api/v1/managed-keys/custody"),
  previewManagedKeyGeneration: (input) => postRead<ManagedKeyGenerationPreview>("/api/v1/managed-keys/preview", input),
  generateManagedKey: (input) => mutate<ManagedKey>("POST", "/api/v1/managed-keys", input),
  rotateManagedKey: (keyId) => mutate<ManagedKey>("POST", "/api/v1/managed-keys/rotate", { key_id: keyId }),
  revokeManagedKey: (keyId) => mutate<ManagedKey>("POST", "/api/v1/managed-keys/revoke", { key_id: keyId }),
  zeroizeManagedKey: (keyId) => mutate<ManagedKey>("POST", "/api/v1/managed-keys/zeroize", { key_id: keyId }),
  accessRoles: () => req<RoleList>("/api/v1/access/roles"),
  oidcMappingStatus: () => req<OIDCMappingStatus>("/api/v1/access/oidc-mapping"),
  members: (options) => req<MemberList>(`/api/v1/access/members${accessMembersQueryString(options)}`),
  upsertMember: (subject, input) => mutate<Member>("PUT", `/api/v1/access/members/${encodeURIComponent(subject)}`, input),
  offboardMember: (subject, input) => mutate<OffboardMemberResponse>("POST", `/api/v1/access/members/${encodeURIComponent(subject)}/offboard`, input),
  accessChangeRequests: (options) => req<AccessChangeRequestList>(`/api/v1/access/requests${pageQueryString(options)}`),
  createAccessChangeRequest: (input) => mutate<AccessChangeRequest>("POST", "/api/v1/access/requests", input),
  getAccessChangeRequest: (id) => req<AccessChangeRequest>(`/api/v1/access/requests/${encodeURIComponent(id)}`),
  decideAccessChangeRequest: (id, input) => mutate<AccessChangeRequest>("POST", `/api/v1/access/requests/${encodeURIComponent(id)}/decisions`, input),
  nhiReviewCampaigns: (options) => req<NHIReviewCampaignList>(`/api/v1/access/reviews${pageQueryString(options)}`),
  startNHIReviewCampaign: (input) => mutate<NHIReviewCampaign>("POST", "/api/v1/access/reviews", input),
  getNHIReviewCampaign: (id) => req<NHIReviewCampaign>(`/api/v1/access/reviews/${encodeURIComponent(id)}`),
  decideNHIReviewItem: (campaignId, itemId, input) =>
    mutate<NHIReviewCampaign>("POST", `/api/v1/access/reviews/${encodeURIComponent(campaignId)}/items/${encodeURIComponent(itemId)}/decision`, input),
  apiTokens: (options) => req<APITokenList>(`/api/v1/access/api-tokens${apiTokensQueryString(options)}`),
  createAPIToken: (input) => mutate<APITokenCreateResponse>("POST", "/api/v1/access/api-tokens", input),
  revokeAPIToken: (id) => mutate<void>("DELETE", `/api/v1/access/api-tokens/${encodeURIComponent(id)}`),
  erasePrivacySubject: (input) => mutate<PrivacySubjectErasure>("POST", "/api/v1/privacy/subject-erasures", input),
  privacySubjectErasures: (options) => req<PrivacySubjectErasureList>(`/api/v1/privacy/subject-erasures${pageQueryString(options)}`),
  exportPrivacySubject: (input) => postRead<PrivacySubjectExport>("/api/v1/privacy/subject-exports", input),
  enforcePrivacyRetention: () => mutate<PrivacyRetentionRun>("POST", "/api/v1/privacy/retention-runs"),
  privacyRetentionRuns: (options) => req<PrivacyRetentionRunList>(`/api/v1/privacy/retention-runs${pageQueryString(options)}`),
  privacyCatalog: () => req<PrivacyCatalog>("/api/v1/privacy/catalog"),
  auditEvents: (options) => req<{ events: AuditEvent[] }>(`/api/v1/audit/events${auditQueryString(options)}`).then((r) => r.events ?? []),
  exportAudit: (options) => req<AuditBundle>(`/api/v1/audit/export${auditQueryString(options)}`),
  auditFeeds: () => req<AuditFeedList>("/api/v1/audit/feeds"),
  previewAuditFeed: (id, input) => postRead<AuditFeedPreview>(`/api/v1/audit/feeds/${encodeURIComponent(id)}/preview`, input),
  putAuditFeed: (id, input) => mutate<AuditFeed>("PUT", `/api/v1/audit/feeds/${encodeURIComponent(id)}`, input),
  downloadAuditExport: (options, format) => downloadAuditExportImpl(options, format),
  complianceEvidencePack: (framework) => req<ComplianceEvidencePack>(`/api/v1/compliance/evidence-packs/${encodeURIComponent(framework)}`),
  complianceInventoryReport: () => req<ComplianceInventoryReport>("/api/v1/compliance/inventory-report"),
  nhiComplianceReport: () => req<NHIComplianceReport>("/api/v1/compliance/nhi-report"),
  complianceReportSchedules: (options) => req<ComplianceReportScheduleList>(`/api/v1/compliance/report-schedules${pageQueryString(options)}`),
  createComplianceReportSchedule: (input) => mutate<ComplianceReportSchedule>("POST", "/api/v1/compliance/report-schedules", input),
  policyVersions: () => req<PolicyVersionList>("/api/v1/policy/versions"),
  createPolicyVersion: (input) => mutate<PolicyVersion>("POST", "/api/v1/policy/versions", input),
  activatePolicyVersion: (id, input) => mutate<PolicyVersion>("POST", `/api/v1/policy/versions/${encodeURIComponent(id)}/activate`, input),
  rollbackPolicyVersion: (id, input) => mutate<PolicyVersion>("POST", `/api/v1/policy/versions/${encodeURIComponent(id)}/rollback`, input),
  policyDryRun: (input) => mutate<PolicyDryRun>("POST", "/api/v1/policy/dry-run", input),
  graph: () => req<GraphResponse>("/api/v1/graph"),
  graphReachable: estate.graphReachable,
  graphBlastRadius: estate.graphBlastRadius,
  graphTrustStores: estate.graphTrustStores,
  unownedIdentities: estate.unownedIdentities,
  caRetirementChecklist: estate.caRetirementChecklist,
  retireCAKey: estate.retireCAKey,
  assessMigration: estate.assessMigration,
  startMigrationRun: estate.startMigrationRun,
  migrationRuns: estate.migrationRuns,
  migrationRun: estate.migrationRun,
  pauseMigrationRun: estate.pauseMigrationRun,
  resumeMigrationRun: estate.resumeMigrationRun,
  rollbackMigrationRun: estate.rollbackMigrationRun,
  graphQuery: (query) => postRead<GraphQueryResult>("/api/v1/graph/query", { query }),
  // CLI parity (S3.3): console flows for every remaining core API operation.
  pamSessions: (options) => req<PAMSessionList>(`/api/v1/access/sessions${pageQueryString(options)}`),
  pamSession: (id) => req<PAMSession>(`/api/v1/access/sessions/${encodeURIComponent(id)}`),
  openPAMSession: (input) => mutate<PAMSession>("POST", "/api/v1/access/sessions", input),
  acmeDNS01ProviderConfig: (id) => req<ACMEDNS01ProviderConfig>(`/api/v1/acme/dns-01/provider-configs/${encodeURIComponent(id)}`),
  updateACMEDNS01ProviderConfig: (id, input) => mutate<ACMEDNS01ProviderConfig>("PUT", `/api/v1/acme/dns-01/provider-configs/${encodeURIComponent(id)}`, input),
  deleteACMEDNS01ProviderConfig: (id) => mutate<void>("DELETE", `/api/v1/acme/dns-01/provider-configs/${encodeURIComponent(id)}`),
  acmeDNS01Preflight: (input) => mutate<ACMEDNS01Preflight>("POST", "/api/v1/acme/dns-01/preflight", input),
  revokeAgentCert: (id, input) => mutate<AgentCertRevocation>("POST", `/api/v1/agents/${encodeURIComponent(id)}/cert-revocations`, input),
  caCeremony: (id) => req<CAKeyCeremony>(`/api/v1/ca/ceremonies/${encodeURIComponent(id)}`),
  caAuthorities: () => req<CAAuthorityList>("/api/v1/ca/authorities"),
  edgeSegmentPolicies: () => req<EdgeSegmentPolicyList>("/api/v1/edge/segments"),
  edgeDelegations: () => req<EdgeDelegationList>("/api/v1/edge/delegations"),
  edgeDelegation: (id) => req<EdgeDelegationDetail>(`/api/v1/edge/delegations/${encodeURIComponent(id)}`),
  createRootCA: (input) => mutate<CAAuthority>("POST", "/api/v1/ca/authorities/roots", input),
  createIntermediateCA: (input) => mutate<CAAuthority>("POST", "/api/v1/ca/authorities/intermediates", input),
  signIntermediateCSR: (id, input) => mutate<CAIssuedIntermediate>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/intermediates/csr`, input),
  issueLeafFromCA: (id, input) => mutate<CAIssuedLeaf>("POST", `/api/v1/ca/authorities/${encodeURIComponent(id)}/issue`, input),
  bulkRevokeCertificates: (input) => mutate<BulkRevokeResult>("POST", "/api/v1/certificates/bulk-revoke", input),
  bulkRevokeIdentities: (input) => mutate<BulkRevokeResult>("POST", "/api/v1/identities/bulk-revoke", input),
  connectorTarget: (id) => req<DeploymentTarget>(`/api/v1/connectors/targets/${encodeURIComponent(id)}`),
  updateConnectorTarget: (id, input) => mutate<DeploymentTarget>("PUT", `/api/v1/connectors/targets/${encodeURIComponent(id)}`, input),
  deleteConnectorTarget: (id) => mutate<void>("DELETE", `/api/v1/connectors/targets/${encodeURIComponent(id)}`),
  outboxCircuits: () => req<OutboxCircuitList>("/api/v1/connectors/outbox-circuits"),
  agentJobPosture: () => req<AgentJobPosture>("/api/v1/operations/jobs"),
  bulkheadStats: () => req<BulkheadStats>("/api/v1/operations/bulkheads"),
  connectorDelivery: (id) => req<ConnectorDelivery>(`/api/v1/connectors/deliveries/${encodeURIComponent(id)}`),
  previewEphemeralCredential: (input) => postRead<EphemeralCredentialPreview>("/api/v1/ephemeral/preview", input),
  requestEphemeralCredential: (input) => mutate<EphemeralCredential>("POST", "/api/v1/ephemeral", input),
  approveEphemeralCredential: (id, input) => mutate<EphemeralApproval>("POST", `/api/v1/ephemeral/${encodeURIComponent(id)}/approvals`, input),
  issuer: (id) => req<Issuer>(`/api/v1/issuers/${encodeURIComponent(id)}`),
  rotationRun: (id) => req<RotationRun>(`/api/v1/lifecycle/rotation-runs/${encodeURIComponent(id)}`),
  mdmSCEPPolicy: (id) => req<MDMSCEPPolicy>(`/api/v1/mdm/scep/policies/${encodeURIComponent(id)}`),
  previewMDMSCEPPolicy: (input) => postRead<MDMSCEPPolicyPreview>("/api/v1/mdm/scep/policies/preview", input),
  previewMDMSCEPPolicyUpdate: (id, input) => postRead<MDMSCEPPolicyPreview>(`/api/v1/mdm/scep/policies/${encodeURIComponent(id)}/preview`, input),
  createMDMSCEPPolicy: (input) => mutate<MDMSCEPPolicy>("POST", "/api/v1/mdm/scep/policies", input),
  updateMDMSCEPPolicy: (id, input) => mutate<MDMSCEPPolicy>("PUT", `/api/v1/mdm/scep/policies/${encodeURIComponent(id)}`, input),
  deleteMDMSCEPPolicy: (id) => mutate<void>("DELETE", `/api/v1/mdm/scep/policies/${encodeURIComponent(id)}`),
  previewMDMSCEPChallengeRotation: (id) =>
    postRead<MDMSCEPChallengeRotationPreview>(`/api/v1/mdm/scep/policies/${encodeURIComponent(id)}/rotate-challenge/preview`),
  rotateMDMSCEPChallenge: (id) => mutate<MDMSCEPChallengeRotated>("POST", `/api/v1/mdm/scep/policies/${encodeURIComponent(id)}/rotate-challenge`),
  notification: (id) => req<Notification>(`/api/v1/notifications/${encodeURIComponent(id)}`),
  owner: (id) => req<Owner>(`/api/v1/owners/${encodeURIComponent(id)}`),
  updateOwner: (id, input) => mutate<Owner>("PUT", `/api/v1/owners/${encodeURIComponent(id)}`, input),
  deleteOwner: (id) => mutate<void>("DELETE", `/api/v1/owners/${encodeURIComponent(id)}`),
  platformDistribution: () => req<PlatformDistributionStatus>("/api/v1/platform/distribution"),
  privacyArchiveAttestations: (options) =>
    req<PrivacyArchiveErasureAttestationList>(`/api/v1/privacy/archive-erasure-attestations${pageQueryString(options, options?.subjectRef, "subject_ref")}`),
  recordPrivacyArchiveAttestation: (input) => mutate<PrivacyArchiveErasureAttestation>("POST", "/api/v1/privacy/archive-erasure-attestations", input),
  remediationOwnerActions: (ownerId) =>
    req<OwnerRemediationQueue>(`/api/v1/remediation/owner-actions${ownerId ? `?owner_id=${encodeURIComponent(ownerId)}` : ""}`),
  runSecretRotation: (input) => mutate<SecretRotation>("POST", "/api/v1/secrets/rotations", input),
  createSecretRotationSchedule: (input) => mutate<SecretRotationSchedule>("POST", "/api/v1/secrets/rotation-schedules", input),
  secretRotationSchedules: (options) => req<SecretRotationScheduleList>(`/api/v1/secrets/rotation-schedules${pageQueryString(options)}`),
  runDueSecretRotations: () => mutate<SecretRotationDueRun>("POST", "/api/v1/secrets/rotation-schedules/run-due"),
  aiStatus: () => req<AIStatus>("/api/v1/ai/status"),
  aiQuery: (input) => postRead<AIAnswer>("/api/v1/ai/query", input),
  aiRCA: (input) => postRead<AIAnswer>("/api/v1/ai/rca", input),
  mcpTools: () => req<MCPToolList>("/api/v1/mcp/tools"),
  callMCPTool: (tool, input) => postRead<MCPToolResult>(`/api/v1/mcp/tools/${encodeURIComponent(tool)}`, input),
  listCBOMAssets: () => req<CBOMInventory>("/api/v1/cbom/assets"),
  previewCBOMScan: (input) => postRead<CBOMScanPreview>("/api/v1/cbom/scans/preview", input),
  startCBOMScan: (input) => mutate<CBOMScan>("POST", "/api/v1/cbom/scans", input),
  pqcCampaigns: (options) => req<PQCMigrationCampaignList>(`/api/v1/pqc/campaigns${pageQueryString(options)}`),
  pqcCampaign: (id) => req<PQCMigrationCampaign>(`/api/v1/pqc/campaigns/${encodeURIComponent(id)}`),
  createPQCCampaign: (input) => mutate<PQCMigrationCampaign>("POST", "/api/v1/pqc/campaigns", input),
  createCryptoReadinessAction: (input) => mutate<PQCMigrationCampaign>("POST", "/api/v1/graph/crypto-readiness/actions", input),
  updatePQCCampaign: (id, input) => mutate<PQCMigrationCampaign>("PUT", `/api/v1/pqc/campaigns/${encodeURIComponent(id)}`, input),
  setPQCCampaignReadiness: (id, input) => mutate<PQCMigrationCampaign>("POST", `/api/v1/pqc/campaigns/${encodeURIComponent(id)}/readiness`, input),
  dispositionPQCCampaignFinding: (id, findingId, input) =>
    mutate<PQCMigrationCampaign>("POST", `/api/v1/pqc/campaigns/${encodeURIComponent(id)}/findings/${encodeURIComponent(findingId)}/disposition`, input),
  closePQCCampaign: (id, input) => mutate<PQCMigrationCampaign>("POST", `/api/v1/pqc/campaigns/${encodeURIComponent(id)}/close`, input),
  pqcCampaignEvidence: (id) => req<PQCMigrationCampaignClosure>(`/api/v1/pqc/campaigns/${encodeURIComponent(id)}/evidence`),
  planPQCMigration: (input) => postRead<PQCMigrationPlan>("/api/v1/pqc/migrations/plan", input),
  startPQCMigration: (input) => mutate<PQCMigrationRun>("POST", "/api/v1/pqc/migrations", input),
  getPQCMigrationProgress: (runId) => req<PQCMigrationProgress>(`/api/v1/pqc/migrations/${encodeURIComponent(runId)}`),
  rollbackPQCMigration: (runId, assetIds, reason) =>
    mutate<PQCMigrationRollback>("POST", `/api/v1/pqc/migrations/${encodeURIComponent(runId)}/rollback`, {
      asset_ids: assetIds,
      reason,
    }),
  issueBrokerAgentIdentity: (input) => mutate<BrokerAgentIdentity>("POST", "/api/v1/broker/agent-identities", input),
  workloadAttesterTrustSources: () => req<WorkloadAttesterTrustSourceList>("/api/v1/workloads/attester-trust-sources"),
  createWorkloadAttesterTrustSource: (input) => mutate<WorkloadAttesterTrustSource>("POST", "/api/v1/workloads/attester-trust-sources", input),
  updateWorkloadAttesterTrustSource: (id, input) =>
    mutate<WorkloadAttesterTrustSource>("PUT", `/api/v1/workloads/attester-trust-sources/${encodeURIComponent(id)}`, input),
  rotateWorkloadAttesterTrustSource: (id, input) =>
    mutate<WorkloadAttesterTrustSourceRotated>("POST", `/api/v1/workloads/attester-trust-sources/${encodeURIComponent(id)}/rotate`, input),
  revokeWorkloadAttesterTrustSource: (id, input) =>
    mutate<WorkloadAttesterTrustSourceRevoked>("POST", `/api/v1/workloads/attester-trust-sources/${encodeURIComponent(id)}/revoke`, input),
  deleteWorkloadAttesterTrustSource: (id) => mutate<void>("DELETE", `/api/v1/workloads/attester-trust-sources/${encodeURIComponent(id)}`),
  issueAttestedSVID: (input) => mutate<AttestedSVID>("POST", "/api/v1/workloads/attested-issuance", input),
  sshStatus: () => req<SSHStatus>("/api/v1/ssh/status"),
  sshFleet: () => req<SSHFleetInventory>("/api/v1/ssh/fleet"),
  recordSSHTrustRollout: (input) => mutate<SSHTrustRollout>("POST", "/api/v1/ssh/trust-rollouts", input),
  issueAttestedSSHUserCert: (input) => mutate<SSHAttestedUserCert>("POST", "/api/v1/ssh/attested-user-certs", input),
  revokeSSHCertificate: (input) => mutate<SSHStatus>("POST", "/api/v1/ssh/certificates/revoke", input),
  retireSSHHost: (input) => mutate<SSHHostRetirement>("POST", "/api/v1/ssh/hosts/retire", input),
  protocolStatuses: async () => ({
    source: "public_responder_probe",
    checked_at: new Date().toISOString(),
    items: await Promise.all(protocolStatusProbes.map((spec) => protocolProbe(spec))),
  }),
  estQualification,
  scepQualification,
  cmpQualification: () => postRead<CMPQualification>("/api/v1/protocols/cmp/qualification"),
  spiffeQualification: () => postRead<SPIFFEQualification>("/api/v1/protocols/spiffe/qualification"),
  secretPage: (options) => {
    const qs = new URLSearchParams();
    if (options?.limit != null) qs.set("limit", String(options.limit));
    if (options?.cursor) qs.set("cursor", options.cursor);
    const suffix = qs.toString();
    return req<SecretMetaList>(`/api/v1/secrets/store${suffix ? `?${suffix}` : ""}`);
  },
  createSecret: (input) => mutate<SecretMeta>("POST", "/api/v1/secrets/store", input),
  getSecret: (name, options) => {
    const qs = new URLSearchParams();
    if (options?.resolve) qs.set("resolve", "true");
    const suffix = qs.toString();
    return req<SecretValue>(`/api/v1/secrets/store/${encodeURIComponent(name)}${suffix ? `?${suffix}` : ""}`);
  },
  getSecretWithToken: (name, token) =>
    req<SecretValue>(`/api/v1/secrets/store/${encodeURIComponent(name)}`, {
      credentials: "omit",
      headers: { Authorization: `Bearer ${token}` },
    }),
  getSecretVersion: (name, version) =>
    req<SecretValue>(`/api/v1/secrets/store/history/${encodeURIComponent(name)}?version=${encodeURIComponent(String(version))}`),
  recoverSecret: (name, input) => mutate<SecretMeta>("POST", `/api/v1/secrets/store/recover/${encodeURIComponent(name)}`, input),
  rotateSecret: (name, input) => mutate<SecretMeta>("PUT", `/api/v1/secrets/store/${encodeURIComponent(name)}`, input),
  deleteSecret: (name) => mutate<void>("DELETE", `/api/v1/secrets/store/${encodeURIComponent(name)}`),
  approveSecretChange: (name, input) => mutate<SecretApproval>("POST", `/api/v1/secrets/store/approvals/${encodeURIComponent(name)}`, input),
  secretRepositoryScanning: () => req<SecretRepositoryScanPosture>("/api/v1/secrets/scans/repositories"),
  receiveSecretRepositoryWebhook: (provider, input) =>
    mutate<SecretRepositoryWebhookReceipt>("POST", `/api/v1/secrets/scans/repositories/${encodeURIComponent(provider)}/webhook`, input),
  thirdPartySecretScanning: () => req<ThirdPartySecretScanPosture>("/api/v1/secrets/scans/third-party"),
  ingestThirdPartySecretScan: (provider, input) =>
    mutate<ThirdPartySecretScanReceipt>("POST", `/api/v1/secrets/scans/third-party/${encodeURIComponent(provider)}/ingest`, input),
  scanSecrets: (input) => mutate<SecretScan>("POST", "/api/v1/secrets/scans", input),
  syncSecret: (input) => mutate<SecretSync>("POST", "/api/v1/secrets/syncs", input),
  cloudSecretManagers: () => req<CloudSecretManagerIntegration>("/api/v1/secrets/cloud-secret-managers"),
  secretSyncTargets: () => req<SecretSyncTargetCatalog>("/api/v1/secrets/syncs/targets"),
  secretSyncWorkloadIdentitySources: () => req<SecretSyncWorkloadIdentitySourceList>("/api/v1/secrets/syncs/workload-identity-sources"),
  createSecretSyncWorkloadIdentitySource: (input) => mutate<SecretSyncWorkloadIdentitySource>("POST", "/api/v1/secrets/syncs/workload-identity-sources", input),
  updateSecretSyncWorkloadIdentitySource: (id, input) =>
    mutate<SecretSyncWorkloadIdentitySource>("PUT", `/api/v1/secrets/syncs/workload-identity-sources/${encodeURIComponent(id)}`, input),
  deleteSecretSyncWorkloadIdentitySource: (id) => mutate<void>("DELETE", `/api/v1/secrets/syncs/workload-identity-sources/${encodeURIComponent(id)}`),
  kubernetesCSRSupport: () => req<KubernetesCSRSupport>("/api/v1/kubernetes/certificate-signing-requests"),
  kubernetesTrustBundles: () => req<KubernetesTrustBundleDistribution>("/api/v1/kubernetes/trust-bundles"),
  kubernetesSecretOperator: () => req<KubernetesSecretOperator>("/api/v1/secrets/kubernetes-operator"),
  secretWorkloadInjection: () => req<SecretWorkloadInjection>("/api/v1/secrets/workload-injection"),
  unvaultedSecrets: () => req<UnvaultedSecretPosture>("/api/v1/secrets/unvaulted"),
  issueDynamicLease: (input) => mutate<DynamicLease>("POST", "/api/v1/secrets/leases", input),
  getDynamicLease: (leaseId) => req<DynamicLease>(`/api/v1/secrets/leases/${encodeURIComponent(leaseId)}`),
  renewDynamicLease: (leaseId, input) => mutate<DynamicLease>("POST", `/api/v1/secrets/leases/${encodeURIComponent(leaseId)}/renew`, input),
  revokeDynamicLease: (leaseId) => mutate<DynamicLease>("POST", `/api/v1/secrets/leases/${encodeURIComponent(leaseId)}/revoke`),
  issueEphemeralAPIKey: (input) => mutate<EphemeralAPIKey>("POST", "/api/v1/ephemeral/api-keys", input),
  issuePKISecret: (input) => mutate<PKISecret>("POST", "/api/v1/secrets/pki", input),
  machineLogin: (input) => mutate<MachineLoginResponse>("POST", "/api/v1/secrets/login", input),
  machineAuthMethods: () => req<MachineAuthMethodList>("/api/v1/secrets/auth-methods"),
  machineSessions: (options) => req<MachineSessionList>(`/api/v1/secrets/sessions${options?.limit ? `?limit=${options.limit}` : ""}`),
  revokeMachineSession: (id) => mutate<MachineSession>("POST", `/api/v1/secrets/sessions/${encodeURIComponent(id)}/revoke`),
  disableMachineAuthMethod: (name) => mutate<MachineAuthMethodOverride>("POST", `/api/v1/secrets/auth-methods/${encodeURIComponent(name)}/disable`),
  enableMachineAuthMethod: (name) => mutate<MachineAuthMethodOverride>("POST", `/api/v1/secrets/auth-methods/${encodeURIComponent(name)}/enable`),
  createShare: (input) => mutate<ShareToken>("POST", "/api/v1/secrets/shares", input),
  redeemShare: (input) => mutate<ShareValue>("POST", "/api/v1/secrets/shares/redeem", input),
  transitKeys: () => req<TransitKeyList>("/api/v1/transit/keys"),
  createTransitKey: (input) => mutate<TransitKey>("POST", "/api/v1/transit/keys", input),
  rotateTransitKey: (input) => mutate<TransitKey>("POST", "/api/v1/transit/keys/rotate", input),
  encryptTransit: (input) => mutate<TransitCiphertext>("POST", "/api/v1/transit/encrypt", input),
  decryptTransit: (input) => mutate<TransitPlaintext>("POST", "/api/v1/transit/decrypt", input),
  hmacTransit: (input) => mutate<TransitHMAC>("POST", "/api/v1/transit/hmac", input),
  rewrapTransit: (input) => mutate<TransitCiphertext>("POST", "/api/v1/transit/rewrap", input),
  signTransit: (input) => mutate<TransitSignature>("POST", "/api/v1/transit/sign", input),
  verifyTransit: (input) => mutate<TransitVerify>("POST", "/api/v1/transit/verify", input),
  notifications: (options) => req<NotificationList>(`/api/v1/notifications${notificationQueryString(options)}`),
  notificationChannels: () => req<NotificationChannelList>("/api/v1/notification-channels"),
  createNotificationChannel: (input) => mutate<NotificationChannel>("POST", "/api/v1/notification-channels", input),
  getNotificationChannel: (id) => req<NotificationChannel>(`/api/v1/notification-channels/${encodeURIComponent(id)}`),
  updateNotificationChannel: (id, input) => mutate<NotificationChannel>("PUT", `/api/v1/notification-channels/${encodeURIComponent(id)}`, input),
  deleteNotificationChannel: (id) => mutate<void>("DELETE", `/api/v1/notification-channels/${encodeURIComponent(id)}`),
  notificationRoutingPolicies: () => req<NotificationRoutingPolicyList>("/api/v1/notification-routing-policies"),
  notificationRoutingPreview: (options) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options)) if (value) query.set(key, value);
    return req<NotificationRoutingPreview>(`/api/v1/notification-routing-preview?${query.toString()}`);
  },
  createNotificationRoutingPolicy: (input) => mutate<NotificationRoutingPolicy>("POST", "/api/v1/notification-routing-policies", input),
  updateNotificationRoutingPolicy: (id, input) =>
    mutate<NotificationRoutingPolicy>("PUT", `/api/v1/notification-routing-policies/${encodeURIComponent(id)}`, input),
  deleteNotificationRoutingPolicy: (id) => mutate<void>("DELETE", `/api/v1/notification-routing-policies/${encodeURIComponent(id)}`),
  testNotificationChannel: (id, input) => mutate<NotificationChannelTest>("POST", `/api/v1/notification-channels/${encodeURIComponent(id)}/test`, input),
  markNotificationRead: (id) => mutate<Notification>("POST", `/api/v1/notifications/${encodeURIComponent(id)}/read`),
  requeueNotification: (id) => mutate<Notification>("POST", `/api/v1/notifications/${encodeURIComponent(id)}/requeue`),
};

/** One stable wrapper per API method keeps normal query function identities
 * unchanged. In preview, only methods explicitly present in previewData can
 * resolve; mutations and unmodeled reads fail before liveApi can reach req or
 * fetch. */
function createPreviewAwareApi(implementation: Api): Api {
  const wrapped: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  for (const [method, candidate] of Object.entries(implementation)) {
    const invoke = candidate as (...args: unknown[]) => Promise<unknown>;
    wrapped[method] = (...args: unknown[]) => (previewTransportIsolated ? previewResponse(method) : invoke(...args));
  }
  return wrapped as unknown as Api;
}

export const api: Api = createPreviewAwareApi(liveApi);

/** loginURL is where the browser is sent to begin the OIDC flow. */
export const loginURL = "/auth/login";

function auditQueryString(options?: AuditQuery): string {
  const qs = new URLSearchParams();
  qs.set("limit", String(options?.limit ?? 50));
  if (options?.type) qs.set("type", options.type);
  if (options?.since) qs.set("since", options.since);
  if (options?.until) qs.set("until", options.until);
  if (options?.asOf != null) qs.set("as_of", String(options.asOf));
  if (options?.q) qs.set("q", options.q);
  return `?${qs.toString()}`;
}

function riskQueryString(options?: RiskQuery): string {
  const qs = new URLSearchParams();
  if (options?.sort) qs.set("sort", options.sort);
  if (options?.minScore != null) qs.set("min_score", String(options.minScore));
  if (options?.privilege != null) qs.set("privilege", String(options.privilege));
  if (options?.owner) qs.set("owner", options.owner);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function accessMembersQueryString(options?: { limit?: number; cursor?: string; includeOffboarded?: boolean }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.includeOffboarded) qs.set("include_offboarded", "true");
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function apiTokensQueryString(options?: { limit?: number; cursor?: string; subject?: string; includeRevoked?: boolean }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.subject) qs.set("subject", options.subject);
  if (options?.includeRevoked) qs.set("include_revoked", "true");
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function pageQueryString(options?: { limit?: number; cursor?: string }, scopedId?: string, scopedKey = "identity_id"): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (scopedId) qs.set(scopedKey, scopedId);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

function notificationQueryString(options?: { limit?: number; cursor?: string; status?: Notification["status"] }): string {
  const qs = new URLSearchParams();
  if (options?.limit != null) qs.set("limit", String(options.limit));
  if (options?.cursor) qs.set("cursor", options.cursor);
  if (options?.status) qs.set("status", options.status);
  const suffix = qs.toString();
  return suffix ? `?${suffix}` : "";
}

/** identityState returns the credential's lifecycle state. The served contract
 * (OpenAPI Identity) names this field `status`; this helper keeps the call sites
 * decoupled from the field name so a future contract change is a one-line edit here. */
export function identityState(i: Identity): string {
  return i.status ?? "";
}
