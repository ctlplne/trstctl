import { lazy, Suspense, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Eyebrow } from "@/components/typography";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { AlertTriangle, Clock3, Copy, Eye, KeyRound, Loader2, MoreHorizontal, RefreshCw, RotateCw, Send, Trash2, UserRoundX } from "lucide-react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { ProgressiveTaskList } from "@/components/ProgressiveTaskList";
import { ScrollableTableRegion } from "@/components/ScrollableTableRegion";
import { IdentityPicker } from "@/components/IdentityPicker";
import { useCan } from "@/components/rbac";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { SecretTree, ReferenceResolver, EnvDiffPanel, VersionHistory, SecretImport } from "@/components/secrets";
import { formatDateTime as formatDate } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import {
  ApiError,
  api,
  type APIToken,
  type CloudSecretManagerIntegration,
  type EphemeralCredential,
  type Identity,
  type KubernetesSecretOperator,
  type MachineAuthMethod,
  type MachineSession as MachineSessionRecord,
  type Owner,
  type SecretApprovalAction,
  type SecretAccessPreview,
  type SecretMeta,
  type SecretStoreCreatePreview,
  type SecretRepositoryScanPosture,
  type SecretRotation,
  type SecretRotationPreview,
  type SecretRotationRequest,
  type SecretRotationSchedule,
  type SecretRotationScheduleRun,
  type SecretSyncTargetCatalog,
  type SecretWorkloadInjection,
  type ThirdPartySecretScanPosture,
  type UnvaultedSecretPosture,
  type SecretValue,
} from "@/lib/api";
import {
  formatCommandArgv,
  parseSecretRotationPartialReceipt,
  RevealPanel,
  RotationHealthBadges,
  SecretApprovalQueue,
  Snippet,
  mergeMeta,
  NativeSecretCreateForm,
  secretApprovalActionLabel,
  secretApprovalQueueID,
  secretRotationDeferredReasonKeys,
  secretRotationDueEvidenceHasClosedErrors,
  type SecretApprovalQueueItem,
  type SecretRotationDeferredEvidence,
  type SecretRotationDueEvidence,
} from "./secrets/SecretsPageParts";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";
import { SecretSyncWorkloadIdentityPanel } from "./secrets/SecretSyncWorkloadIdentityPanel";
import { PKISecretWorkflow } from "./secrets/PKISecretWorkflow";
import { MachineAuthWorkflow } from "./secrets/MachineAuthWorkflow";
import { SecretScanningWorkflow } from "./secrets/SecretScanningWorkflow";
import { DynamicSecretWorkflow } from "./secrets/DynamicSecretWorkflow";
import { SecretSyncWorkflow } from "./secrets/SecretSyncWorkflow";

const SecretSharingWorkflow = lazy(() => import("./secrets/SecretSharingWorkflow"));
const EphemeralAPIKeyWorkflow = lazy(() => import("./secrets/EphemeralAPIKeyWorkflow"));
const TransitOperations = lazy(() => import("./secrets/TransitOperations").then((module) => ({ default: module.TransitOperations })));

function SecretsWorkflowFallback() {
  return <div className="min-h-24 animate-pulse rounded-md bg-muted" aria-hidden="true" />;
}

/** The store (tree + table + lifecycle) renders at /secrets; every other
 * workflow is its own route in the Secrets space sidebar (S-C2) instead of
 * stacking into a ~6,800px scroll (audit P0: mega-page pattern) or hiding
 * behind an in-page tab strip. The historical `?tab=` deep links redirect
 * permanently to the routes, mirroring the C-A1 /platform precedent. */
type SecretsTab = "store" | "access" | "developer" | "sharing" | "engines" | "scanning" | "sync";
const secretsTabIds: readonly SecretsTab[] = ["store", "access", "developer", "sharing", "engines", "scanning", "sync"];

function secretsTabFromSearchParam(value: string | null): SecretsTab {
  return secretsTabIds.includes(value as SecretsTab) ? (value as SecretsTab) : "store";
}

/** Route → workspace: /secrets is the store; /secrets/<id> selects the rest. */
function secretsTabFromPath(pathname: string): SecretsTab {
  const segment = pathname.split("/")[2] ?? "";
  return segment !== "store" && secretsTabIds.includes(segment as SecretsTab) ? (segment as SecretsTab) : "store";
}

/** One plain-language question and one next action per workspace. The action
 * either focuses the first safe field on this page or opens the existing setup
 * surface that owns the required configuration. */
const secretsRouteUX = {
  store: {
    titleKey: "secrets.route.store",
    answerKey: "secrets.route.storeAnswer",
    detailKey: "secrets.route.storeDetails",
    actionKey: "secrets.route.storeAction",
    focusID: "secret-create-name",
  },
  access: {
    titleKey: "secrets.route.access",
    answerKey: "secrets.route.accessAnswer",
    detailKey: "secrets.route.accessDetails",
    actionKey: "secrets.route.accessAction",
    focusID: "grant-subject",
  },
  developer: {
    titleKey: "secrets.route.developer",
    answerKey: "secrets.route.developerAnswer",
    detailKey: "secrets.route.developerDetails",
    actionKey: "secrets.route.developerAction",
    focusID: "developer-secret-name",
  },
  sharing: {
    titleKey: "secrets.route.sharing",
    answerKey: "secrets.route.sharingAnswer",
    detailKey: "secrets.route.sharingDetails",
    actionKey: "secrets.route.sharingAction",
    focusID: "share-value",
  },
  engines: {
    titleKey: "secrets.route.engines",
    answerKey: "secrets.route.enginesAnswer",
    detailKey: "secrets.route.enginesDetails",
    actionKey: "secrets.route.enginesAction",
    destination: "/integrate",
  },
  scanning: {
    titleKey: "secrets.tabs.scanning",
    answerKey: "secrets.route.scanningAnswer",
    detailKey: "secrets.route.scanningDetails",
    actionKey: "secrets.route.scanningAction",
    destination: "/discovery?kind=secret_repo",
  },
  sync: {
    titleKey: "secrets.route.sync",
    answerKey: "secrets.route.syncAnswer",
    detailKey: "secrets.route.syncDetails",
    actionKey: "secrets.route.syncAction",
    destination: "/connectors",
  },
} as const;

// The served schema exposes queued connector delivery. Keep this guard while
// generated clients are refreshed from OpenAPI so source tests remain type-safe.
function secretRotationQueued(rotation: SecretRotation): boolean {
  return "queued" in rotation && rotation.queued === true;
}

function SecretsHealthLink({ to, label, urgent, icon }: { to: string; label: string; urgent: boolean; icon: ReactNode }) {
  return (
    <li>
      <Link to={to} className="ui-panel flex min-h-20 items-center gap-3 p-4 hover:border-brand-accent/50">
        <span className={urgent ? "text-risk-critical" : "text-brand-accent"}>{icon}</span>
        <span className="text-sm font-semibold">{label}</span>
      </Link>
    </li>
  );
}

export function Secrets() {
  const { t } = useTranslation();
  const nativeStoreList = useCapabilityExecution("F63", "listSecrets");
  const rotationScheduleList = useCapabilityExecution("F37", "listSecretRotationSchedules");
  const machineAuthMethodList = useCapabilityExecution("F58", "listMachineAuthMethods");
  const machineSessionList = useCapabilityExecution("F58", "listMachineSessions");
  const [overviewNow] = useState(() => Date.now());
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // S-C2: the route decides the workspace; ?tab= is legacy-redirect input only.
  const tab = secretsTabFromPath(location.pathname);
  const routeUX = secretsRouteUX[tab];
  const legacyTab = location.pathname === "/secrets" ? secretsTabFromSearchParam(searchParams.get("tab")) : "store";
  const [items, setItems] = useState<SecretMeta[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [secretSearch, setSecretSearch] = useState("");
  const [detailSecretName, setDetailSecretName] = useState<string | null>(null);
  const [secretMenuName, setSecretMenuName] = useState<string | null>(null);

  const [createName, setCreateName] = useState("");
  const [createValue, setCreateValue] = useState("");
  const [createOwnerID, setCreateOwnerID] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const createNameRef = useRef<HTMLInputElement>(null);
  const [owners, setOwners] = useState<Owner[]>([]);
  const [ownersAvailable, setOwnersAvailable] = useState<boolean | null>(null);
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createPreview, setCreatePreview] = useState<SecretStoreCreatePreview | null>(null);
  const [createPreviewBusy, setCreatePreviewBusy] = useState(false);
  const [createPreviewError, setCreatePreviewError] = useState<string | null>(null);
  const [createPreviewStale, setCreatePreviewStale] = useState(false);

  useEffect(() => {
    if (createOpen) createNameRef.current?.focus();
  }, [createOpen]);

  const [revealed, setRevealed] = useState<SecretValue | null>(null);
  const [revealBusy, setRevealBusy] = useState<string | null>(null);
  const [revealError, setRevealError] = useState<string | null>(null);

  const [rotateName, setRotateName] = useState("");
  const [rotateValue, setRotateValue] = useState("");
  const [rotateBusy, setRotateBusy] = useState(false);
  const [rotateError, setRotateError] = useState<string | null>(null);

  const [deleteName, setDeleteName] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [approvalQueue, setApprovalQueue] = useState<SecretApprovalQueueItem[]>([]);
  const [approvalBusy, setApprovalBusy] = useState<string | null>(null);

  const [accessName, setAccessName] = useState("");
  const [accessEnvVar, setAccessEnvVar] = useState("DB_PASSWORD");
  const [accessResolve, setAccessResolve] = useState(false);
  const [accessReview, setAccessReview] = useState<{ requestKey: string; plan: SecretAccessPreview } | null>(null);
  const [accessReviewBusy, setAccessReviewBusy] = useState(false);
  const [accessReviewError, setAccessReviewError] = useState<string | null>(null);
  const [accessReviewStale, setAccessReviewStale] = useState(false);
  const [accessResult, setAccessResult] = useState<{ name: string; version?: number; fingerprint: string } | null>(null);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  // C-S1 (DA-02 interim): grant console state — Job 2's grant step over the
  // existing idempotent /access and /ephemeral endpoints.
  const canGrant = useCan("access:write");
  const canReadTokens = useCan("access:read");
  const [grantIdentities, setGrantIdentities] = useState<Identity[]>([]);
  const [grantSubject, setGrantSubject] = useState("");
  const [grantScopes, setGrantScopes] = useState("secrets:read");
  const [grantEphemeral, setGrantEphemeral] = useState(false);
  const [grantTTL, setGrantTTL] = useState("3600");
  const [grantBusy, setGrantBusy] = useState(false);
  const [grantError, setGrantError] = useState<string | null>(null);
  const [grantResult, setGrantResult] = useState<{ token: string; subject: string; expiresAt?: string } | null>(null);
  const [grantVerifyBusy, setGrantVerifyBusy] = useState(false);
  const [grantVerifyError, setGrantVerifyError] = useState<string | null>(null);
  const [grantVerifyResult, setGrantVerifyResult] = useState<{ name: string; version?: number } | null>(null);
  const [tokenRows, setTokenRows] = useState<APIToken[] | null>(null);
  const [revokingTokenId, setRevokingTokenId] = useState<string | null>(null);
  // C-S4 (DA-02 faithful): auth-method console state over the C-S2/C-S3
  // endpoints — methods projection + overlay, and the issued-session ledger.
  const canAdminMethods = useCan("secrets:write");
  const [authMethods, setAuthMethods] = useState<MachineAuthMethod[] | null>(null);
  const [machineSessions, setMachineSessions] = useState<MachineSessionRecord[] | null>(null);
  const [methodBusy, setMethodBusy] = useState<string | null>(null);
  const [methodError, setMethodError] = useState<string | null>(null);
  const [sessionBusy, setSessionBusy] = useState<string | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);

  const [sharingTask, setSharingTask] = useState<"share" | "machine" | null>(null);
  const [engineTask, setEngineTask] = useState<"dynamic" | "transit" | "pki" | null>(null);

  const [repoScanPosture, setRepoScanPosture] = useState<SecretRepositoryScanPosture | null>(null);
  const [thirdPartyPosture, setThirdPartyPosture] = useState<ThirdPartySecretScanPosture | null>(null);

  const [cloudManagers, setCloudManagers] = useState<CloudSecretManagerIntegration | null>(null);
  const [syncCatalog, setSyncCatalog] = useState<SecretSyncTargetCatalog | null>(null);
  const [operatorPosture, setOperatorPosture] = useState<KubernetesSecretOperator | null>(null);
  const [workloadInjection, setWorkloadInjection] = useState<SecretWorkloadInjection | null>(null);
  const [unvaultedPosture, setUnvaultedPosture] = useState<UnvaultedSecretPosture | null>(null);

  const [rotationRunKey, setRotationRunKey] = useState("");
  const [rotationRunOldRef, setRotationRunOldRef] = useState("");
  const [rotationRunProvider, setRotationRunProvider] = useState("");
  const [rotationRunTarget, setRotationRunTarget] = useState("");
  const [rotationRunRemoteKey, setRotationRunRemoteKey] = useState("");
  const [rotationRunBusy, setRotationRunBusy] = useState(false);
  const [rotationRunError, setRotationRunError] = useState<string | null>(null);
  const [rotationRun, setRotationRun] = useState<SecretRotation | null>(null);
  const [rotationPreview, setRotationPreview] = useState<{
    requestKey: string;
    request: SecretRotationRequest;
    plan: SecretRotationPreview;
  } | null>(null);
  const rotationRequest = useMemo<SecretRotationRequest>(
    () => ({
      key: rotationRunKey.trim(),
      old_ref: rotationRunOldRef.trim(),
      provider: rotationRunProvider.trim(),
      ...(rotationRunTarget.trim() ? { target: rotationRunTarget.trim() } : {}),
      ...(rotationRunRemoteKey.trim() ? { remote_key: rotationRunRemoteKey.trim() } : {}),
    }),
    [rotationRunKey, rotationRunOldRef, rotationRunProvider, rotationRunRemoteKey, rotationRunTarget],
  );
  const rotationRequestKey = JSON.stringify(rotationRequest);
  const reviewedRotation = rotationPreview?.requestKey === rotationRequestKey ? rotationPreview : null;

  const [rotationSchedules, setRotationSchedules] = useState<SecretRotationSchedule[] | null>(null);
  const [scheduleDialogOpen, setScheduleDialogOpen] = useState(false);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleKey, setScheduleKey] = useState("");
  const [scheduleOldRef, setScheduleOldRef] = useState("");
  const [scheduleProvider, setScheduleProvider] = useState("");
  const [scheduleInterval, setScheduleInterval] = useState("86400");
  const [scheduleNextRunAt, setScheduleNextRunAt] = useState("");
  const [scheduleEnabled, setScheduleEnabled] = useState(true);
  const [scheduleBusy, setScheduleBusy] = useState(false);
  const [scheduleError, setScheduleError] = useState<string | null>(null);
  const [runDueBusy, setRunDueBusy] = useState(false);
  const [runDueError, setRunDueError] = useState<string | null>(null);
  const [dueRuns, setDueRuns] = useState<SecretRotationScheduleRun[] | null>(null);
  const [dueDeferred, setDueDeferred] = useState<SecretRotationDeferredEvidence[]>([]);
  const [dueLimits, setDueLimits] = useState<{ run: boolean; scan: boolean } | null>(null);

  const [credentialRequestID, setCredentialRequestID] = useState("");
  const [credentialMethod, setCredentialMethod] = useState("");
  const [credentialPayload, setCredentialPayload] = useState("");
  const [credentialPublicKey, setCredentialPublicKey] = useState("");
  const [credentialTTL, setCredentialTTL] = useState("");
  const [credentialBusy, setCredentialBusy] = useState(false);
  const [credentialError, setCredentialError] = useState<string | null>(null);
  const [credential, setCredential] = useState<EphemeralCredential | null>(null);
  const [credentialCopied, setCredentialCopied] = useState<"request_id" | "certificate" | null>(null);

  async function load(cursor?: string) {
    if (nativeStoreList.checking) return;
    setLoadError(null);
    setLoading(true);
    try {
      const posturePromise =
        typeof api.secretRepositoryScanning === "function"
          ? api.secretRepositoryScanning().catch(() => null)
          : Promise.resolve<SecretRepositoryScanPosture | null>(null);
      const thirdPartyPosturePromise =
        typeof api.thirdPartySecretScanning === "function"
          ? api.thirdPartySecretScanning().catch(() => null)
          : Promise.resolve<ThirdPartySecretScanPosture | null>(null);
      const syncCatalogPromise =
        typeof api.secretSyncTargets === "function" ? api.secretSyncTargets().catch(() => null) : Promise.resolve<SecretSyncTargetCatalog | null>(null);
      const cloudManagersPromise =
        typeof api.cloudSecretManagers === "function"
          ? api.cloudSecretManagers().catch(() => null)
          : Promise.resolve<CloudSecretManagerIntegration | null>(null);
      const operatorPosturePromise =
        typeof api.kubernetesSecretOperator === "function"
          ? api.kubernetesSecretOperator().catch(() => null)
          : Promise.resolve<KubernetesSecretOperator | null>(null);
      const workloadInjectionPromise =
        typeof api.secretWorkloadInjection === "function"
          ? api.secretWorkloadInjection().catch(() => null)
          : Promise.resolve<SecretWorkloadInjection | null>(null);
      const unvaultedPosturePromise =
        typeof api.unvaultedSecrets === "function" ? api.unvaultedSecrets().catch(() => null) : Promise.resolve<UnvaultedSecretPosture | null>(null);
      const ownersPromise = typeof api.owners === "function" ? api.owners().catch(() => null) : Promise.resolve<Owner[] | null>(null);
      const pagePromise = nativeStoreList.runnable ? api.secretPage({ limit: 20, cursor }) : Promise.resolve(null);
      const [page, posture, thirdParty, catalog, cloudManagerPosture, operator, injection, unvaulted, ownerRows] = await Promise.all([
        pagePromise,
        posturePromise,
        thirdPartyPosturePromise,
        syncCatalogPromise,
        cloudManagersPromise,
        operatorPosturePromise,
        workloadInjectionPromise,
        unvaultedPosturePromise,
        ownersPromise,
      ]);
      if (page) {
        setItems((current) => (cursor ? mergeMeta(current, page.items) : page.items));
        setNextCursor(page.next_cursor);
        setAccessName((current) => current || page.items[0]?.name || "");
      } else {
        setItems([]);
        setNextCursor(undefined);
        setLoadError(
          nativeStoreList.unavailable?.detail ??
            "The runtime capability check could not confirm that the native secret store is available. No secret operation was attempted.",
        );
      }
      if (posture) setRepoScanPosture(posture);
      if (thirdParty) setThirdPartyPosture(thirdParty);
      if (catalog) {
        setSyncCatalog(catalog);
      }
      if (cloudManagerPosture) {
        setCloudManagers(cloudManagerPosture);
      }
      if (operator) {
        setOperatorPosture(operator);
      }
      if (injection) {
        setWorkloadInjection(injection);
      }
      if (unvaulted) {
        setUnvaultedPosture(unvaulted);
      }
      if (ownerRows) {
        const orderedOwners = [...ownerRows].sort((left, right) => left.name.localeCompare(right.name));
        setOwners(orderedOwners);
      }
      setOwnersAvailable(ownerRows !== null);
    } catch (err) {
      setLoadError(apiProblemMessage(err, "Secrets API unavailable or disabled"));
      setOwnersAvailable(false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!nativeStoreList.checking) void load();
    // The primitive posture fields intentionally retrigger the first read when
    // the live capability projection finishes loading or changes at runtime.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nativeStoreList.checking, nativeStoreList.runnable, nativeStoreList.unavailable?.detail]);

  const refreshRotationSchedules = () => {
    if (rotationScheduleList.checking) return Promise.resolve();
    if (!rotationScheduleList.runnable) {
      setRotationSchedules(null);
      return Promise.resolve();
    }
    return Promise.resolve()
      .then(() => api.secretRotationSchedules({ limit: 20 }))
      .then((page) => setRotationSchedules(page.items ?? []))
      .catch(() => undefined);
  };

  useEffect(() => {
    if (!rotationScheduleList.checking) void refreshRotationSchedules();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rotationScheduleList.checking, rotationScheduleList.runnable]);

  const selectedMeta = useMemo(() => items.find((item) => item.name === accessName) ?? items[0] ?? null, [items, accessName]);
  const accessRequest = useMemo(
    () => ({ name: accessName.trim() || selectedMeta?.name || "", env_var: accessEnvVar.trim(), resolve: accessResolve }),
    [accessEnvVar, accessName, accessResolve, selectedMeta?.name],
  );
  const accessRequestKey = JSON.stringify(accessRequest);
  const reviewedAccess = accessReview?.requestKey === accessRequestKey ? accessReview : null;
  const ownerByID = useMemo(() => new Map(owners.map((owner) => [owner.id, owner])), [owners]);
  const filteredItems = useMemo(() => {
    const needle = secretSearch.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) =>
      [
        item.name,
        ownerByID.get(item.owner_id ?? "")?.name ?? "unassigned",
        ownerByID.get(item.owner_id ?? "")?.environment ?? "",
        String(item.version ?? ""),
        item.created_at ?? "",
        item.updated_at ?? "",
        "native store",
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [items, ownerByID, secretSearch]);
  const detailSecret = useMemo(() => items.find((item) => item.name === detailSecretName) ?? null, [detailSecretName, items]);
  const unownedSecrets = useMemo(() => items.filter((item) => !item.owner_id || !ownerByID.has(item.owner_id)), [items, ownerByID]);
  const overdueSchedules = useMemo(
    () =>
      (rotationSchedules ?? []).filter((schedule) => {
        const nextRun = new Date(schedule.next_run_at).getTime();
        return schedule.enabled && Number.isFinite(nextRun) && nextRun <= overviewNow;
      }),
    [overviewNow, rotationSchedules],
  );
  const failedSchedules = useMemo(
    () => (rotationSchedules ?? []).filter((schedule) => ["failed", "delivery_failed", "rollback_failed", "unsupported"].includes(schedule.last_run_status)),
    [rotationSchedules],
  );
  const leakedFindings = unvaultedPosture?.summary.leaked_secret_findings ?? 0;
  const nativeStoreUnavailable = nativeStoreList.enforced && nativeStoreList.state === "unavailable";
  const secretOverviewComplete = !loading && !loadError && rotationSchedules !== null && unvaultedPosture !== null && ownersAvailable === true;
  const secretAttention = useMemo(() => {
    const rows: Array<{ id: string; name: string; detail: string; consequence: string; to: string; action: string }> = [];
    const failed = new Set<string>();
    for (const schedule of failedSchedules) {
      failed.add(schedule.id);
      rows.push({
        id: `failed:${schedule.id}`,
        name: schedule.name,
        detail: schedule.last_error || t("secrets.overview.deliveryFailureFallback"),
        consequence: t("secrets.overview.deliveryFailureConsequence"),
        to: "/secrets/sync",
        action: t("secrets.overview.repairDelivery"),
      });
    }
    for (const schedule of overdueSchedules) {
      if (failed.has(schedule.id)) continue;
      rows.push({
        id: `overdue:${schedule.id}`,
        name: schedule.name,
        detail: t("secrets.overview.rotationOverdue"),
        consequence: t("secrets.overview.rotationConsequence"),
        to: "/secrets?focus=rotation",
        action: t("secrets.overview.reviewRotation"),
      });
    }
    if (leakedFindings > 0) {
      rows.push({
        id: "leaks",
        name: t("secrets.overview.leakName"),
        detail: t("secrets.overview.leakDetail", { count: String(leakedFindings) }),
        consequence: t("secrets.overview.leakConsequence"),
        to: "/secrets/scanning",
        action: t("secrets.overview.reviewLeaks"),
      });
    }
    for (const secret of unownedSecrets.slice(0, 3)) {
      rows.push({
        id: `owner:${secret.name}`,
        name: secret.name,
        detail: t("secrets.overview.ownerMissing"),
        consequence: t("secrets.overview.ownerConsequence"),
        to: "/secrets?owner=missing",
        action: t("secrets.overview.assignOwner"),
      });
    }
    return rows;
  }, [failedSchedules, leakedFindings, overdueSchedules, t, unownedSecrets]);

  const secretColumns = useMemo<Array<DataGridColumn<SecretMeta>>>(
    () => [
      {
        id: "name",
        header: "Secret",
        sortable: true,
        cell: (item) => (
          <button
            type="button"
            aria-label={t("secrets.store.viewMetadataFor", { name: item.name })}
            className="break-all text-start font-medium underline decoration-border underline-offset-4 hover:decoration-foreground"
            onClick={() => setDetailSecretName(item.name)}
          >
            {item.name}
          </button>
        ),
      },
      {
        id: "owner",
        header: translateNow("source.owner.4b1b8aa360"),
        cell: (item) => ownerByID.get(item.owner_id ?? "")?.name ?? t("secrets.store.unassignedOwner"),
      },
      {
        id: "environment",
        header: t("owners.readiness.environment"),
        cell: (item) => ownerByID.get(item.owner_id ?? "")?.environment || "—",
      },
      { id: "updated", header: "Updated", cell: (item) => formatDate(item.updated_at) },
      {
        id: "actions",
        header: "Action",
        cell: (item) => (
          <div className="relative flex flex-wrap items-start gap-1.5">
            <Button type="button" size="sm" variant="outline" onClick={() => void revealSecret(item.name)} disabled={revealBusy === item.name}>
              {revealBusy === item.name ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              {t("secrets.store.revealValue")}
            </Button>
            <Button
              type="button"
              size="icon"
              variant="ghost"
              aria-label={t("secrets.store.moreActionsFor", { name: item.name })}
              aria-expanded={secretMenuName === item.name}
              className="h-9 w-9"
              onClick={() => setSecretMenuName((openName) => (openName === item.name ? null : item.name))}
            >
              <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
            </Button>
            {secretMenuName === item.name && (
              <div
                role="group"
                aria-label={t("secrets.store.actionsFor", { name: item.name })}
                className="basis-full rounded-panel border border-border bg-card p-1 shadow-elevation1"
              >
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="w-full justify-start"
                  onClick={() => {
                    setSecretMenuName(null);
                    setRotateName(item.name);
                  }}
                >
                  <RotateCw className="h-4 w-4" aria-hidden="true" />
                  {translateNow("source.prepare.rotate.9534e0ec7e")}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="w-full justify-start text-risk-critical"
                  onClick={() => {
                    setSecretMenuName(null);
                    setDeleteName(item.name);
                  }}
                >
                  <Trash2 className="h-4 w-4" aria-hidden="true" />
                  {translateNow("source.prepare.delete.6d0f9a0ea2")}
                </Button>
              </div>
            )}
          </div>
        ),
      },
    ],
    [ownerByID, revealBusy, secretMenuName, t],
  );

  const scheduleColumns = useMemo<Array<DataGridColumn<SecretRotationSchedule>>>(
    () => [
      { id: "name", header: "Name", sortable: true, cell: (item) => <span className="font-medium">{item.name}</span> },
      {
        id: "key",
        header: "Key",
        cell: (item) => (
          <span className="block max-w-44 truncate font-mono text-xs" title={item.key}>
            {item.key}
          </span>
        ),
      },
      { id: "interval", header: "Interval", cell: (item) => formatRotationInterval(item.interval_seconds) },
      {
        id: "enabled",
        header: "Enabled",
        cell: (item) => (
          <StatusBadge
            vocabulary="lifecycle"
            value={item.enabled ? "enabled" : "disabled"}
            label={item.enabled ? "Enabled" : "Disabled"}
            tone={item.enabled ? "success" : "neutral"}
          />
        ),
      },
      { id: "last-run", header: "Last run", cell: (item) => <StatusBadge vocabulary="lifecycle" value={item.last_run_status || "never"} /> },
      { id: "next-run", header: "Next run", cell: (item) => formatDate(item.next_run_at) },
      // S-C19: say "this has not rotated" instead of making the operator do
      // date arithmetic against the next-run column.
      { id: "rotation-health", header: "Health", cell: (item) => <RotationHealthBadges schedule={item} /> },
    ],
    [],
  );

  function queueSecretApproval(action: SecretApprovalAction, name: string, err: unknown): boolean {
    const message = apiProblemMessage(err, t("secrets.approvals.requiredFallback"));
    if (!(err instanceof ApiError) || err.status !== 403 || !/dual control/i.test(message)) return false;
    const id = secretApprovalQueueID(action, name);
    setApprovalQueue((current) => {
      const existing = current.find((item) => item.id === id);
      return [
        {
          ...existing,
          id,
          name,
          action,
          openedAt: existing?.openedAt ?? new Date().toISOString(),
          status: "pending",
          error: message,
        },
        ...current.filter((item) => item.id !== id),
      ];
    });
    return true;
  }

  function updateApprovalQueueItem(id: string, patch: Partial<SecretApprovalQueueItem>) {
    setApprovalQueue((current) => current.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  }

  function canRetryApproval(item: SecretApprovalQueueItem): boolean {
    if (item.status === "completed") return false;
    if (item.action === "rotate") return rotateName === item.name && rotateValue.trim() !== "";
    if (item.action === "delete") return deleteName === item.name && deleteConfirm === item.name;
    return false;
  }

  async function approveSecretApproval(item: SecretApprovalQueueItem) {
    const busyKey = `${item.id}:approve`;
    setApprovalBusy(busyKey);
    try {
      const requests = await api.approvalRequests();
      const exactRequest = requests.find(
        (request) =>
          request.resource_kind === "secret" && request.resource_id === `secret:${item.name}` && request.action === item.action && request.status === "pending",
      );
      if (!exactRequest) throw new Error(t("source.no.pending.approvals.261de9be5f"));
      const approval = await api.approveSecretChange(item.name, {
        action: item.action,
        request_id: exactRequest.id,
        intent_digest: exactRequest.intent_digest,
      });
      updateApprovalQueueItem(item.id, {
        status: "approved",
        approvals: approval.approvals,
        approver: approval.approver,
        error: undefined,
      });
      setNotice(t("secrets.approvals.approvedNotice", { approver: approval.approver, action: secretApprovalActionLabel(item.action, t), name: item.name }));
    } catch (err) {
      updateApprovalQueueItem(item.id, { error: apiProblemMessage(err, t("secrets.approvals.approveFailed")) });
    } finally {
      setApprovalBusy(null);
    }
  }

  async function retrySecretApproval(item: SecretApprovalQueueItem) {
    const busyKey = `${item.id}:retry`;
    setApprovalBusy(busyKey);
    try {
      if (item.action === "rotate") {
        if (rotateName !== item.name || rotateValue.trim() === "") {
          throw new Error(t("secrets.approvals.rotateRetryNeedsForm", { name: item.name }));
        }
        const meta = await api.rotateSecret(item.name, { value: rotateValue });
        setItems((current) => mergeMeta(current, [meta]));
        setRotateName("");
        setRotateValue("");
        setRotateError(null);
        updateApprovalQueueItem(item.id, { status: "completed", error: undefined });
        setNotice(t("secrets.approvals.rotatedAfterApproval", { name: meta.name, version: meta.version ?? "" }));
        return;
      }
      if (item.action === "delete") {
        if (deleteName !== item.name || deleteConfirm !== item.name) {
          throw new Error(t("secrets.approvals.deleteRetryNeedsForm", { name: item.name }));
        }
        await api.deleteSecret(item.name);
        setItems((current) => current.filter((secret) => secret.name !== item.name));
        setDeleteName("");
        setDeleteConfirm("");
        setDeleteError(null);
        updateApprovalQueueItem(item.id, { status: "completed", error: undefined });
        setNotice(t("secrets.approvals.deletedAfterApproval", { name: item.name }));
        return;
      }
      throw new Error(t("secrets.approvals.recoverRetryUnsupported"));
    } catch (err) {
      if (!queueSecretApproval(item.action, item.name, err)) {
        updateApprovalQueueItem(item.id, { error: apiProblemMessage(err, t("secrets.approvals.retryFailed")) });
      }
    } finally {
      setApprovalBusy(null);
    }
  }

  function invalidateCreatePreview() {
    if (createPreview) setCreatePreviewStale(true);
    setCreatePreview(null);
    setCreatePreviewError(null);
  }

  async function reviewCreate() {
    setCreateError(null);
    setCreatePreviewError(null);
    setNotice(null);
    setCreatePreviewBusy(true);
    try {
      const plan = await api.previewSecretCreate({ name: createName, owner_id: createOwnerID || undefined, value: createValue });
      setCreatePreview(plan);
      setCreatePreviewStale(false);
    } catch (err) {
      setCreatePreview(null);
      setCreatePreviewError(apiProblemMessage(err, t("secrets.store.previewFailed")));
    } finally {
      setCreatePreviewBusy(false);
    }
  }

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreateError(null);
    setNotice(null);
    if (!createPreview?.ready) {
      setCreateError(t("secrets.store.reviewRequired"));
      return;
    }
    setCreateBusy(true);
    try {
      const meta = await api.createSecret({ name: createName, owner_id: createOwnerID || undefined, value: createValue });
      setItems((current) => mergeMeta(current, [meta]));
      setCreateName("");
      setCreateValue("");
      setCreateOwnerID("");
      setCreatePreview(null);
      setCreatePreviewStale(false);
      setCreateOpen(false);
      setNotice(`Secret ${meta.name} stored as version ${meta.version}. The value was sealed and is not shown after submit.`);
    } catch (err) {
      setCreateError(apiProblemMessage(err, "Could not create secret"));
    } finally {
      setCreateBusy(false);
    }
  }

  function closeCreateForm() {
    // A cancelled secret value should leave React state immediately, just as a
    // submitted value does. Names and ownership are cleared too so reopening
    // cannot look like a half-finished mutation.
    setCreateName("");
    setCreateValue("");
    setCreateOwnerID("");
    setCreateError(null);
    setCreatePreview(null);
    setCreatePreviewError(null);
    setCreatePreviewStale(false);
    setCreateOpen(false);
  }

  async function revealSecret(name: string) {
    setRevealError(null);
    setRevealed(null);
    setRevealBusy(name);
    try {
      setRevealed(await api.getSecret(name));
    } catch (err) {
      setRevealError(apiProblemMessage(err, "Could not reveal secret"));
    } finally {
      setRevealBusy(null);
    }
  }

  async function submitRotate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRotateError(null);
    setNotice(null);
    setRotateBusy(true);
    const pendingName = rotateName;
    try {
      const meta = await api.rotateSecret(pendingName, { value: rotateValue });
      setItems((current) => mergeMeta(current, [meta]));
      setRotateName("");
      setRotateValue("");
      setNotice(`Secret ${meta.name} rotated to version ${meta.version}. The replacement value was not rendered.`);
    } catch (err) {
      if (queueSecretApproval("rotate", pendingName, err)) {
        setRotateError(t("secrets.approvals.rotatePending"));
      } else {
        setRotateError(apiProblemMessage(err, "Could not rotate secret"));
      }
    } finally {
      setRotateBusy(false);
    }
  }

  async function submitDelete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setDeleteError(null);
    setNotice(null);
    setDeleteBusy(true);
    const pendingName = deleteName;
    try {
      await api.deleteSecret(pendingName);
      setItems((current) => current.filter((item) => item.name !== pendingName));
      setNotice(`Secret ${pendingName} deleted from the native store.`);
      setDeleteName("");
      setDeleteConfirm("");
    } catch (err) {
      if (queueSecretApproval("delete", pendingName, err)) {
        setDeleteError(t("secrets.approvals.deletePending"));
      } else {
        setDeleteError(apiProblemMessage(err, "Could not delete secret"));
      }
    } finally {
      setDeleteBusy(false);
    }
  }

  function invalidateAccessReview() {
    if (accessReview) setAccessReviewStale(true);
    setAccessReview(null);
    setAccessReviewError(null);
    setAccessError(null);
    setAccessResult(null);
  }

  async function reviewAccess(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessReviewError(null);
    setAccessError(null);
    setAccessResult(null);
    setAccessReviewBusy(true);
    try {
      const plan = await api.previewSecretAccess(accessRequest);
      if (
        plan.capability !== "F64" ||
        plan.operation !== "read_for_process" ||
        !plan.effect_free ||
        plan.name !== accessRequest.name ||
        plan.env_var !== accessRequest.env_var ||
        plan.resolve_references !== accessRequest.resolve
      ) {
        throw new Error(t("secrets.developer.contractMismatch"));
      }
      setAccessReview({ requestKey: accessRequestKey, plan });
      setAccessReviewStale(false);
    } catch (err) {
      setAccessReview(null);
      setAccessReviewError(apiProblemMessage(err, t("secrets.developer.reviewFailed")));
    } finally {
      setAccessReviewBusy(false);
    }
  }

  async function runAccessTest() {
    if (!reviewedAccess?.plan.ready) {
      setAccessError(t("secrets.developer.reviewRequired"));
      return;
    }
    const plan = reviewedAccess.plan;
    setAccessError(null);
    setAccessResult(null);
    setAccessBusy(true);
    try {
      const value = await api.getSecret(plan.name, { resolve: plan.resolve_references });
      if (value.name !== plan.name || (plan.version != null && value.version !== plan.version)) {
        setAccessReview(null);
        setAccessReviewStale(true);
        setAccessError(t("secrets.developer.versionChanged"));
        return;
      }
      setAccessResult({ name: value.name, version: value.version, fingerprint: plan.request_fingerprint });
    } catch (err) {
      setAccessError(apiProblemMessage(err, t("secrets.developer.testFailed")));
    } finally {
      setAccessBusy(false);
    }
  }

  /* ------------------------------------------------------------- C-S1 ---- */

  /** Best-effort roster/ledger reads: grant suggestions and the token table
   * are never load-bearing for the rest of the Secrets page. */
  async function readGrantRoster<T>(load: () => Promise<T>): Promise<T | null> {
    try {
      return (await load()) ?? null;
    } catch {
      return null;
    }
  }

  async function refreshTokenLedger() {
    const page = await readGrantRoster(() => api.apiTokens({ includeRevoked: true, limit: 50 }));
    setTokenRows(page?.items ?? null);
  }

  async function refreshAuthMethods() {
    if (!machineAuthMethodList.runnable) {
      setAuthMethods(null);
      return;
    }
    const page = await readGrantRoster(() => api.machineAuthMethods());
    setAuthMethods(page?.items ?? null);
  }

  async function refreshMachineSessions() {
    if (!machineSessionList.runnable) {
      setMachineSessions(null);
      return;
    }
    const page = await readGrantRoster(() => api.machineSessions({ limit: 50 }));
    setMachineSessions(page?.items ?? null);
  }

  async function toggleAuthMethod(name: string, disable: boolean) {
    setMethodBusy(name);
    setMethodError(null);
    try {
      if (disable) {
        await api.disableMachineAuthMethod(name);
      } else {
        await api.enableMachineAuthMethod(name);
      }
      await refreshAuthMethods();
    } catch (err) {
      setMethodError(apiProblemMessage(err, t("secrets.methods.failedTitle")));
    } finally {
      setMethodBusy(null);
    }
  }

  async function revokeMachineSessionRow(id: string) {
    setSessionBusy(id);
    setSessionError(null);
    try {
      await api.revokeMachineSession(id);
      await refreshMachineSessions();
    } catch (err) {
      setSessionError(apiProblemMessage(err, t("secrets.sessions.failedTitle")));
    } finally {
      setSessionBusy(null);
    }
  }

  useEffect(() => {
    let active = true;
    void readGrantRoster(() => api.identities()).then((items) => {
      if (active && items) setGrantIdentities(items);
    });
    if (canReadTokens) {
      void readGrantRoster(() => api.apiTokens({ includeRevoked: true, limit: 50 })).then((page) => {
        if (active) setTokenRows(page?.items ?? null);
      });
    }
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let active = true;
    if (!machineAuthMethodList.checking) {
      if (machineAuthMethodList.runnable) {
        void readGrantRoster(() => api.machineAuthMethods()).then((page) => {
          if (active) setAuthMethods(page?.items ?? null);
        });
      } else {
        setAuthMethods(null);
      }
    }
    if (!machineSessionList.checking) {
      if (machineSessionList.runnable) {
        void readGrantRoster(() => api.machineSessions({ limit: 50 })).then((page) => {
          if (active) setMachineSessions(page?.items ?? null);
        });
      } else {
        setMachineSessions(null);
      }
    }
    return () => {
      active = false;
    };
  }, [machineAuthMethodList.checking, machineAuthMethodList.runnable, machineSessionList.checking, machineSessionList.runnable]);

  async function submitGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setGrantError(null);
    setGrantResult(null);
    setGrantVerifyError(null);
    setGrantVerifyResult(null);
    setGrantBusy(true);
    try {
      const subject = grantSubject.trim();
      const scopes = grantScopes
        .split(",")
        .map((scope) => scope.trim())
        .filter(Boolean);
      if (grantEphemeral) {
        const ttl = Number(grantTTL.trim());
        const key = await api.issueEphemeralAPIKey({ subject, scopes, ttl_seconds: Number.isFinite(ttl) && ttl > 0 ? Math.floor(ttl) : 3600 });
        setGrantResult({ token: key.token, subject: key.subject, expiresAt: key.expires_at });
      } else {
        const created = await api.createAPIToken({ subject, scopes });
        setGrantResult({ token: created.token, subject: created.subject, expiresAt: created.expires_at });
      }
      setGrantSubject("");
      await refreshTokenLedger();
    } catch (err) {
      setGrantError(apiProblemMessage(err, t("secrets.grant.failedTitle")));
    } finally {
      setGrantBusy(false);
    }
  }

  async function verifyGrantedSecretAccess() {
    if (!grantResult) return;
    const name = accessName.trim() || selectedMeta?.name || "";
    if (!name) {
      setGrantVerifyError(t("secrets.grant.verifyMissingSecret"));
      return;
    }
    setGrantVerifyBusy(true);
    setGrantVerifyError(null);
    setGrantVerifyResult(null);
    try {
      // This request deliberately omits the human session cookie. The raw
      // reveal-once bearer token must authorize the read; only metadata enters
      // React state, and the returned secret value is never rendered or stored.
      const value = await api.getSecretWithToken(name, grantResult.token);
      setGrantVerifyResult({ name: value.name, version: value.version });
    } catch (err) {
      setGrantVerifyError(apiProblemMessage(err, t("secrets.grant.verifyFailedTitle")));
    } finally {
      setGrantVerifyBusy(false);
    }
  }

  async function revokeGrantedToken(id: string) {
    setRevokingTokenId(id);
    setGrantError(null);
    try {
      await api.revokeAPIToken(id);
      await refreshTokenLedger();
    } catch (err) {
      setGrantError(apiProblemMessage(err, t("secrets.grant.failedTitle")));
    } finally {
      setRevokingTokenId(null);
    }
  }

  async function submitRollbackRotation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRotationRunError(null);
    setRotationRun(null);
    setRotationPreview(null);
    setRotationRunBusy(true);
    try {
      if (!rotationRequest.key) throw new Error("Key is required");
      if (!rotationRequest.old_ref) throw new Error("Old reference is required");
      if (!rotationRequest.provider) throw new Error("Provider is required");
      const plan = await api.previewSecretRotation(rotationRequest);
      setRotationPreview({ requestKey: rotationRequestKey, request: rotationRequest, plan });
    } catch (err) {
      setRotationRunError(apiProblemMessage(err, "Could not preview secret rotation"));
    } finally {
      setRotationRunBusy(false);
    }
  }

  async function runReviewedRollbackRotation() {
    if (!reviewedRotation?.plan.ready) return;
    setRotationRunError(null);
    setRotationRun(null);
    setRotationRunBusy(true);
    try {
      setRotationRun(await api.runSecretRotation(reviewedRotation.request));
      setRotationPreview(null);
    } catch (err) {
      setRotationRunError(apiProblemMessage(err, "Could not run reviewed secret rotation"));
    } finally {
      setRotationRunBusy(false);
    }
  }

  function closeScheduleDialog() {
    setScheduleDialogOpen(false);
    setScheduleError(null);
  }

  async function submitRotationSchedule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setScheduleError(null);
    setScheduleBusy(true);
    try {
      const name = scheduleName.trim();
      const key = scheduleKey.trim();
      const oldRef = scheduleOldRef.trim();
      const provider = scheduleProvider.trim();
      if (!name) throw new Error("Schedule name is required");
      if (!key) throw new Error("Key is required");
      if (!oldRef) throw new Error("Old reference is required");
      if (!provider) throw new Error("Provider is required");
      if (!provider.startsWith("connector:") || provider.slice("connector:".length).trim() === "") {
        throw new Error(t("secrets.rotation.scheduleConnectorOnly"));
      }
      const interval = Number(scheduleInterval);
      if (!Number.isFinite(interval) || interval <= 0) throw new Error("Interval seconds must be a positive number");
      let nextRunAt: string | undefined;
      if (scheduleNextRunAt) {
        const parsed = new Date(scheduleNextRunAt);
        if (Number.isNaN(parsed.getTime())) throw new Error("First run must be a valid date and time");
        nextRunAt = parsed.toISOString();
      }
      const created = await api.createSecretRotationSchedule({
        name,
        key,
        old_ref: oldRef,
        provider,
        interval_seconds: Math.round(interval),
        enabled: scheduleEnabled,
        ...(nextRunAt ? { next_run_at: nextRunAt } : {}),
      });
      setScheduleDialogOpen(false);
      setScheduleName("");
      setScheduleKey("");
      setScheduleOldRef("");
      setScheduleNextRunAt("");
      setNotice(`Rotation schedule ${created.name} created; next run ${formatDate(created.next_run_at)}.`);
      await refreshRotationSchedules();
    } catch (err) {
      setScheduleError(apiProblemMessage(err, "Could not create rotation schedule"));
    } finally {
      setScheduleBusy(false);
    }
  }

  async function runDueRotationsNow() {
    setRunDueError(null);
    setNotice(null);
    setDueRuns(null);
    setDueDeferred([]);
    setDueLimits(null);
    setRunDueBusy(true);
    try {
      const result = (await api.runDueSecretRotations()) as SecretRotationDueEvidence;
      if (!secretRotationDueEvidenceHasClosedErrors(result)) {
        throw new Error("Could not run due rotations");
      }
      setDueRuns(result.runs ?? []);
      setDueDeferred(result.deferred ?? []);
      setDueLimits({ run: result.run_limit_reached === true, scan: result.scan_limit_reached === true });
      setNotice(
        t("secrets.rotation.dueNotice", {
          ran: String(result.ran),
          deferred: String(result.deferred?.length ?? 0),
          scanned: String(result.scanned ?? result.ran),
        }),
      );
      await refreshRotationSchedules();
    } catch (err) {
      const partialReceipt = parseSecretRotationPartialReceipt(err);
      if (partialReceipt) {
        // The scheduler's cached 503 body is itself the immutable receipt for
        // this tick. Keep only its fresh evidence; a same-key replay returns
        // these exact rows without executing any child command again.
        setDueRuns(partialReceipt.runs);
        setDueDeferred(partialReceipt.deferred);
        setDueLimits({ run: partialReceipt.run_limit_reached, scan: partialReceipt.scan_limit_reached });
        setRunDueError(partialReceipt.system_error);
        await refreshRotationSchedules();
      } else {
        // Generic and malformed failures carry no fresh scheduler receipt.
        // Clear the last tick so stale evidence cannot be mistaken for now.
        setDueRuns(null);
        setDueDeferred([]);
        setDueLimits(null);
        // A malformed scheduler 503 is outside the closed wire contract. Do
        // not fall back to its problem detail: a corrupted proxy/cache could
        // otherwise reintroduce the exact provider text this decoder rejected.
        setRunDueError(err instanceof ApiError && err.status === 503 ? "Could not run due rotations" : apiProblemMessage(err, "Could not run due rotations"));
      }
    } finally {
      setRunDueBusy(false);
    }
  }

  async function submitEphemeralCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCredentialError(null);
    setCredential(null);
    setCredentialCopied(null);
    setCredentialBusy(true);
    try {
      const requestID = credentialRequestID.trim();
      const method = credentialMethod.trim();
      const payload = credentialPayload.trim();
      const publicKey = credentialPublicKey.trim();
      if (!requestID) throw new Error("Request ID is required");
      if (!method) throw new Error("Attestation method is required");
      if (!payload) throw new Error("Attestation payload is required");
      if (!publicKey.includes("BEGIN")) throw new Error("Public key must be a PEM block including a BEGIN header");
      const ttl = Number(credentialTTL);
      if (credentialTTL.trim() && (!Number.isFinite(ttl) || ttl <= 0)) throw new Error("TTL seconds must be a positive number");
      setCredential(
        await api.requestEphemeralCredential({
          request_id: requestID,
          method,
          payload_base64: payload,
          public_key_pem: publicKey,
          ...(credentialTTL.trim() ? { ttl_seconds: Math.round(ttl) } : {}),
        }),
      );
    } catch (err) {
      setCredentialError(apiProblemMessage(err, "Could not request ephemeral credential"));
    } finally {
      setCredentialBusy(false);
    }
  }

  async function copyCredentialField(kind: "request_id" | "certificate", value: string) {
    try {
      await navigator.clipboard?.writeText(value);
      setCredentialCopied(kind);
    } catch {
      setCredentialCopied(kind);
    }
  }

  useEffect(() => {
    if (tab === "sharing" && sharingTask === "share") {
      document.getElementById("share-value")?.focus();
    }
  }, [sharingTask, tab]);

  // C-A1 precedent: historical /secrets?tab=<id> deep links redirect
  // permanently to the sub-routes; any other query params survive the hop.
  if (legacyTab !== "store") {
    const preserved = new URLSearchParams(searchParams);
    preserved.delete("tab");
    const suffix = preserved.toString();
    return <Navigate to={`/secrets/${legacyTab}${suffix ? `?${suffix}` : ""}`} replace />;
  }

  return (
    <section aria-labelledby="secrets-heading" className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">
      <PageHeader
        titleId="secrets-heading"
        title={t(routeUX.titleKey)}
        description={t(routeUX.answerKey)}
        technicalDetails={t(routeUX.detailKey)}
        actions={
          <>
            <Button
              type="button"
              disabled={tab === "store" && Boolean(loadError)}
              onClick={() => {
                if (tab === "store") {
                  if (createOpen) createNameRef.current?.focus();
                  else setCreateOpen(true);
                  return;
                }
                if (tab === "sharing") {
                  setSharingTask("share");
                  return;
                }
                if ("destination" in routeUX) {
                  navigate(routeUX.destination);
                  return;
                }
                document.getElementById(routeUX.focusID)?.focus();
              }}
            >
              {t(routeUX.actionKey)}
            </Button>
            <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
              {translateNow("source.refresh.0e91610117")}
            </Button>
          </>
        }
      />

      {notice && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
          {notice}
        </p>
      )}

      {loadError && (
        <UnavailableState title={translateNow("source.secrets.api.unavailable.or.disabled.90f9a5c4b4")}>
          {loadError}
          {/[.!?]$/.test(loadError.trim()) ? " " : ". "}
          {translateNow("source.secret.operations.are.fail.closed.until.th.09b52b9f62")}
        </UnavailableState>
      )}

      {tab === "store" && (
        <div className="grid gap-6">
          <section aria-labelledby="secrets-attention-heading" className="ui-panel space-y-4 p-comfortable">
            <div>
              <h2 id="secrets-attention-heading" className="text-title font-semibold">
                {secretAttention.length > 0
                  ? t("secrets.overview.attentionTitle", { count: String(secretAttention.length) })
                  : t(
                      secretOverviewComplete
                        ? "secrets.overview.attentionHealthy"
                        : nativeStoreUnavailable
                          ? "secrets.overview.attentionDependencyUnavailable"
                          : "secrets.overview.attentionUnknown",
                    )}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {secretAttention.length > 0
                  ? t(
                      secretOverviewComplete
                        ? "secrets.overview.attentionHelp"
                        : nativeStoreUnavailable
                          ? "secrets.overview.attentionDependencyPartialHelp"
                          : "secrets.overview.attentionPartialHelp",
                    )
                  : t(
                      secretOverviewComplete
                        ? "secrets.overview.attentionHealthyHelp"
                        : nativeStoreUnavailable
                          ? "secrets.overview.attentionDependencyUnavailableHelp"
                          : "secrets.overview.attentionUnknownHelp",
                    )}
              </p>
            </div>
            {secretAttention.length > 0 ? (
              <ul aria-label={t("secrets.overview.attentionLabel")} className="divide-y divide-border">
                {secretAttention.slice(0, 8).map((row) => (
                  <li key={row.id} className="grid gap-3 py-4 first:pt-0 last:pb-0 lg:grid-cols-[minmax(14rem,1fr)_minmax(14rem,1fr)_auto] lg:items-center">
                    <strong className="min-w-0 break-all text-body">{row.name}</strong>
                    <div className="text-sm">
                      <p>{row.detail}</p>
                      <p className="mt-1 text-muted-foreground">{row.consequence}</p>
                    </div>
                    <Link to={row.to} className="text-sm font-semibold text-brand-accent hover:underline">
                      {row.action}
                    </Link>
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          {secretOverviewComplete ? (
            <section aria-labelledby="secrets-health-heading" className="space-y-3">
              <div>
                <h2 id="secrets-health-heading" className="text-title font-semibold">
                  {t("secrets.overview.healthTitle")}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.overview.healthHelp", { count: String(items.length) })}</p>
              </div>
              <ul aria-label={t("secrets.overview.healthLabel")} className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <SecretsHealthLink
                  to="/secrets/scanning"
                  icon={<AlertTriangle className="h-4 w-4" aria-hidden="true" />}
                  label={t(leakedFindings === 1 ? "secrets.overview.leaksOne" : "secrets.overview.leaksMany", { count: String(leakedFindings) })}
                  urgent={leakedFindings > 0}
                />
                <SecretsHealthLink
                  to="/secrets?focus=rotation"
                  icon={<Clock3 className="h-4 w-4" aria-hidden="true" />}
                  label={t(overdueSchedules.length === 1 ? "secrets.overview.overdueOne" : "secrets.overview.overdueMany", {
                    count: String(overdueSchedules.length),
                  })}
                  urgent={overdueSchedules.length > 0}
                />
                <SecretsHealthLink
                  to="/secrets/sync"
                  icon={<Send className="h-4 w-4" aria-hidden="true" />}
                  label={t(failedSchedules.length === 1 ? "secrets.overview.failuresOne" : "secrets.overview.failuresMany", {
                    count: String(failedSchedules.length),
                  })}
                  urgent={failedSchedules.length > 0}
                />
                <SecretsHealthLink
                  to="/secrets?owner=missing"
                  icon={<UserRoundX className="h-4 w-4" aria-hidden="true" />}
                  label={t(unownedSecrets.length === 1 ? "secrets.overview.unownedOne" : "secrets.overview.unownedMany", {
                    count: String(unownedSecrets.length),
                  })}
                  urgent={unownedSecrets.length > 0}
                />
              </ul>
            </section>
          ) : null}
          <details className="ui-panel group p-comfortable">
            <summary className="cursor-pointer font-medium text-foreground">
              {t("secrets.store.exploreTools")}
              <span className="ms-2 text-sm font-normal text-muted-foreground">{t("secrets.store.exploreToolsHelp")}</span>
            </summary>
            <div className="mt-4 grid gap-4">
              <SecretTree secrets={items} />
              <div className="grid gap-4 lg:grid-cols-2">
                <ReferenceResolver />
                <EnvDiffPanel secrets={items} />
              </div>
              <SecretImport />
            </div>
          </details>

          <section aria-labelledby="store-heading" className="grid gap-4 border-y border-border py-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="store-heading" className="text-title font-semibold">
                  {translateNow("source.native.secret.store.174d71834e")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.the.native.store.returns.names.and.version.6f88143feb")}</p>
              </div>
            </div>

            {createOpen && (
              <NativeSecretCreateForm
                name={createName}
                value={createValue}
                ownerID={createOwnerID}
                owners={owners}
                busy={createBusy}
                previewBusy={createPreviewBusy}
                loadBlocked={Boolean(loadError)}
                preview={createPreview}
                previewError={createPreviewError}
                previewStale={createPreviewStale}
                nameRef={createNameRef}
                onNameChange={(next) => {
                  invalidateCreatePreview();
                  setCreateName(next);
                }}
                onValueChange={(next) => {
                  invalidateCreatePreview();
                  setCreateValue(next);
                }}
                onOwnerChange={(next) => {
                  invalidateCreatePreview();
                  setCreateOwnerID(next);
                }}
                onReview={reviewCreate}
                onCancel={closeCreateForm}
                onSubmit={(event) => void submitCreate(event)}
              />
            )}
            {createError && <ErrorState title={translateNow("source.secret.create.failed.885c3ecf7c")}>{createError}</ErrorState>}

            {!loadError && (
              <DataGrid
                ariaLabel="Native secret metadata"
                rows={filteredItems}
                columns={secretColumns}
                getRowId={(item) => item.name}
                state={loading ? "loading" : filteredItems.length === 0 ? "empty" : "ready"}
                stateTitle={items.length === 0 ? "No secrets stored yet" : "No matching secret metadata"}
                stateMessage={
                  items.length === 0
                    ? "Create a tenant-scoped native-store secret. Only the name and version return to the metadata table."
                    : "No secret metadata matches the current search."
                }
                showColumnChooser
                toolbar={({ columnChooser }) => (
                  <DataGridToolbar
                    searchLabel="Search native secret metadata"
                    searchPlaceholder="Search names or metadata"
                    searchValue={secretSearch}
                    onSearchChange={setSecretSearch}
                    filters={
                      <span className="rounded-control border border-border px-2.5 py-2 text-sm text-muted-foreground">
                        {translateNow("source.engine.native.store.d6b23ebfdb")}
                      </span>
                    }
                    columnChooser={columnChooser}
                  />
                )}
              />
            )}
            {nextCursor && (
              <Button type="button" variant="outline" onClick={() => void load(nextCursor)} disabled={loading}>
                {translateNow("source.load.next.metadata.page.8cd7685eed")}
              </Button>
            )}
            {revealError && <ErrorState title={translateNow("source.reveal.failed.f00b1b5ba6")}>{revealError}</ErrorState>}
            {revealed && (
              <RevealPanel title={t("secrets.store.revealTitle", { name: revealed.name })} onDismiss={() => setRevealed(null)} value={revealed.value}>
                {t("secrets.store.revealHelp", { version: String(revealed.version ?? translateNow("source.latest.5e1e2bcac3")) })}
              </RevealPanel>
            )}
            <DetailDrawer
              open={!!detailSecret}
              title={translateNow("source.secret.metadata.ad1b1e1608")}
              description="Native-store metadata only; secret values are never shown here."
              onClose={() => setDetailSecretName(null)}
            >
              {detailSecret && (
                <dl className="grid gap-3 text-sm md:grid-cols-2">
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.name.dcd1d5223f")}</dt>
                    <dd className="break-all">{detailSecret.name}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.engine.8e75ebbdb2")}</dt>
                    <dd>{translateNow("source.native.store.f4e7459e0a")}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.version.dd167905de")}</dt>
                    <dd className="font-mono text-xs">v{detailSecret.version}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.owner.4b1b8aa360")}</dt>
                    <dd>{ownerByID.get(detailSecret.owner_id ?? "")?.name ?? t("secrets.store.unassignedOwner")}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("owners.readiness.environment")}</dt>
                    <dd>{ownerByID.get(detailSecret.owner_id ?? "")?.environment || "—"}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.updated.3a5ecca188")}</dt>
                    <dd>{formatDate(detailSecret.updated_at)}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.created.d70b9e24bc")}</dt>
                    <dd>{formatDate(detailSecret.created_at)}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.value.handling.f20f0a6806")}</dt>
                    <dd>{t("secrets.store.metadataValueHandling")}</dd>
                  </div>
                </dl>
              )}
              {detailSecret && <VersionHistory name={detailSecret.name} latestVersion={detailSecret.version} />}
            </DetailDrawer>
          </section>

          <details className="group border-y border-border py-4">
            <summary className="cursor-pointer text-title font-semibold text-foreground">
              {t("secrets.store.lifecycleSummary")}
              <span className="ms-2 text-sm font-normal text-muted-foreground">{t("secrets.store.lifecycleSummaryHelp")}</span>
            </summary>
            <section aria-labelledby="rotate-heading" className="mt-4 grid gap-4">
              <div>
                <h2 id="rotate-heading" className="text-title font-semibold">
                  {translateNow("source.manual.rotation.and.delete.1aee4da261")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.rotation.scopeDescription")}</p>
              </div>
              <div className="ui-panel grid gap-3 p-comfortable">
                <div>
                  <h3 className="text-title font-semibold">{t("parity.rollbackSafeRotation_267d4a")}</h3>
                  <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("parity.rotateAProviderBackedCredentialBy_ec7a8f")}</p>
                </div>
                <form
                  aria-label={t("parity.runRollbackSafeRotation_5a7f2d")}
                  onSubmit={(event) => void submitRollbackRotation(event)}
                  className="grid gap-3 md:grid-cols-2 xl:grid-cols-3"
                >
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.key.99a52df3ff")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={rotationRunKey}
                      onChange={(event) => setRotationRunKey(event.target.value)}
                      placeholder={t("parity.paymentsDbPassword_50e8d6")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.oldReference_69d1f6")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={rotationRunOldRef}
                      onChange={(event) => setRotationRunOldRef(event.target.value)}
                      placeholder="ref:v3"
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.provider.472590ae97")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={rotationRunProvider}
                      onChange={(event) => setRotationRunProvider(event.target.value)}
                      placeholder={t("secrets.rotation.scheduleProviderPlaceholder")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.syncTargetOptional_189fc7")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={rotationRunTarget}
                      onChange={(event) => setRotationRunTarget(event.target.value)}
                      placeholder={translateNow("source.kubernetes.prod.16a7f7e17a")}
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.remoteKeyOptional_b6dff8")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={rotationRunRemoteKey}
                      onChange={(event) => setRotationRunRemoteKey(event.target.value)}
                      placeholder={translateNow("source.secret.payments.db.password.cf46ca15a9")}
                    />
                  </label>
                  <div className="md:col-span-2 xl:col-span-3">
                    <Button type="submit" disabled={rotationRunBusy || Boolean(loadError)}>
                      {rotationRunBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                      {t("secrets.rotation.previewAction")}
                    </Button>
                  </div>
                </form>
                {rotationPreview && !reviewedRotation && (
                  <p role="status" className="rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm text-status-warning">
                    {t("secrets.rotation.previewStale")}
                  </p>
                )}
                {reviewedRotation && (
                  <section aria-label={t("secrets.rotation.previewLabel")} className="grid gap-4 rounded-control border border-border bg-background p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h4 className="font-semibold text-foreground">
                          {reviewedRotation.plan.ready ? t("secrets.rotation.previewReady") : t("secrets.rotation.previewBlocked")}
                        </h4>
                        <p className="mt-1 text-sm text-muted-foreground">{t("secrets.rotation.previewNoEffects")}</p>
                      </div>
                      <span
                        className={
                          reviewedRotation.plan.ready
                            ? "rounded-full bg-status-success/10 px-2.5 py-1 text-xs font-semibold text-status-success"
                            : "rounded-full bg-risk-critical/10 px-2.5 py-1 text-xs font-semibold text-risk-critical"
                        }
                      >
                        {reviewedRotation.plan.ready ? t("secrets.rotation.ready") : t("secrets.rotation.blocked")}
                      </span>
                    </div>
                    <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
                      <div>
                        <dt className="font-medium text-muted-foreground">{t("secrets.rotation.versionChange")}</dt>
                        <dd className="font-mono text-xs">
                          {t("secrets.rotation.versionTransition", {
                            current: reviewedRotation.plan.current_version ?? "—",
                            next: reviewedRotation.plan.next_version ?? "—",
                          })}
                        </dd>
                      </div>
                      <div>
                        <dt className="font-medium text-muted-foreground">{translateNow("source.provider.472590ae97")}</dt>
                        <dd className="break-all font-mono text-xs">{reviewedRotation.plan.provider}</dd>
                      </div>
                      <div>
                        <dt className="font-medium text-muted-foreground">{t("secrets.rotation.destination")}</dt>
                        <dd className="break-all font-mono text-xs">
                          {reviewedRotation.plan.target || "—"} / {reviewedRotation.plan.remote_key || "—"}
                        </dd>
                      </div>
                      <div>
                        <dt className="font-medium text-muted-foreground">{t("secrets.rotation.permission")}</dt>
                        <dd className="font-mono text-xs">{reviewedRotation.plan.required_permission}</dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="font-medium text-muted-foreground">{t("secrets.rotation.fingerprint")}</dt>
                        <dd className="break-all font-mono text-xs">{reviewedRotation.plan.request_fingerprint}</dd>
                      </div>
                    </dl>
                    <p className="rounded-control border border-status-info/30 bg-status-info/10 px-3 py-2 text-sm text-status-info">
                      {reviewedRotation.plan.secret_data_handling}
                    </p>
                    {reviewedRotation.plan.blockers.length > 0 && (
                      <div>
                        <h5 className="text-sm font-semibold text-risk-critical">{t("secrets.rotation.blockersHeading")}</h5>
                        <ul className="mt-1 list-disc space-y-1 ps-5 text-sm text-risk-critical">
                          {reviewedRotation.plan.blockers.map((blocker) => (
                            <li key={blocker}>{blocker}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <div className="grid gap-4 md:grid-cols-2">
                      <div>
                        <h5 className="text-sm font-semibold text-foreground">{t("secrets.rotation.executionChanges")}</h5>
                        <ul className="mt-1 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
                          {[...reviewedRotation.plan.execute_writes, ...reviewedRotation.plan.execute_external_effects].map((effect) => (
                            <li key={effect}>{effect}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <h5 className="text-sm font-semibold text-foreground">{t("secrets.rotation.recoveryHeading")}</h5>
                        <ol className="mt-1 list-decimal space-y-1 ps-5 text-sm text-muted-foreground">
                          {reviewedRotation.plan.recovery_steps.map((step) => (
                            <li key={step}>{step}</li>
                          ))}
                        </ol>
                      </div>
                    </div>
                    {reviewedRotation.plan.ready && (
                      <div>
                        <Button type="button" onClick={() => void runReviewedRollbackRotation()} disabled={rotationRunBusy}>
                          {rotationRunBusy ? (
                            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                          ) : (
                            <RotateCw className="h-4 w-4" aria-hidden="true" />
                          )}
                          {t("secrets.rotation.executeReviewed")}
                        </Button>
                      </div>
                    )}
                  </section>
                )}
                {rotationRunError && <ErrorState title={t("parity.rollbackSafeRotationFailed_5f1a57")}>{rotationRunError}</ErrorState>}
                {rotationRun && (
                  <div role="status" className="grid gap-2 rounded-control border border-border bg-background p-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge
                        vocabulary="lifecycle"
                        value={secretRotationQueued(rotationRun) ? "pending" : rotationRun.completed ? "completed" : "failed"}
                        label={
                          secretRotationQueued(rotationRun)
                            ? t("secrets.rotation.queued")
                            : rotationRun.completed
                              ? t("secrets.rotation.completed")
                              : t("secrets.rotation.failed")
                        }
                        tone={secretRotationQueued(rotationRun) ? "warning" : rotationRun.completed ? "success" : "critical"}
                      />
                      <span className="break-all font-mono text-xs">{rotationRun.key}</span>
                    </div>
                    {rotationRun.completed || secretRotationQueued(rotationRun) ? (
                      <p className="break-all font-mono text-xs">
                        {rotationRun.old_ref} → {rotationRun.new_ref}
                      </p>
                    ) : (
                      <div className="grid gap-2">
                        <p>
                          {t("parity.failedPhase_49b14a")}{" "}
                          <span className="font-mono text-xs">{rotationRun.failed_phase ?? translateNow("source.unknown.b23a6a8439")}</span>
                          {rotationRun.error ? translateNow("source.value1.ed27296cce", { value1: rotationRun.error }) : ""}
                        </p>
                        {rotationRun.rollback_failed ? (
                          <p className="rounded-control border border-risk-critical/30 bg-risk-critical/10 px-3 py-2 text-risk-critical">
                            {translateNow("source.rollback.failed.manual.intervention.requir.113a558395")}
                            {rotationRun.rollback_error ? translateNow("source.value1.eff53e36f5", { value1: rotationRun.rollback_error }) : ""}
                          </p>
                        ) : rotationRun.rolled_back ? (
                          <p className="rounded-control border border-status-info/30 bg-status-info/10 px-3 py-2 text-status-info">
                            {t("parity.theProviderWasRolledBackCleanly_3c888a")} <span className="font-mono text-xs">{rotationRun.old_ref}</span>.
                          </p>
                        ) : rotationRun.rollback_attempted ? (
                          <p className="text-muted-foreground">Rollback was attempted; check the provider state before retrying.</p>
                        ) : null}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div className="ui-panel grid gap-3 p-comfortable">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-title font-semibold">{t("parity.scheduledRotations_1a0452")}</h3>
                    <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("parity.recurringRollbackSafeRotationsRunBy_06c343")}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      onClick={() => {
                        setScheduleError(null);
                        setScheduleDialogOpen(true);
                      }}
                    >
                      {t("parity.newSchedule_729465")}
                    </Button>
                    <Button type="button" variant="outline" onClick={() => void runDueRotationsNow()} disabled={runDueBusy}>
                      {runDueBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                      {translateNow("source.run.due.now.06b5403e4c")}
                    </Button>
                  </div>
                </div>
                {runDueError && <ErrorState title={t("parity.runDueRotationsFailed_b9c511")}>{runDueError}</ErrorState>}
                {dueLimits && (dueLimits.run || dueLimits.scan) && (
                  <div
                    role="status"
                    aria-label={t("secrets.rotation.limitNoticeLabel")}
                    className="grid gap-1 rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm text-status-warning"
                  >
                    {dueLimits.run && <p>{t("secrets.rotation.runLimitNotice")}</p>}
                    {dueLimits.scan && <p>{t("secrets.rotation.scanLimitNotice")}</p>}
                  </div>
                )}
                {rotationSchedules && (
                  <DataGrid
                    ariaLabel="Scheduled secret rotations"
                    rows={rotationSchedules}
                    columns={scheduleColumns}
                    getRowId={(item) => item.id}
                    state={rotationSchedules.length === 0 ? "empty" : "ready"}
                    stateTitle="No rotation schedules"
                    stateMessage={t("secrets.rotation.scheduleStateMessage")}
                  />
                )}
                {dueDeferred.length > 0 && (
                  <div
                    role="status"
                    className="grid gap-2 rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm text-status-warning"
                  >
                    <p>{t("secrets.rotation.deferredSummary", { count: String(dueDeferred.length) })}</p>
                    <ul aria-label={t("secrets.rotation.deferredListLabel")} className="grid gap-1">
                      {dueDeferred.map((deferred) => (
                        <li
                          key={`${deferred.schedule_id}:${deferred.due_at}`}
                          className="grid gap-1 rounded-control border border-status-warning/20 px-2 py-1 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-center md:gap-3"
                        >
                          <span className="break-all font-mono text-xs">{deferred.schedule_id}</span>
                          <span>{t(secretRotationDeferredReasonKeys[deferred.reason])}</span>
                          <span>{t("secrets.rotation.deferredDueAt", { time: formatDate(deferred.due_at) })}</span>
                          {deferred.error && <span className="md:col-span-3 text-xs">{deferred.error}</span>}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {dueRuns && dueRuns.length > 0 && (
                  <ul aria-label={t("parity.latestDueRotationRuns_ac4710")} className="grid gap-2">
                    {dueRuns.map((run) => (
                      <li key={run.run_id} className="flex flex-wrap items-center gap-2 rounded-control border border-border px-3 py-2 text-sm">
                        <StatusBadge vocabulary="lifecycle" value={run.status} />
                        <span className="break-all font-mono text-xs">{run.rotation.key}</span>
                        <span className="text-muted-foreground">{formatDate(run.ran_at)}</span>
                        {run.error && <span className="text-destructive">{run.error}</span>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              {/* Known names autocomplete from the loaded store — no copy-pasting
            out of the metadata table above. */}
              <datalist id="secret-name-options">
                {items.map((item) => (
                  <option key={item.name} value={item.name} />
                ))}
              </datalist>
              <form
                aria-label={translateNow("source.rotate.secret.4405518d27")}
                onSubmit={(event) => void submitRotate(event)}
                className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
              >
                <label className="grid gap-1 text-sm" htmlFor="developer-secret-env-var">
                  <span className="font-medium">{translateNow("source.secret.to.rotate.4e6aab975e")}</span>
                  <input
                    id="developer-secret-env-var"
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={rotateName}
                    onChange={(event) => setRotateName(event.target.value)}
                    placeholder={selectedMeta?.name ?? translateNow("source.app.db.password.917cb98f9d")}
                    list="secret-name-options"
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.replacement.value.81858184c6")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    type="password"
                    value={rotateValue}
                    onChange={(event) => setRotateValue(event.target.value)}
                    required
                  />
                </label>
                <Button type="submit" className="self-end" loading={rotateBusy} disabled={Boolean(loadError)}>
                  {translateNow("source.rotate.secret.4405518d27")}
                </Button>
              </form>
              {rotateError && <ErrorState title={translateNow("source.rotation.failed.2d3e7bd0f1")}>{rotateError}</ErrorState>}

              <form
                aria-label={translateNow("source.delete.secret.1a48c8c830")}
                onSubmit={(event) => void submitDelete(event)}
                className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.secret.to.delete.6abd642165")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={deleteName}
                    onChange={(event) => setDeleteName(event.target.value)}
                    placeholder={selectedMeta?.name ?? translateNow("source.app.db.password.917cb98f9d")}
                    list="secret-name-options"
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.type.the.exact.secret.name.8106c6efde")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={deleteConfirm}
                    onChange={(event) => setDeleteConfirm(event.target.value)}
                    required
                  />
                </label>
                <Button
                  type="submit"
                  variant="destructive"
                  className="self-end"
                  loading={deleteBusy}
                  disabled={!deleteName || deleteConfirm !== deleteName || Boolean(loadError)}
                >
                  {translateNow("source.delete.secret.1a48c8c830")}
                </Button>
              </form>
              {deleteError && <ErrorState title={translateNow("source.delete.failed.8727e2ba36")}>{deleteError}</ErrorState>}
              <SecretApprovalQueue
                items={approvalQueue}
                busyKey={approvalBusy}
                canRetry={canRetryApproval}
                onApprove={(item) => void approveSecretApproval(item)}
                onRetry={(item) => void retrySecretApproval(item)}
              />
            </section>
          </details>
        </div>
      )}

      {tab === "access" && (
        <div className="grid gap-6">
          {/* C-S1 (DA-02 interim): Job 2's grant step, in-console, over the
              existing idempotent /access/api-tokens and /ephemeral/api-keys
              mutations. Create (Store tab) → grant (here) → verify the
              selected secret with that exact reveal-once bearer credential. */}
          {canGrant && (
            <section aria-labelledby="grant-access-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="grant-access-heading" className="text-title font-semibold">
                  {t("secrets.grant.heading")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.grant.description")}</p>
              </div>
              <form aria-labelledby="grant-access-heading" onSubmit={(event) => void submitGrant(event)} className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-1 text-sm" htmlFor="grant-subject">
                  <span className="font-medium">{t("secrets.grant.subject")}</span>
                  <IdentityPicker
                    id="grant-subject"
                    value={grantSubject}
                    onChange={setGrantSubject}
                    identities={grantIdentities}
                    placeholder={t("incidents.picker.identityHint")}
                    className="rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.grant.scopes")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2 font-mono"
                    value={grantScopes}
                    onChange={(event) => setGrantScopes(event.target.value)}
                    required
                  />
                </label>
                <label className="flex items-center gap-2 text-sm font-medium">
                  <input type="checkbox" checked={grantEphemeral} onChange={(event) => setGrantEphemeral(event.target.checked)} />
                  {t("secrets.grant.ephemeral")}
                </label>
                {grantEphemeral && (
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{t("secrets.grant.ttl")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      type="number"
                      min={1}
                      value={grantTTL}
                      onChange={(event) => setGrantTTL(event.target.value)}
                    />
                  </label>
                )}
                <div className="md:col-span-2">
                  <Button type="submit" disabled={grantBusy || !grantSubject.trim() || !grantScopes.trim()}>
                    {grantBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                    {t("secrets.grant.submit")}
                  </Button>
                </div>
              </form>
              {grantError && <ErrorState title={t("secrets.grant.failedTitle")}>{grantError}</ErrorState>}
              {grantResult && (
                <div role="status" className="rounded-panel border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-medium">{t("secrets.grant.revealTitle")}</p>
                    <div className="flex flex-wrap gap-2">
                      <Button type="button" size="sm" variant="outline" disabled={grantVerifyBusy} onClick={() => void verifyGrantedSecretAccess()}>
                        {grantVerifyBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                        {t("secrets.grant.verify")}
                      </Button>
                      <Button type="button" size="sm" variant="ghost" onClick={() => setGrantResult(null)}>
                        {t("secrets.grant.dismiss")}
                      </Button>
                    </div>
                  </div>
                  <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{grantResult.token}</code>
                  <p className="mt-1 text-xs text-muted-foreground">{t("secrets.grant.revealNote")}</p>
                </div>
              )}
              {grantVerifyError && <ErrorState title={t("secrets.grant.verifyFailedTitle")}>{grantVerifyError}</ErrorState>}
              {grantVerifyResult && (
                <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
                  {t("secrets.grant.verifyPassed", { name: grantVerifyResult.name, version: String(grantVerifyResult.version ?? "latest") })}
                </p>
              )}
              {canReadTokens && tokenRows && (
                <ScrollableTableRegion label={t("secrets.grant.ledgerCaption")}>
                  <table className="ui-table min-w-[44rem]">
                    <caption className="sr-only">{t("secrets.grant.ledgerCaption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("secrets.grant.ledgerSubject")}</th>
                        <th scope="col">{t("secrets.grant.ledgerScopes")}</th>
                        <th scope="col">{t("secrets.grant.ledgerStatus")}</th>
                        <th scope="col">{t("secrets.grant.ledgerExpires")}</th>
                        <th scope="col">{t("secrets.grant.ledgerActions")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tokenRows.map((token) => (
                        <tr key={token.id} className="align-top">
                          <td className="font-medium">{token.subject}</td>
                          <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                          <td>{token.revoked_at ? t("secrets.grant.statusRevoked") : t("secrets.grant.statusActive")}</td>
                          <td>{token.expires_at ? formatDate(token.expires_at) : "—"}</td>
                          <td>
                            {!token.revoked_at && (
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                disabled={revokingTokenId === token.id}
                                onClick={() => void revokeGrantedToken(token.id)}
                              >
                                <Trash2 className="h-4 w-4" aria-hidden="true" />
                                {t("secrets.grant.revoke")}
                              </Button>
                            )}
                          </td>
                        </tr>
                      ))}
                      {tokenRows.length === 0 && (
                        <tr>
                          <td colSpan={5} className="text-muted-foreground">
                            {t("secrets.grant.ledgerEmpty")}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </ScrollableTableRegion>
              )}
            </section>
          )}
          <details className="group border-y border-border py-4">
            <summary className="cursor-pointer text-title font-semibold text-foreground">{t("secrets.access.machineAdministration")}</summary>
            <div className="grid gap-6 pt-4">
              <section aria-labelledby="machine-login-heading" className="grid gap-4">
                <div>
                  <h2 id="machine-login-heading" className="text-title font-semibold">
                    {translateNow("source.machine.login.e25f8c4843")}
                  </h2>
                  <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.exchange.a.machine.credential.for.a.scoped.db8919fe53")}</p>
                </div>
                <MachineAuthWorkflow methods={authMethods} loadBlocked={Boolean(loadError)} onSessionIssued={refreshMachineSessions} />
              </section>

              {/* C-S4 (DA-02 faithful): the auth-method console over the C-S2/C-S3
              endpoints. The DA-02 dead-end placeholder is dead —
              methods (with the per-tenant disable overlay) and the issued-
              session ledger are served surfaces now. Methods stay declared in
              server config: the console projects and overlays, it never edits
              config. */}
              <section aria-labelledby="auth-methods-heading" className="grid gap-4 border-t border-border pt-4">
                <div>
                  <h2 id="auth-methods-heading" className="text-title font-semibold">
                    {t("secrets.methods.heading")}
                  </h2>
                  <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.methods.description")}</p>
                </div>
                {methodError && <ErrorState title={t("secrets.methods.failedTitle")}>{methodError}</ErrorState>}
                {authMethods === null ? (
                  <p className="text-sm text-muted-foreground">{machineAuthMethodList.unavailable?.detail ?? t("secrets.methods.unavailable")}</p>
                ) : (
                  <ScrollableTableRegion className="rounded-panel" label={t("secrets.methods.heading")}>
                    <table className="ui-table min-w-[52rem]">
                      <caption className="sr-only">{t("secrets.methods.heading")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("secrets.methods.name")}</th>
                          <th scope="col">{t("secrets.methods.type")}</th>
                          <th scope="col">{t("secrets.methods.issuer")}</th>
                          <th scope="col">{t("secrets.methods.audience")}</th>
                          <th scope="col">{t("secrets.methods.scopes")}</th>
                          <th scope="col">{t("secrets.methods.source")}</th>
                          <th scope="col">{t("secrets.methods.status")}</th>
                          {canAdminMethods && <th scope="col">{t("secrets.methods.actions")}</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {authMethods.map((method) => (
                          <tr key={method.name} className="align-top">
                            <td className="font-medium">{method.name}</td>
                            <td className="font-mono text-xs">{method.type}</td>
                            <td className="break-all font-mono text-xs">{method.issuer || "—"}</td>
                            <td className="break-all font-mono text-xs">{method.audience || "—"}</td>
                            <td className="font-mono text-xs">
                              {method.scopes?.length
                                ? method.scopes.join(", ")
                                : method.scopes_by_principal
                                  ? t("secrets.methods.perPrincipal", { count: String(Object.keys(method.scopes_by_principal).length) })
                                  : "—"}
                            </td>
                            <td>{method.source}</td>
                            <td>{method.disabled ? t("secrets.methods.disabled") : t("secrets.methods.enabled")}</td>
                            {canAdminMethods && (
                              <td>
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  disabled={methodBusy === method.name}
                                  onClick={() => void toggleAuthMethod(method.name, !method.disabled)}
                                >
                                  {method.disabled ? t("secrets.methods.enable") : t("secrets.methods.disable")}
                                </Button>
                              </td>
                            )}
                          </tr>
                        ))}
                        {authMethods.length === 0 && (
                          <tr>
                            <td colSpan={canAdminMethods ? 8 : 7} className="text-muted-foreground">
                              {t("secrets.methods.empty")}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </ScrollableTableRegion>
                )}
              </section>

              <section aria-labelledby="machine-sessions-heading" className="grid gap-4 border-t border-border pt-4">
                <div>
                  <h2 id="machine-sessions-heading" className="text-title font-semibold">
                    {t("secrets.sessions.heading")}
                  </h2>
                  <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.sessions.description")}</p>
                </div>
                {sessionError && <ErrorState title={t("secrets.sessions.failedTitle")}>{sessionError}</ErrorState>}
                {machineSessions === null ? (
                  <p className="text-sm text-muted-foreground">{machineSessionList.unavailable?.detail ?? t("secrets.sessions.unavailable")}</p>
                ) : (
                  <ScrollableTableRegion className="rounded-panel" label={t("secrets.sessions.heading")}>
                    <table className="ui-table min-w-[52rem]">
                      <caption className="sr-only">{t("secrets.sessions.heading")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("secrets.sessions.principal")}</th>
                          <th scope="col">{t("secrets.sessions.method")}</th>
                          <th scope="col">{t("secrets.sessions.scopes")}</th>
                          <th scope="col">{t("secrets.sessions.status")}</th>
                          <th scope="col">{t("secrets.sessions.issued")}</th>
                          <th scope="col">{t("secrets.sessions.expires")}</th>
                          {canAdminMethods && <th scope="col">{t("secrets.sessions.actions")}</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {machineSessions.map((row) => (
                          <tr key={row.id} className="align-top">
                            <td className="font-medium">{row.principal}</td>
                            <td className="font-mono text-xs">{row.method}</td>
                            <td className="font-mono text-xs">{row.scopes?.join(", ") || "—"}</td>
                            <td>{row.status}</td>
                            <td>{formatDate(row.issued_at)}</td>
                            <td>{formatDate(row.expires_at)}</td>
                            {canAdminMethods && (
                              <td>
                                {row.status === "active" && (
                                  <Button
                                    type="button"
                                    size="sm"
                                    variant="outline"
                                    disabled={sessionBusy === row.id}
                                    onClick={() => void revokeMachineSessionRow(row.id)}
                                  >
                                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                                    {t("secrets.sessions.revoke")}
                                  </Button>
                                )}
                              </td>
                            )}
                          </tr>
                        ))}
                        {machineSessions.length === 0 && (
                          <tr>
                            <td colSpan={canAdminMethods ? 7 : 6} className="text-muted-foreground">
                              {t("secrets.sessions.empty")}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </ScrollableTableRegion>
                )}
              </section>
            </div>
          </details>
        </div>
      )}

      {tab === "developer" && (
        <div className="grid gap-6">
          <section aria-labelledby="developer-heading" className="grid gap-5 border-y border-border py-4">
            <div>
              <h2 id="developer-heading" className="text-title font-semibold">
                {t("secrets.developer.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.developer.description")}</p>
            </div>

            <form aria-label={t("secrets.developer.reviewForm")} onSubmit={(event) => void reviewAccess(event)} className="ui-panel grid gap-4 p-comfortable">
              <div className="grid gap-4 md:grid-cols-2">
                <label className="grid gap-1 text-sm" htmlFor="developer-secret-name">
                  <span className="font-medium">{t("secrets.developer.secretName")}</span>
                  <input
                    id="developer-secret-name"
                    className="min-h-10 rounded-control border border-border bg-background px-3 py-2"
                    value={accessName}
                    onChange={(event) => {
                      invalidateAccessReview();
                      setAccessName(event.target.value);
                    }}
                    placeholder={translateNow("source.app.db.password.917cb98f9d")}
                    list="developer-secret-options"
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.developer.envVar")}</span>
                  <input
                    className="min-h-10 rounded-control border border-border bg-background px-3 py-2 font-mono"
                    value={accessEnvVar}
                    onChange={(event) => {
                      invalidateAccessReview();
                      setAccessEnvVar(event.target.value);
                    }}
                    placeholder={t("secrets.developer.envVarPlaceholder")}
                    required
                  />
                </label>
              </div>
              <datalist id="developer-secret-options">
                {items.map((item) => (
                  <option key={item.name} value={item.name} />
                ))}
              </datalist>
              <div className="flex items-start gap-2 text-sm">
                <input
                  id="developer-secret-resolve"
                  type="checkbox"
                  aria-labelledby="developer-secret-resolve-label"
                  aria-describedby="developer-secret-resolve-help"
                  checked={accessResolve}
                  onChange={(event) => {
                    invalidateAccessReview();
                    setAccessResolve(event.target.checked);
                  }}
                />
                <span>
                  <strong id="developer-secret-resolve-label" className="block">
                    {t("secrets.developer.resolve")}
                  </strong>
                  <span id="developer-secret-resolve-help" className="text-muted-foreground">
                    {t("secrets.developer.resolveHelp")}
                  </span>
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button type="submit" disabled={accessReviewBusy || accessBusy || Boolean(loadError) || !accessRequest.name || !accessRequest.env_var}>
                  {accessReviewBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  {t("secrets.developer.reviewAction")}
                </Button>
                <p className="text-sm text-muted-foreground">{t("secrets.developer.reviewHelp")}</p>
              </div>
            </form>

            {accessReviewStale && !reviewedAccess && (
              <p role="status" className="rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm text-status-warning">
                {t("secrets.developer.stale")}
              </p>
            )}
            {accessReviewError && <ErrorState title={t("secrets.developer.reviewFailed")}>{accessReviewError}</ErrorState>}

            {reviewedAccess && (
              <section aria-label={t("secrets.developer.reviewedPlan")} className="ui-panel grid gap-5 p-comfortable">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-title font-semibold">{t(reviewedAccess.plan.ready ? "secrets.developer.ready" : "secrets.developer.blocked")}</h3>
                    <p className="mt-1 text-sm text-muted-foreground">{t("secrets.developer.noEffects")}</p>
                  </div>
                  <StatusBadge
                    value={reviewedAccess.plan.ready ? "ready" : "blocked"}
                    label={t(reviewedAccess.plan.ready ? "secrets.developer.readyBadge" : "secrets.developer.blockedBadge")}
                    tone={reviewedAccess.plan.ready ? "success" : "warning"}
                  />
                </div>
                <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
                  <div>
                    <dt className="text-muted-foreground">{t("secrets.developer.secretName")}</dt>
                    <dd className="break-all font-medium">{reviewedAccess.plan.name}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t("secrets.developer.version")}</dt>
                    <dd>{reviewedAccess.plan.version ?? t("secrets.developer.notAvailable")}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t("secrets.developer.permission")}</dt>
                    <dd className="font-mono text-xs">{reviewedAccess.plan.required_permission}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t("secrets.developer.references")}</dt>
                    <dd>{t(reviewedAccess.plan.resolve_references ? "secrets.developer.enabled" : "secrets.developer.disabled")}</dd>
                  </div>
                </dl>
                {reviewedAccess.plan.blockers.length > 0 && (
                  <ul aria-label={t("secrets.developer.blockers")} className="list-disc space-y-1 pl-5 text-sm text-destructive">
                    {reviewedAccess.plan.blockers.map((blocker) => (
                      <li key={blocker}>{blocker}</li>
                    ))}
                  </ul>
                )}
                <div className="grid gap-3 xl:grid-cols-3">
                  <Snippet title={t("secrets.developer.cli")} text={formatCommandArgv(reviewedAccess.plan.cli_argv)} />
                  <Snippet title={t("secrets.developer.typescript")} text={reviewedAccess.plan.typescript} />
                  <Snippet title={t("secrets.developer.http")} text={`${reviewedAccess.plan.api_request.method} ${reviewedAccess.plan.api_request.path}`} />
                </div>
                <p className="text-sm text-muted-foreground">{reviewedAccess.plan.secret_data_handling}</p>
                <details className="rounded-control border border-border px-3 py-2">
                  <summary className="cursor-pointer text-sm font-medium">{t("secrets.developer.technicalDetails")}</summary>
                  <div className="mt-3 grid gap-3 text-sm md:grid-cols-3">
                    <div>
                      <h4 className="font-medium">{t("secrets.developer.executeReads")}</h4>
                      <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                        {reviewedAccess.plan.execute_reads.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <h4 className="font-medium">{t("secrets.developer.recovery")}</h4>
                      <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                        {reviewedAccess.plan.recovery_steps.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <h4 className="font-medium">{t("secrets.developer.verification")}</h4>
                      <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                        {reviewedAccess.plan.verification_steps.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </details>
                {accessError && <ErrorState title={t("secrets.developer.testFailed")}>{accessError}</ErrorState>}
                {reviewedAccess.plan.ready && (
                  <Button type="button" className="w-fit" onClick={() => void runAccessTest()} disabled={accessBusy}>
                    {accessBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                    {t(accessError ? "secrets.developer.retryAction" : "secrets.developer.runAction")}
                  </Button>
                )}
              </section>
            )}

            {accessResult && (
              <div
                role="status"
                className="grid gap-1 rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success"
              >
                <strong>{t("secrets.developer.verified", { name: accessResult.name, version: String(accessResult.version ?? "latest") })}</strong>
                <span>{t("secrets.developer.verifiedHelp")}</span>
                <code className="break-all text-xs">{accessResult.fingerprint}</code>
              </div>
            )}

            <SecretImport reason={reviewedAccess?.plan.bulk_import.reason} safePath={reviewedAccess?.plan.bulk_import.safe_path} />
          </section>
        </div>
      )}

      {tab === "sharing" && (
        <div className="grid gap-6">
          <ProgressiveTaskList
            heading={t("progressiveTasks.heading")}
            description={t("progressiveTasks.description")}
            activeTask={sharingTask}
            closeLabel={t("progressiveTasks.close")}
            onTaskChange={(task) => setSharingTask(task as typeof sharingTask)}
            tasks={[
              {
                id: "share",
                title: t("secrets.tasks.share.title"),
                description: t("secrets.tasks.share.description"),
                actionLabel: t("secrets.tasks.share.action"),
              },
              {
                id: "machine",
                title: t("secrets.tasks.machineCredential.title"),
                description: t("secrets.tasks.machineCredential.description"),
                actionLabel: t("secrets.tasks.machineCredential.action"),
              },
            ]}
          />

          {sharingTask === "share" && (
            <Suspense fallback={<div className="min-h-24 animate-pulse rounded-md bg-muted" aria-hidden="true" />}>
              <SecretSharingWorkflow
                approvalItems={approvalQueue}
                approvalBusyKey={approvalBusy}
                canRetryApproval={canRetryApproval}
                onApprove={(item) => void approveSecretApproval(item)}
                onRetryApproval={(item) => void retrySecretApproval(item)}
                blocked={Boolean(loadError)}
              />
            </Suspense>
          )}

          {sharingTask === "machine" && (
            <Suspense fallback={<div className="min-h-24 animate-pulse rounded-md bg-muted" aria-hidden="true" />}>
              <EphemeralAPIKeyWorkflow canGrant={canGrant} nativeStoreUnavailable={Boolean(loadError)} />
            </Suspense>
          )}

          {sharingTask === "machine" && (
            <section className="grid gap-4">
              <div className="grid gap-4 border-t border-border pt-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.7fr)]">
                <form
                  aria-label={t("parity.requestAttestationGatedEphemeralCredential_4ce3ce")}
                  onSubmit={(event) => void submitEphemeralCredential(event)}
                  className="grid content-start gap-3"
                >
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.requestId_63aa59")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={credentialRequestID}
                      onChange={(event) => setCredentialRequestID(event.target.value)}
                      placeholder={t("parity.req7c2f9a_03dd4e")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.attestation.method.1f0610be7c")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={credentialMethod}
                      onChange={(event) => setCredentialMethod(event.target.value)}
                      placeholder={t("parity.tpmQuote_f72300")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.attestationPayloadBase64_b7cf3a")}
                    <textarea
                      className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                      value={credentialPayload}
                      onChange={(event) => setCredentialPayload(event.target.value)}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.publicKeyPem_10749e")}
                    <textarea
                      className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                      value={credentialPublicKey}
                      onChange={(event) => setCredentialPublicKey(event.target.value)}
                      placeholder={translateNow("source.begin.public.key.59a58325e8")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.ttlSecondsOptional_68f1c5")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      type="number"
                      min="60"
                      value={credentialTTL}
                      onChange={(event) => setCredentialTTL(event.target.value)}
                    />
                  </label>
                  <Button type="submit" disabled={credentialBusy || Boolean(loadError)}>
                    {credentialBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                    {translateNow("source.request.credential.014a4a64ca")}
                  </Button>
                  {credentialError && <ErrorState title={t("parity.ephemeralCredentialRequestFailed_12be63")}>{credentialError}</ErrorState>}
                </form>
                <div className="ui-panel grid content-start gap-2 p-comfortable text-sm">
                  <h3 className="text-title font-semibold">{t("parity.attestationGatedCredentials_2887bd")}</h3>
                  <p className="text-muted-foreground">
                    Submit workload attestation and a public key to mint a just-in-time credential. When approval quorum applies, the request waits for
                    approvers; share the request ID with an approver to finish issuance.
                  </p>
                </div>
              </div>
              {credential && (
                <div className="ui-panel grid gap-3 p-comfortable text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    {credential.state === "issued" ? (
                      <StatusBadge vocabulary="lifecycle" value="issued" label="Issued" tone="success" />
                    ) : (
                      <StatusBadge
                        vocabulary="lifecycle"
                        value="awaiting_approval"
                        label={`Awaiting approval — ${credential.approvals} of ${credential.required_approvals} approvals`}
                        tone="warning"
                      />
                    )}
                    <span className="text-muted-foreground">
                      {translateNow("source.subject.6897128384")} <span className="font-medium text-foreground">{credential.subject}</span>{" "}
                      {translateNow("source.expires.1de5fe01e9")} {formatDate(credential.expires_at)}
                    </span>
                  </div>
                  {credential.state === "awaiting_approval" && (
                    <div className="grid gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-control border border-border bg-muted px-2.5 py-1.5 font-mono text-xs">{credential.request_id}</span>
                        <Button type="button" size="sm" variant="outline" onClick={() => void copyCredentialField("request_id", credential.request_id)}>
                          <Copy className="h-4 w-4" aria-hidden="true" />
                          {t("parity.copyRequestId_a53908")}
                        </Button>
                        {credentialCopied === "request_id" && <span className="text-xs text-muted-foreground">{t("parity.copied_dd2ce2")}</span>}
                      </div>
                      <p className="text-muted-foreground">{t("parity.approversCanIssueThisFromThe_33b073")}</p>
                    </div>
                  )}
                  {credential.state === "issued" && credential.certificate_pem && (
                    <div className="grid gap-2">
                      <pre className="max-h-48 overflow-auto rounded bg-muted px-3 py-2 font-mono text-xs">{credential.certificate_pem}</pre>
                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => void copyCredentialField("certificate", credential.certificate_pem ?? "")}
                        >
                          <Copy className="h-4 w-4" aria-hidden="true" />
                          {t("parity.copyCertificate_59db8a")}
                        </Button>
                        {credentialCopied === "certificate" && <span className="text-xs text-muted-foreground">{t("parity.copied_dd2ce2")}</span>}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>
          )}
        </div>
      )}

      {tab === "scanning" && (
        <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">
          <SecretScanningWorkflow repoPosture={repoScanPosture} thirdPartyPosture={thirdPartyPosture} loadingBlocked={Boolean(loadError)} />
        </div>
      )}

      {tab === "engines" && (
        <div className="grid gap-6">
          <ProgressiveTaskList
            heading={t("progressiveTasks.heading")}
            description={t("progressiveTasks.description")}
            activeTask={engineTask}
            closeLabel={t("progressiveTasks.close")}
            onTaskChange={(task) => setEngineTask(task as typeof engineTask)}
            tasks={[
              {
                id: "dynamic",
                title: t("secrets.tasks.dynamic.title"),
                description: t("secrets.tasks.dynamic.description"),
                actionLabel: t("secrets.tasks.dynamic.action"),
              },
              {
                id: "transit",
                title: t("secrets.tasks.transit.title"),
                description: t("secrets.tasks.transit.description"),
                actionLabel: t("secrets.tasks.transit.action"),
              },
              {
                id: "pki",
                title: t("secrets.tasks.pki.title"),
                description: t("secrets.tasks.pki.description"),
                actionLabel: t("secrets.tasks.pki.action"),
              },
            ]}
          />

          {engineTask === "dynamic" && (
            <div id="task-panel-dynamic" className="border-y border-border py-4">
              {/* TRACE-005 served contract: dynamic secret leases are served by
                  POST /api/v1/secrets/leases and require secrets:read. The
                  workflow below renders the effect-free review, one-time
                  credential reveal, durable metadata, renewal, and revocation. */}
              <DynamicSecretWorkflow loadBlocked={Boolean(loadError)} />
            </div>
          )}

          {engineTask === "transit" && (
            <Suspense fallback={<SecretsWorkflowFallback />}>
              <TransitOperations nativeStoreUnavailable={Boolean(loadError)} />
            </Suspense>
          )}

          {engineTask === "pki" && (
            <section id="task-panel-pki" aria-labelledby="pki-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="pki-heading" className="text-title font-semibold">
                  {translateNow("source.pki.as.a.secret.e349ae9d0f")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.issue.a.short.lived.certificate.bundle.and.68b22cee4d")}</p>
              </div>
              <PKISecretWorkflow loadBlocked={Boolean(loadError)} />
            </section>
          )}
        </div>
      )}

      {tab === "sync" && (
        <div className="grid gap-6">
          <section aria-labelledby="secret-sync-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="secret-sync-heading" className="text-title font-semibold">
                {translateNow("source.secret.sync.and.platform.integrations.90c8c57a01")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Push a stored secret to a configured target. The browser sends the secret name and remote key only; the stored value is never rendered here.
              </p>
            </div>
            <details className="ui-panel group order-1 p-comfortable">
              <summary className="cursor-pointer font-medium text-foreground">
                {t("secrets.sync.evidenceSummary")}
                <span className="ms-2 text-sm font-normal text-muted-foreground">{t("secrets.sync.evidenceSummaryHelp")}</span>
              </summary>
              <div className="mt-4 grid gap-4">
                {cloudManagers && (
                  <div className="ui-panel grid gap-3 p-comfortable text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">{cloudManagers.capability}</span>
                      <span className="text-muted-foreground">
                        {t("secrets.cloudManagers.coverage", {
                          discovery: cloudManagers.summary.discovery_configured,
                          sync: cloudManagers.summary.sync_configured,
                        })}
                      </span>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="ui-table min-w-[58rem]">
                        <caption className="sr-only">{t("secrets.cloudManagers.caption")}</caption>
                        <thead>
                          <tr>
                            <th scope="col">{t("secrets.cloudManagers.provider")}</th>
                            <th scope="col">{t("secrets.cloudManagers.discovery")}</th>
                            <th scope="col">{t("secrets.cloudManagers.sync")}</th>
                            <th scope="col">{t("secrets.cloudManagers.handling")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {cloudManagers.providers.map((provider) => (
                            <tr key={provider.id}>
                              <td>
                                <span className="font-medium">{provider.name}</span>
                                <span className="block font-mono text-xs text-muted-foreground">{provider.id}</span>
                              </td>
                              <td>
                                {provider.discovery_configured
                                  ? t("secrets.cloudManagers.discoveryConfigured", { count: provider.discovery_source_count })
                                  : provider.discovery_supported
                                    ? t("secrets.cloudManagers.discoveryAvailable")
                                    : t("secrets.cloudManagers.notSupported")}
                              </td>
                              <td>
                                {provider.sync_configured
                                  ? t("secrets.cloudManagers.syncConfigured")
                                  : provider.sync_supported
                                    ? t("secrets.cloudManagers.syncAvailable")
                                    : t("secrets.cloudManagers.notSupported")}
                              </td>
                              <td>{provider.secret_handling}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {cloudManagers.residuals.length > 0 && (
                      <ul className="grid gap-1 text-xs text-muted-foreground">
                        {cloudManagers.residuals.slice(0, 2).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
                {syncCatalog && (
                  <div className="ui-panel grid gap-3 p-comfortable text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">{syncCatalog.capability}</span>
                      <span className="text-muted-foreground">{t("secrets.sync.configuredCount", { count: syncCatalog.configured_targets.length })}</span>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="ui-table min-w-[54rem]">
                        <caption className="sr-only">{t("secrets.sync.catalogCaption")}</caption>
                        <thead>
                          <tr>
                            <th scope="col">{t("secrets.sync.target")}</th>
                            <th scope="col">{t("secrets.sync.platform")}</th>
                            <th scope="col">{t("secrets.sync.status")}</th>
                            <th scope="col">{t("secrets.sync.delivery")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {syncCatalog.targets.map((target) => (
                            <tr key={target.id}>
                              <td>
                                <span className="font-medium">{target.name}</span>
                                <span className="block font-mono text-xs text-muted-foreground">{target.id}</span>
                              </td>
                              <td>{target.platform}</td>
                              <td>{target.configured ? t("secrets.sync.configured") : t("secrets.sync.available")}</td>
                              <td>{target.delivery_mode}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
                {operatorPosture && (
                  <div className="ui-panel grid gap-3 p-comfortable text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">
                        {operatorPosture.capability}
                      </span>
                      <span className="text-muted-foreground">{t("secrets.sync.operatorCoverage")}</span>
                    </div>
                    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.operatorCRDs")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {operatorPosture.crds.map((crd) => (
                            <span key={crd.kind} className="rounded-control border border-border px-2 py-1 font-mono text-xs">
                              {crd.kind} - {crd.status}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.operatorReloadWorkloads")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {operatorPosture.reload_workloads.map((kind) => (
                            <span key={kind} className="rounded-control border border-border px-2 py-1 text-xs">
                              {kind}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <p className="max-w-3xl text-sm text-muted-foreground">{operatorPosture.secret_handling}</p>
                    {operatorPosture.residuals.length > 0 && (
                      <ul className="grid gap-1 text-xs text-muted-foreground">
                        {operatorPosture.residuals.slice(0, 2).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
                {workloadInjection && (
                  <div className="ui-panel grid gap-3 p-comfortable text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">
                        {workloadInjection.capability}
                      </span>
                      <span className="text-muted-foreground">{t("secrets.sync.injectionCoverage")}</span>
                    </div>
                    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.injectionCRD")}</Eyebrow>
                        <span className="rounded-control border border-border px-2 py-1 font-mono text-xs">
                          {workloadInjection.crd.kind} - {workloadInjection.crd.status}
                        </span>
                      </div>
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.injectionModes")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {workloadInjection.modes.map((mode) => (
                            <span key={mode.id} className="rounded-control border border-border px-2 py-1 text-xs">
                              {mode.name}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.injectionWorkloads")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {workloadInjection.workload_kinds.map((kind) => (
                            <span key={kind} className="rounded-control border border-border px-2 py-1 text-xs">
                              {kind}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <p className="max-w-3xl text-sm text-muted-foreground">{workloadInjection.secret_handling}</p>
                    {workloadInjection.residuals.length > 0 && (
                      <ul className="grid gap-1 text-xs text-muted-foreground">
                        {workloadInjection.residuals.slice(0, 2).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
                {unvaultedPosture && (
                  <div className="ui-panel grid gap-3 p-comfortable text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">
                        {unvaultedPosture.capability}
                      </span>
                      <span className="text-muted-foreground">
                        {t("secrets.sync.unvaultedCoverage", {
                          findings: unvaultedPosture.summary.leaked_secret_findings,
                          vaults: unvaultedPosture.summary.vault_providers_visible,
                          sync: unvaultedPosture.summary.sync_targets_configured,
                        })}
                      </span>
                    </div>
                    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.unvaultedDetection")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {unvaultedPosture.detection_sources.map((source) => (
                            <span key={source.id} className="rounded-control border border-border px-2 py-1 text-xs">
                              {source.name}: {source.configured_count}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.unvaultedVaults")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {unvaultedPosture.vault_providers
                            .filter((provider) => provider.discovery_configured)
                            .map((provider) => (
                              <span key={provider.id} className="rounded-control border border-border px-2 py-1 text-xs">
                                {provider.name}
                              </span>
                            ))}
                        </div>
                      </div>
                      <div className="grid gap-2">
                        <Eyebrow>{t("secrets.sync.unvaultedSyncTargets")}</Eyebrow>
                        <div className="flex flex-wrap gap-2">
                          {unvaultedPosture.configured_sync_targets.map((target) => (
                            <span key={target} className="rounded-control border border-border px-2 py-1 font-mono text-xs">
                              {target}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <p className="max-w-3xl text-sm text-muted-foreground">{unvaultedPosture.secret_handling}</p>
                    {unvaultedPosture.residuals.length > 0 && (
                      <ul className="grid gap-1 text-xs text-muted-foreground">
                        {unvaultedPosture.residuals.slice(0, 2).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
                <SecretSyncWorkloadIdentityPanel />
              </div>
            </details>
            <SecretSyncWorkflow catalog={syncCatalog} initialName={selectedMeta?.name ?? ""} loadBlocked={Boolean(loadError)} />
          </section>
        </div>
      )}

      {scheduleDialogOpen && (
        <Dialog
          open
          onClose={closeScheduleDialog}
          titleId="rotation-schedule-heading"
          descriptionId="rotation-schedule-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="rotation-schedule-heading" className="text-title font-semibold">
              {t("parity.newRotationSchedule_0d2b93")}
            </h2>
            <p id="rotation-schedule-description" className="mt-1 text-sm text-muted-foreground">
              {t("secrets.rotation.scheduleDescription")}
            </p>
          </header>
          <form aria-label={t("parity.createRotationSchedule_6a80bd")} className="grid gap-4 p-5" onSubmit={(event) => void submitRotationSchedule(event)}>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.scheduleName_fb63dc")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                value={scheduleName}
                onChange={(event) => setScheduleName(event.target.value)}
                placeholder={t("parity.paymentsDbMonthly_b690bc")}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              {translateNow("source.key.99a52df3ff")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                value={scheduleKey}
                onChange={(event) => setScheduleKey(event.target.value)}
                placeholder={t("parity.paymentsDbPassword_50e8d6")}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.oldReference_69d1f6")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                value={scheduleOldRef}
                onChange={(event) => setScheduleOldRef(event.target.value)}
                placeholder="ref:v3"
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              {translateNow("source.provider.472590ae97")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                list="secret-rotation-provider-options"
                value={scheduleProvider}
                onChange={(event) => setScheduleProvider(event.target.value)}
                placeholder={t("secrets.rotation.scheduleProviderPlaceholder")}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              {translateNow("source.interval.seconds.5f0f5b832a")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                type="number"
                min="60"
                value={scheduleInterval}
                onChange={(event) => setScheduleInterval(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.firstRunOptional_7ecf76")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                type="datetime-local"
                value={scheduleNextRunAt}
                onChange={(event) => setScheduleNextRunAt(event.target.value)}
              />
            </label>
            <label className="flex items-center gap-2 text-body font-medium">
              <input type="checkbox" checked={scheduleEnabled} onChange={(event) => setScheduleEnabled(event.target.checked)} />
              {translateNow("source.enabled.92c1cdfdf4")}
            </label>
            {scheduleError && (
              <p role="alert" className="text-sm text-destructive">
                {scheduleError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={closeScheduleDialog}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={scheduleBusy}>
                {scheduleBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                {translateNow("source.create.schedule.5b08f3c719")}
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </section>
  );
}

function formatRotationInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "-";
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
