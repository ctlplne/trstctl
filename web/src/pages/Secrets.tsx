import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { Copy, Eye, KeyRound, Loader2, LogIn, RefreshCw, RotateCw, Share2, Trash2 } from "lucide-react";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { IdentityPicker } from "@/components/IdentityPicker";
import { ModuleKpiStrip } from "@/components/ModuleKpiStrip";
import { useCan } from "@/components/rbac";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { SecretTree, ReferenceResolver, EnvDiffPanel, VersionHistory, SecretImport } from "@/components/secrets";
import { formatDateTime as formatDate } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  ApiError,
  api,
  type APIToken,
  type CloudSecretManagerIntegration,
  type DynamicLease,
  type EphemeralAPIKey,
  type EphemeralCredential,
  type Identity,
  type KubernetesSecretOperator,
  type MachineAuthMethod,
  type MachineLoginResponse,
  type MachineSession as MachineSessionRecord,
  type PKISecret,
  type SecretApprovalAction,
  type SecretMeta,
  type SecretRepositoryScanPosture,
  type SecretRotation,
  type SecretRotationSchedule,
  type SecretRotationScheduleRun,
  type SecretScan,
  type SecretSync,
  type SecretSyncTargetCatalog,
  type SecretWorkloadInjection,
  type ThirdPartySecretScanPosture,
  type ThirdPartySecretScanReceipt,
  type UnvaultedSecretPosture,
  type SecretValue,
  type ShareToken,
  type ShareValue,
  type TransitCiphertext,
  type TransitHMAC,
  type TransitSignature,
} from "@/lib/api";
import {
  DynamicLeaseMetadata,
  MachineSession,
  RepositoryScanPosture,
  RevealPanel,
  SecretApprovalQueue,
  Snippet,
  ThirdPartyScanPosture,
  apiProblemMessage,
  decodeTransitBytes,
  defaultThirdPartyProviders,
  encodeTransitBytes,
  leaseMetadataOnly,
  mergeMeta,
  parseScopeList,
  secretApprovalActionLabel,
  secretApprovalQueueID,
  type SecretApprovalQueueItem,
} from "./secrets/SecretsPageParts";

/** The store (tree + table + lifecycle) renders first; every other workflow
 * lives behind a workspace tab instead of stacking into a ~6,800px scroll
 * (audit P0: mega-page pattern). */
type SecretsTab = "store" | "access" | "sharing" | "engines" | "scanning" | "sync";
const secretsTabIds: readonly SecretsTab[] = ["store", "access", "sharing", "engines", "scanning", "sync"];

function secretsTabFromSearchParam(value: string | null): SecretsTab {
  return secretsTabIds.includes(value as SecretsTab) ? (value as SecretsTab) : "store";
}

export function Secrets() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState<SecretsTab>(() => secretsTabFromSearchParam(searchParams.get("tab")));
  const [items, setItems] = useState<SecretMeta[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [secretSearch, setSecretSearch] = useState("");
  const [detailSecretName, setDetailSecretName] = useState<string | null>(null);

  const [createName, setCreateName] = useState("");
  const [createValue, setCreateValue] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

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
  const [accessResult, setAccessResult] = useState<{ name: string; version?: number } | null>(null);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  const [pkiName, setPkiName] = useState("");
  const [pkiTTL, setPkiTTL] = useState("900");
  const [pkiBusy, setPkiBusy] = useState(false);
  const [pkiError, setPkiError] = useState<string | null>(null);
  const [pkiBundle, setPkiBundle] = useState<PKISecret | null>(null);

  const [loginMethod, setLoginMethod] = useState("token");
  const [loginCredential, setLoginCredential] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [session, setSession] = useState<MachineLoginResponse | null>(null);
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

  const [shareValueInput, setShareValueInput] = useState("");
  const [shareTTL, setShareTTL] = useState("300");
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareToken, setShareToken] = useState<ShareToken | null>(null);
  const [redeemToken, setRedeemToken] = useState("");
  const [redeemBusy, setRedeemBusy] = useState(false);
  const [redeemError, setRedeemError] = useState<string | null>(null);
  const [redeemed, setRedeemed] = useState<ShareValue | null>(null);

  const [ephemeralSubject, setEphemeralSubject] = useState("");
  const [ephemeralScopes, setEphemeralScopes] = useState("");
  const [ephemeralTTL, setEphemeralTTL] = useState("900");
  const [ephemeralBusy, setEphemeralBusy] = useState(false);
  const [ephemeralError, setEphemeralError] = useState<string | null>(null);
  const [ephemeralKey, setEphemeralKey] = useState<EphemeralAPIKey | null>(null);

  const [leaseProvider, setLeaseProvider] = useState("postgresql");
  const [leaseRole, setLeaseRole] = useState("");
  const [leaseTTL, setLeaseTTL] = useState("1200");
  const [leaseExtendSeconds, setLeaseExtendSeconds] = useState("300");
  const [leaseBusy, setLeaseBusy] = useState<"issue" | "renew" | "revoke" | null>(null);
  const [leaseError, setLeaseError] = useState<string | null>(null);
  const [lease, setLease] = useState<DynamicLease | null>(null);
  const [leaseCredential, setLeaseCredential] = useState<{ id: string; credential: string } | null>(null);

  const [transitKey, setTransitKey] = useState("");
  const [transitPlaintext, setTransitPlaintext] = useState("");
  const [transitAAD, setTransitAAD] = useState("");
  const [transitCiphertextInput, setTransitCiphertextInput] = useState("");
  const [transitMessage, setTransitMessage] = useState("");
  const [transitBusy, setTransitBusy] = useState<"encrypt" | "decrypt" | "hmac" | "rewrap" | "sign" | null>(null);
  const [transitError, setTransitError] = useState<string | null>(null);
  const [transitCiphertext, setTransitCiphertext] = useState<TransitCiphertext | null>(null);
  const [transitPlaintextResult, setTransitPlaintextResult] = useState<string | null>(null);
  const [transitHMACResult, setTransitHMACResult] = useState<TransitHMAC | null>(null);
  const [transitSignature, setTransitSignature] = useState<TransitSignature | null>(null);

  const [scanPath, setScanPath] = useState("");
  const [scanMode, setScanMode] = useState<"workspace" | "git_history">("workspace");
  const [scanCustomRulesPath, setScanCustomRulesPath] = useState("");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<SecretScan | null>(null);
  const [repoScanPosture, setRepoScanPosture] = useState<SecretRepositoryScanPosture | null>(null);
  const [thirdPartyPosture, setThirdPartyPosture] = useState<ThirdPartySecretScanPosture | null>(null);
  const [thirdPartyProvider, setThirdPartyProvider] = useState("cicd_log");
  const [thirdPartySource, setThirdPartySource] = useState("");
  const [thirdPartyArtifactPath, setThirdPartyArtifactPath] = useState("");
  const [thirdPartyEvent, setThirdPartyEvent] = useState("");
  const [thirdPartyBusy, setThirdPartyBusy] = useState(false);
  const [thirdPartyError, setThirdPartyError] = useState<string | null>(null);
  const [thirdPartyReceipt, setThirdPartyReceipt] = useState<ThirdPartySecretScanReceipt | null>(null);

  const [syncName, setSyncName] = useState("");
  const [syncTarget, setSyncTarget] = useState("");
  const [syncRemoteKey, setSyncRemoteKey] = useState("");
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [syncResult, setSyncResult] = useState<SecretSync | null>(null);
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
  const [rotationRunTTL, setRotationRunTTL] = useState("");
  const [rotationRunBusy, setRotationRunBusy] = useState(false);
  const [rotationRunError, setRotationRunError] = useState<string | null>(null);
  const [rotationRun, setRotationRun] = useState<SecretRotation | null>(null);

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
      const [page, posture, thirdParty, catalog, cloudManagerPosture, operator, injection, unvaulted] = await Promise.all([
        api.secretPage({ limit: 20, cursor }),
        posturePromise,
        thirdPartyPosturePromise,
        syncCatalogPromise,
        cloudManagersPromise,
        operatorPosturePromise,
        workloadInjectionPromise,
        unvaultedPosturePromise,
      ]);
      setItems((current) => (cursor ? mergeMeta(current, page.items) : page.items));
      setNextCursor(page.next_cursor);
      setAccessName((current) => current || page.items[0]?.name || "");
      setSyncName((current) => current || page.items[0]?.name || "");
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
    } catch (err) {
      setLoadError(apiProblemMessage(err, "Secrets API unavailable or disabled"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const refreshRotationSchedules = () =>
    Promise.resolve()
      .then(() => api.secretRotationSchedules({ limit: 20 }))
      .then((page) => setRotationSchedules(page.items ?? []))
      .catch(() => undefined);

  useEffect(() => {
    void refreshRotationSchedules();
  }, []);

  const selectedMeta = useMemo(() => items.find((item) => item.name === accessName) ?? items[0] ?? null, [items, accessName]);
  const filteredItems = useMemo(() => {
    const needle = secretSearch.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) =>
      [item.name, String(item.version ?? ""), item.created_at ?? "", item.updated_at ?? "", "native store"].join(" ").toLowerCase().includes(needle),
    );
  }, [items, secretSearch]);
  const detailSecret = useMemo(() => items.find((item) => item.name === detailSecretName) ?? null, [detailSecretName, items]);
  const configuredSyncTargets = useMemo(() => syncCatalog?.targets.filter((target) => target.configured) ?? [], [syncCatalog]);

  const secretColumns = useMemo<Array<DataGridColumn<SecretMeta>>>(
    () => [
      { id: "name", header: "Name", sortable: true, cell: (item) => <span className="font-medium">{item.name}</span> },
      { id: "engine", header: "Engine", cell: () => "native store" },
      { id: "version", header: "Version", cell: (item) => <span className="font-mono text-xs">v{item.version}</span> },
      { id: "updated", header: "Updated", cell: (item) => formatDate(item.updated_at) },
      { id: "created", header: "Created", cell: (item) => formatDate(item.created_at) },
      {
        id: "actions",
        header: "Actions",
        cell: (item) => (
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => void revealSecret(item.name)} disabled={revealBusy === item.name}>
              {revealBusy === item.name ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              Reveal once
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setRotateName(item.name)}>
              <RotateCw className="h-4 w-4" aria-hidden="true" />
              Prepare rotate
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setDeleteName(item.name)}>
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              Prepare delete
            </Button>
          </div>
        ),
      },
    ],
    [revealBusy],
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
      const approval = await api.approveSecretChange(item.name, item.action);
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
        const meta = await api.rotateSecret(item.name, { name: item.name, value: rotateValue });
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

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreateError(null);
    setNotice(null);
    setCreateBusy(true);
    try {
      const meta = await api.createSecret({ name: createName, value: createValue });
      setItems((current) => mergeMeta(current, [meta]));
      setCreateName("");
      setCreateValue("");
      setNotice(`Secret ${meta.name} stored as version ${meta.version}. The value was sealed and is not shown after submit.`);
    } catch (err) {
      setCreateError(apiProblemMessage(err, "Could not create secret"));
    } finally {
      setCreateBusy(false);
    }
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
      const meta = await api.rotateSecret(pendingName, { name: pendingName, value: rotateValue });
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

  async function runAccessTest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessError(null);
    setAccessResult(null);
    setAccessBusy(true);
    try {
      const value = await api.getSecret(accessName);
      setAccessResult({ name: value.name, version: value.version });
    } catch (err) {
      setAccessError(apiProblemMessage(err, "Access test failed"));
    } finally {
      setAccessBusy(false);
    }
  }

  async function submitPKI(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPkiError(null);
    setPkiBundle(null);
    setPkiBusy(true);
    try {
      const ttl = Number(pkiTTL);
      setPkiBundle(await api.issuePKISecret({ common_name: pkiName, ttl_seconds: Number.isFinite(ttl) ? ttl : undefined }));
      setPkiName("");
    } catch (err) {
      setPkiError(apiProblemMessage(err, "Could not issue PKI secret"));
    } finally {
      setPkiBusy(false);
    }
  }

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginError(null);
    setSession(null);
    setLoginBusy(true);
    try {
      setSession(await api.machineLogin({ method: loginMethod, credential: loginCredential }));
      setLoginCredential("");
    } catch (err) {
      setLoginError(apiProblemMessage(err, "Machine login failed"));
    } finally {
      setLoginBusy(false);
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
    const page = await readGrantRoster(() => api.machineAuthMethods());
    setAuthMethods(page?.items ?? null);
  }

  async function refreshMachineSessions() {
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
    void readGrantRoster(() => api.machineAuthMethods()).then((page) => {
      if (active) setAuthMethods(page?.items ?? null);
    });
    void readGrantRoster(() => api.machineSessions({ limit: 50 })).then((page) => {
      if (active) setMachineSessions(page?.items ?? null);
    });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submitGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setGrantError(null);
    setGrantResult(null);
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

  async function submitShare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setShareError(null);
    setShareToken(null);
    setShareBusy(true);
    try {
      const ttl = Number(shareTTL);
      setShareToken(await api.createShare({ value: shareValueInput, ttl_seconds: Number.isFinite(ttl) ? ttl : undefined }));
      setShareValueInput("");
    } catch (err) {
      setShareError(apiProblemMessage(err, "Could not create one-time share"));
    } finally {
      setShareBusy(false);
    }
  }

  async function submitRedeem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRedeemError(null);
    setRedeemed(null);
    setRedeemBusy(true);
    try {
      setRedeemed(await api.redeemShare({ token: redeemToken }));
    } catch (err) {
      setRedeemError(apiProblemMessage(err, "Could not redeem one-time share"));
    } finally {
      setRedeemBusy(false);
    }
  }

  async function submitEphemeralAPIKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEphemeralError(null);
    setEphemeralKey(null);
    setEphemeralBusy(true);
    try {
      const subject = ephemeralSubject.trim();
      const scopes = parseScopeList(ephemeralScopes);
      const ttl = Number(ephemeralTTL);
      if (!subject) throw new Error("Subject is required");
      if (scopes.length === 0) throw new Error("At least one scope is required");
      if (!Number.isFinite(ttl) || ttl <= 0) throw new Error("TTL seconds must be a positive number");
      setEphemeralKey(await api.issueEphemeralAPIKey({ subject, scopes, ttl_seconds: Math.round(ttl) }));
      setEphemeralSubject("");
      setEphemeralScopes("");
    } catch (err) {
      setEphemeralError(apiProblemMessage(err, "Could not issue ephemeral API key"));
    } finally {
      setEphemeralBusy(false);
    }
  }

  async function submitDynamicLease(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLeaseError(null);
    setLeaseCredential(null);
    setLeaseBusy("issue");
    try {
      const role = leaseRole.trim();
      const ttl = Number(leaseTTL);
      if (!role) throw new Error("Role is required");
      if (!Number.isFinite(ttl) || ttl <= 0) throw new Error("TTL seconds must be a positive number");
      const issued = await api.issueDynamicLease({ provider: leaseProvider, role, ttl_seconds: Math.round(ttl) });
      setLease(leaseMetadataOnly(issued));
      if (issued.credential) setLeaseCredential({ id: issued.id, credential: issued.credential });
      setLeaseRole("");
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not issue dynamic lease"));
    } finally {
      setLeaseBusy(null);
    }
  }

  async function renewDynamicLease() {
    if (!lease) return;
    setLeaseError(null);
    setLeaseBusy("renew");
    try {
      const extendSeconds = Number(leaseExtendSeconds);
      if (!Number.isFinite(extendSeconds) || extendSeconds <= 0) throw new Error("Extend seconds must be a positive number");
      setLease(leaseMetadataOnly(await api.renewDynamicLease(lease.id, { extend_seconds: Math.round(extendSeconds) })));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not renew dynamic lease"));
    } finally {
      setLeaseBusy(null);
    }
  }

  async function revokeDynamicLease() {
    if (!lease) return;
    setLeaseError(null);
    setLeaseCredential(null);
    setLeaseBusy("revoke");
    try {
      setLease(leaseMetadataOnly(await api.revokeDynamicLease(lease.id)));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not revoke dynamic lease"));
    } finally {
      setLeaseBusy(null);
    }
  }

  async function encryptTransit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setTransitError(null);
    setTransitPlaintextResult(null);
    setTransitBusy("encrypt");
    try {
      const ciphertext = await api.encryptTransit({
        key: transitKey.trim(),
        plaintext: encodeTransitBytes(transitPlaintext),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitCiphertext(ciphertext);
      setTransitCiphertextInput(ciphertext.ciphertext);
      setTransitPlaintext("");
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not encrypt plaintext"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function decryptTransit() {
    setTransitError(null);
    setTransitPlaintextResult(null);
    setTransitBusy("decrypt");
    try {
      const result = await api.decryptTransit({
        key: transitKey.trim(),
        ciphertext: transitCiphertextInput.trim(),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitPlaintextResult(decodeTransitBytes(result.plaintext));
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not decrypt ciphertext"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function hmacTransit() {
    setTransitError(null);
    setTransitHMACResult(null);
    setTransitBusy("hmac");
    try {
      setTransitHMACResult(await api.hmacTransit({ key: transitKey.trim(), data: encodeTransitBytes(transitMessage) }));
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not compute HMAC"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function rewrapTransit() {
    setTransitError(null);
    setTransitBusy("rewrap");
    try {
      const result = await api.rewrapTransit({
        key: transitKey.trim(),
        ciphertext: transitCiphertextInput.trim(),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitCiphertext(result);
      setTransitCiphertextInput(result.ciphertext);
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not rewrap ciphertext"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function signTransit() {
    setTransitError(null);
    setTransitSignature(null);
    setTransitBusy("sign");
    try {
      setTransitSignature(await api.signTransit({ key: transitKey.trim(), message: encodeTransitBytes(transitMessage) }));
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not sign message"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function submitSecretScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setScanError(null);
    setScanBusy(true);
    try {
      const path = scanPath.trim();
      if (!path) throw new Error("Path is required");
      const customRulesPath = scanCustomRulesPath.trim();
      setScanResult(await api.scanSecrets({ path, mode: scanMode, ...(customRulesPath ? { custom_rules_path: customRulesPath } : {}) }));
    } catch (err) {
      setScanError(apiProblemMessage(err, "Could not run secret scan"));
    } finally {
      setScanBusy(false);
    }
  }

  async function submitThirdPartySecretScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setThirdPartyError(null);
    setThirdPartyBusy(true);
    try {
      const source = thirdPartySource.trim();
      const artifactPath = thirdPartyArtifactPath.trim();
      if (!source) throw new Error("Source is required");
      if (!artifactPath) throw new Error("Artifact path is required");
      const receipt = await api.ingestThirdPartySecretScan(thirdPartyProvider, {
        source,
        artifact_path: artifactPath,
        ...(thirdPartyEvent.trim() ? { event: thirdPartyEvent.trim() } : {}),
      });
      setThirdPartyReceipt(receipt);
    } catch (err) {
      setThirdPartyError(apiProblemMessage(err, "Could not queue third-party secret scan"));
    } finally {
      setThirdPartyBusy(false);
    }
  }

  async function submitSecretSync(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSyncError(null);
    setSyncBusy(true);
    try {
      const name = syncName.trim();
      const target = syncTarget.trim();
      const remoteKey = syncRemoteKey.trim();
      if (!name) throw new Error("Secret name is required");
      if (!target) throw new Error("Target is required");
      setSyncResult(await api.syncSecret({ name, target, ...(remoteKey ? { remote_key: remoteKey } : {}) }));
    } catch (err) {
      setSyncError(apiProblemMessage(err, "Could not sync secret"));
    } finally {
      setSyncBusy(false);
    }
  }

  async function submitRollbackRotation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRotationRunError(null);
    setRotationRun(null);
    setRotationRunBusy(true);
    try {
      const key = rotationRunKey.trim();
      const oldRef = rotationRunOldRef.trim();
      const provider = rotationRunProvider.trim();
      if (!key) throw new Error("Key is required");
      if (!oldRef) throw new Error("Old reference is required");
      if (!provider) throw new Error("Provider is required");
      const ttl = Number(rotationRunTTL);
      if (rotationRunTTL.trim() && (!Number.isFinite(ttl) || ttl <= 0)) throw new Error("TTL seconds must be a positive number");
      setRotationRun(
        await api.runSecretRotation({
          key,
          old_ref: oldRef,
          provider,
          ...(rotationRunTarget.trim() ? { target: rotationRunTarget.trim() } : {}),
          ...(rotationRunRemoteKey.trim() ? { remote_key: rotationRunRemoteKey.trim() } : {}),
          ...(rotationRunTTL.trim() ? { ttl_seconds: Math.round(ttl) } : {}),
        }),
      );
    } catch (err) {
      setRotationRunError(apiProblemMessage(err, "Could not run rollback-safe rotation"));
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
    setRunDueBusy(true);
    try {
      const result = await api.runDueSecretRotations();
      setDueRuns(result.runs ?? []);
      setNotice(`Ran ${result.ran} due rotations.`);
      await refreshRotationSchedules();
    } catch (err) {
      setRunDueError(apiProblemMessage(err, "Could not run due rotations"));
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

  function selectTab(next: string) {
    const value = secretsTabFromSearchParam(next);
    setTab(value);
    setSearchParams(
      (current) => {
        const nextParams = new URLSearchParams(current);
        if (value === "store") {
          nextParams.delete("tab");
        } else {
          nextParams.set("tab", value);
        }
        return nextParams;
      },
      { replace: true },
    );
  }

  return (
    <section aria-labelledby="secrets-heading" className="grid gap-6">
      <PageHeader
        titleId="secrets-heading"
        title="Secrets"
        description="Stored secrets, API keys, tokens, machine logins, PKI secrets, and one-time shares — distinct from the X.509 certificates in Certificates. Metadata is durable; returned values, keys, and tokens are reveal-once material."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Refresh
          </Button>
        }
      />

      {notice && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
          {notice}
        </p>
      )}

      {loadError && (
        <UnavailableState title="Secrets API unavailable or disabled">
          {loadError}. Secret operations are fail-closed until the feature is enabled and a key-encryption key is configured.
        </UnavailableState>
      )}

      <PageTabs
        idPrefix="secrets"
        ariaLabel="Secrets workspaces"
        active={tab}
        onChange={selectTab}
        tabs={[
          { id: "store", label: t("secrets.tabs.store") },
          { id: "access", label: t("secrets.tabs.access") },
          { id: "sharing", label: t("secrets.tabs.sharing") },
          { id: "engines", label: t("secrets.tabs.engines") },
          { id: "scanning", label: t("secrets.tabs.scanning") },
          { id: "sync", label: t("secrets.tabs.sync") },
        ]}
        className="mb-0"
      />

      {tab === "store" && (
        <div {...tabPanelProps("secrets", "store")} className="grid gap-6">
          <ModuleKpiStrip
            ariaLabel="Secrets module metrics"
            kpis={[
              { id: "stored", label: t("moduleKpi.secrets.stored"), value: items.length, to: "/secrets" },
              { id: "engines", label: t("moduleKpi.secrets.engines"), value: t("moduleKpi.view"), to: "/secrets?tab=engines" },
              { id: "sync", label: t("moduleKpi.secrets.sync"), value: t("moduleKpi.view"), to: "/secrets?tab=sync" },
            ]}
          />
          <SecretTree secrets={items} />

          <div className="grid gap-4 lg:grid-cols-2">
            <ReferenceResolver />
            <EnvDiffPanel secrets={items} />
          </div>

          <SecretImport onImported={() => void load()} />

          <section aria-labelledby="store-heading" className="grid gap-4 border-y border-border py-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="store-heading" className="text-title font-semibold">
                  Native secret store
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                  The native store returns names and versions only. Create and rotate send a value once, then this page drops the input and shows metadata.
                </p>
              </div>
            </div>

            <form
              aria-label="Create secret"
              onSubmit={(event) => void submitCreate(event)}
              className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Secret name</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={createName}
                  onChange={(event) => setCreateName(event.target.value)}
                  placeholder="app/db/password"
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Secret value</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  type="password"
                  value={createValue}
                  onChange={(event) => setCreateValue(event.target.value)}
                  required
                />
              </label>
              <Button type="submit" className="self-end" disabled={createBusy || Boolean(loadError)}>
                {createBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                Create secret
              </Button>
            </form>
            {createError && <ErrorState title="Secret create failed">{createError}</ErrorState>}

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
                    filters={<span className="rounded-control border border-border px-2.5 py-2 text-sm text-muted-foreground">Engine: native store</span>}
                    columnChooser={columnChooser}
                  />
                )}
                onRowOpen={(item) => setDetailSecretName(item.name)}
                rowActionLabel={() => "View metadata"}
              />
            )}
            {nextCursor && (
              <Button type="button" variant="outline" onClick={() => void load(nextCursor)} disabled={loading}>
                Load next metadata page
              </Button>
            )}
            {revealError && <ErrorState title="Reveal failed">{revealError}</ErrorState>}
            {revealed && (
              <RevealPanel title={`Reveal-once value for ${revealed.name}`} onDismiss={() => setRevealed(null)} value={revealed.value}>
                Version {revealed.version ?? "latest"} was returned for this secret. Dismiss clears it from the page.
              </RevealPanel>
            )}
            <DetailDrawer
              open={!!detailSecret}
              title="Secret metadata"
              description="Native-store metadata only; secret values are never shown here."
              onClose={() => setDetailSecretName(null)}
            >
              {detailSecret && (
                <dl className="grid gap-3 text-sm md:grid-cols-2">
                  <div>
                    <dt className="font-medium text-muted-foreground">Name</dt>
                    <dd className="break-all">{detailSecret.name}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Engine</dt>
                    <dd>native store</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Version</dt>
                    <dd className="font-mono text-xs">v{detailSecret.version}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Updated</dt>
                    <dd>{formatDate(detailSecret.updated_at)}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Created</dt>
                    <dd>{formatDate(detailSecret.created_at)}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Value handling</dt>
                    <dd>Reveal-once only; no value is stored in this drawer, browser storage, or the URL.</dd>
                  </div>
                </dl>
              )}
              {detailSecret && <VersionHistory name={detailSecret.name} latestVersion={detailSecret.version} />}
            </DetailDrawer>
          </section>

          <section aria-labelledby="rotate-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="rotate-heading" className="text-title font-semibold">
                Manual rotation and delete
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Manual native-store rotation replaces one stored value at a time. Rollback-safe provider rotation and scheduled rotations run from the panels
                below; downstream sync lives in the sync section.
              </p>
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
                  Key
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
                  Provider
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    list="secret-rotation-provider-options"
                    value={rotationRunProvider}
                    onChange={(event) => setRotationRunProvider(event.target.value)}
                    placeholder={t("parity.postgresql_519968")}
                    required
                  />
                </label>
                <datalist id="secret-rotation-provider-options">
                  {(cloudManagers?.providers ?? []).map((provider) => (
                    <option key={provider.id} value={provider.id} label={provider.name} />
                  ))}
                </datalist>
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.syncTargetOptional_189fc7")}
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    value={rotationRunTarget}
                    onChange={(event) => setRotationRunTarget(event.target.value)}
                    placeholder="kubernetes/prod"
                  />
                </label>
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.remoteKeyOptional_b6dff8")}
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    value={rotationRunRemoteKey}
                    onChange={(event) => setRotationRunRemoteKey(event.target.value)}
                    placeholder="Secret/payments-db/password"
                  />
                </label>
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.ttlSecondsOptional_68f1c5")}
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    type="number"
                    min="60"
                    value={rotationRunTTL}
                    onChange={(event) => setRotationRunTTL(event.target.value)}
                  />
                </label>
                <div className="md:col-span-2 xl:col-span-3">
                  <Button type="submit" disabled={rotationRunBusy || Boolean(loadError)}>
                    {rotationRunBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RotateCw className="h-4 w-4" aria-hidden="true" />}
                    Run rotation
                  </Button>
                </div>
              </form>
              {rotationRunError && <ErrorState title={t("parity.rollbackSafeRotationFailed_5f1a57")}>{rotationRunError}</ErrorState>}
              {rotationRun && (
                <div role="status" className="grid gap-2 rounded-control border border-border bg-background p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge
                      vocabulary="lifecycle"
                      value={rotationRun.completed ? "completed" : "failed"}
                      label={rotationRun.completed ? "Rotation completed" : "Rotation failed"}
                      tone={rotationRun.completed ? "success" : "critical"}
                    />
                    <span className="break-all font-mono text-xs">{rotationRun.key}</span>
                  </div>
                  {rotationRun.completed ? (
                    <p className="break-all font-mono text-xs">
                      {rotationRun.old_ref} → {rotationRun.new_ref}
                    </p>
                  ) : (
                    <div className="grid gap-2">
                      <p>
                        {t("parity.failedPhase_49b14a")} <span className="font-mono text-xs">{rotationRun.failed_phase ?? "unknown"}</span>
                        {rotationRun.error ? ` — ${rotationRun.error}` : ""}
                      </p>
                      {rotationRun.rollback_failed ? (
                        <p className="rounded-control border border-risk-critical/30 bg-risk-critical/10 px-3 py-2 text-risk-critical">
                          Rollback failed — manual intervention required.{rotationRun.rollback_error ? ` ${rotationRun.rollback_error}` : ""}
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
                    Run due now
                  </Button>
                </div>
              </div>
              {runDueError && <ErrorState title={t("parity.runDueRotationsFailed_b9c511")}>{runDueError}</ErrorState>}
              {rotationSchedules && (
                <DataGrid
                  ariaLabel="Scheduled secret rotations"
                  rows={rotationSchedules}
                  columns={scheduleColumns}
                  getRowId={(item) => item.id}
                  state={rotationSchedules.length === 0 ? "empty" : "ready"}
                  stateTitle="No rotation schedules"
                  stateMessage="Create a schedule to run rollback-safe rotation on an interval."
                />
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
              aria-label="Rotate secret"
              onSubmit={(event) => void submitRotate(event)}
              className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Secret to rotate</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={rotateName}
                  onChange={(event) => setRotateName(event.target.value)}
                  placeholder={selectedMeta?.name ?? "app/db/password"}
                  list="secret-name-options"
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Replacement value</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  type="password"
                  value={rotateValue}
                  onChange={(event) => setRotateValue(event.target.value)}
                  required
                />
              </label>
              <Button type="submit" className="self-end" loading={rotateBusy} disabled={Boolean(loadError)}>
                Rotate secret
              </Button>
            </form>
            {rotateError && <ErrorState title="Rotation failed">{rotateError}</ErrorState>}

            <form
              aria-label="Delete secret"
              onSubmit={(event) => void submitDelete(event)}
              className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Secret to delete</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={deleteName}
                  onChange={(event) => setDeleteName(event.target.value)}
                  placeholder={selectedMeta?.name ?? "app/db/password"}
                  list="secret-name-options"
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Type the exact secret name</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
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
                Delete secret
              </Button>
            </form>
            {deleteError && <ErrorState title="Delete failed">{deleteError}</ErrorState>}
            <SecretApprovalQueue
              items={approvalQueue}
              busyKey={approvalBusy}
              canRetry={canRetryApproval}
              onApprove={(item) => void approveSecretApproval(item)}
              onRetry={(item) => void retrySecretApproval(item)}
            />
          </section>
        </div>
      )}

      {tab === "access" && (
        <div {...tabPanelProps("secrets", "access")} className="grid gap-6">
          <section aria-labelledby="developer-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="developer-heading" className="text-title font-semibold">
                Developer access
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                SDK and CLI examples contain only names, tenants, and versions. The access test performs a read without rendering the value.
              </p>
            </div>
            <div className="grid gap-3 lg:grid-cols-2">
              <Snippet
                title="CLI injector"
                text={`trstctl secrets get ${selectedMeta?.name ?? "app/db/password"} --tenant current --format env --exec ./service`}
              />
              <Snippet
                title="TypeScript SDK"
                text={`const secret = await client.secrets.get("${selectedMeta?.name ?? "app/db/password"}");\nprocess.env.DB_PASSWORD = secret.value; // keep in process memory only`}
              />
            </div>
            <form aria-label="Secret access test" onSubmit={(event) => void runAccessTest(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Secret name</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={accessName}
                  onChange={(event) => setAccessName(event.target.value)}
                  placeholder="app/db/password"
                  required
                />
              </label>
              <Button type="submit" className="self-end" variant="outline" disabled={accessBusy || Boolean(loadError)}>
                {accessBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                Run access test
              </Button>
            </form>
            {accessError && <ErrorState title="Access test failed">{accessError}</ErrorState>}
            {accessResult && (
              <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
                Access test passed for {accessResult.name}; version {accessResult.version ?? "latest"} was reachable, and the value was not rendered.
              </p>
            )}
          </section>
        </div>
      )}

      {tab === "engines" && (
        <div {...tabPanelProps("secrets", "engines")} className="grid gap-6">
          <section aria-labelledby="pki-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="pki-heading" className="text-title font-semibold">
                PKI as a secret
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Issue a short-lived certificate bundle and reveal the private key only in the explicit result panel.
              </p>
            </div>
            <form aria-label="Issue PKI secret" onSubmit={(event) => void submitPKI(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_auto]">
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Common name</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={pkiName}
                  onChange={(event) => setPkiName(event.target.value)}
                  placeholder="svc.internal"
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">TTL seconds</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  type="number"
                  min="60"
                  value={pkiTTL}
                  onChange={(event) => setPkiTTL(event.target.value)}
                />
              </label>
              <Button type="submit" className="self-end" disabled={pkiBusy || Boolean(loadError)}>
                {pkiBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                Issue PKI secret
              </Button>
            </form>
            {pkiError && <ErrorState title="PKI issue failed">{pkiError}</ErrorState>}
            {pkiBundle && (
              <RevealPanel
                title={`PKI bundle ${pkiBundle.serial}`}
                onDismiss={() => setPkiBundle(null)}
                value={`${pkiBundle.certificate}\n${pkiBundle.private_key}`}
              >
                Copy or download now. The serial, certificate, and private key are cleared when dismissed.
              </RevealPanel>
            )}
          </section>
        </div>
      )}

      {tab === "access" && (
        <div className="grid gap-6">
          {/* C-S1 (DA-02 interim): Job 2's grant step, in-console, over the
              existing idempotent /access/api-tokens and /ephemeral/api-keys
              mutations. Create (Store tab) → grant (here) → verify (login
              below). */}
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
                    className="rounded-md border border-input bg-background px-3 py-2 font-mono text-sm"
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.grant.scopes")}</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2 font-mono"
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
                      className="rounded-md border border-input bg-background px-3 py-2"
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
                    <Button type="button" size="sm" variant="ghost" onClick={() => setGrantResult(null)}>
                      {t("secrets.grant.dismiss")}
                    </Button>
                  </div>
                  <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{grantResult.token}</code>
                  <p className="mt-1 text-xs text-muted-foreground">{t("secrets.grant.revealNote")}</p>
                </div>
              )}
              {canReadTokens && tokenRows && (
                <div className="overflow-x-auto rounded-panel border border-border">
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
                </div>
              )}
            </section>
          )}
          <section aria-labelledby="machine-login-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="machine-login-heading" className="text-title font-semibold">
                Machine login
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Exchange a machine credential for a scoped workload session. The submitted credential is cleared after submit and never echoed.
              </p>
            </div>
            <form aria-label="Machine login test" onSubmit={(event) => void submitLogin(event)} className="grid gap-3 md:grid-cols-[12rem_minmax(0,1fr)_auto]">
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Method</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={loginMethod}
                  onChange={(event) => setLoginMethod(event.target.value)}
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Credential</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  type="password"
                  value={loginCredential}
                  onChange={(event) => setLoginCredential(event.target.value)}
                  required
                />
              </label>
              <Button type="submit" className="self-end" disabled={loginBusy || Boolean(loadError)}>
                {loginBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <LogIn className="h-4 w-4" aria-hidden="true" />}
                Test login
              </Button>
            </form>
            {loginError && <ErrorState title="Machine login failed">{loginError}</ErrorState>}
            {session && <MachineSession session={session} />}
          </section>

          {/* C-S4 (DA-02 faithful): the auth-method console over the C-S2/C-S3
              endpoints. The "isn't in the console yet" placeholder is dead —
              methods (with the per-tenant disable overlay) and the issued-
              session ledger are served surfaces now. Methods stay declared in
              server config: the console projects and overlays, it never edits
              config. */}
          <section aria-labelledby="auth-methods-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="auth-methods-heading" className="text-title font-semibold">
                {t("secrets.methods.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.methods.description")}</p>
            </div>
            {methodError && <ErrorState title={t("secrets.methods.failedTitle")}>{methodError}</ErrorState>}
            {authMethods === null ? (
              <p className="text-sm text-muted-foreground">{t("secrets.methods.unavailable")}</p>
            ) : (
              <div className="overflow-x-auto rounded-panel border border-border">
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
              </div>
            )}
          </section>

          <section aria-labelledby="machine-sessions-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="machine-sessions-heading" className="text-title font-semibold">
                {t("secrets.sessions.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.sessions.description")}</p>
            </div>
            {sessionError && <ErrorState title={t("secrets.sessions.failedTitle")}>{sessionError}</ErrorState>}
            {machineSessions === null ? (
              <p className="text-sm text-muted-foreground">{t("secrets.sessions.unavailable")}</p>
            ) : (
              <div className="overflow-x-auto rounded-panel border border-border">
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
              </div>
            )}
          </section>
        </div>
      )}

      {tab === "sharing" && (
        <div {...tabPanelProps("secrets", "sharing")} className="grid gap-6">
          <section aria-labelledby="share-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="share-heading" className="text-title font-semibold">
                One-time sharing
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Create returns a bearer token once. Redeem returns the value once; a later redeem is expected to fail closed.
              </p>
            </div>
            <div className="grid gap-4 xl:grid-cols-2">
              <form aria-label="Create one-time share" onSubmit={(event) => void submitShare(event)} className="grid content-start gap-3">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">Value to share</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    type="password"
                    value={shareValueInput}
                    onChange={(event) => setShareValueInput(event.target.value)}
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">TTL seconds</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    type="number"
                    min="60"
                    value={shareTTL}
                    onChange={(event) => setShareTTL(event.target.value)}
                  />
                </label>
                <Button type="submit" disabled={shareBusy || Boolean(loadError)}>
                  {shareBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
                  Create share
                </Button>
                {shareError && <ErrorState title="Share create failed">{shareError}</ErrorState>}
              </form>
              <form aria-label="Redeem one-time share" onSubmit={(event) => void submitRedeem(event)} className="grid content-start gap-3">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">Share token</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    value={redeemToken}
                    onChange={(event) => setRedeemToken(event.target.value)}
                    required
                  />
                </label>
                <Button type="submit" variant="outline" disabled={redeemBusy || Boolean(loadError)}>
                  {redeemBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  Redeem share
                </Button>
                {redeemError && <ErrorState title="Share redeem failed">{redeemError}</ErrorState>}
              </form>
            </div>
            {shareToken && (
              <RevealPanel title="One-time share token" onDismiss={() => setShareToken(null)} value={shareToken.token}>
                Expires {formatDate(shareToken.expires_at)}. The token is bearer material; copy it now, then dismiss.
              </RevealPanel>
            )}
            {redeemed && (
              <RevealPanel title="Redeemed share value" onDismiss={() => setRedeemed(null)} value={redeemed.value}>
                This value is the exact-once redeem result. A second redeem should fail.
              </RevealPanel>
            )}
          </section>

          <section aria-labelledby="ephemeral-api-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="ephemeral-api-heading" className="text-title font-semibold">
                Ephemeral API keys
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Issue a scoped, short-lived key for a machine task. The server returns the raw token once; after dismissal this page keeps no copy.
              </p>
              {/* TRACE-005 source anchor: ephemeral API-key issuance is served; POST /api/v1/ephemeral/api-keys; trstctl-cli ephemeral api-keys issue; api_token.revoked */}
            </div>
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.7fr)]">
              <form aria-label="Issue ephemeral API key" onSubmit={(event) => void submitEphemeralAPIKey(event)} className="grid content-start gap-3">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">Subject</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    value={ephemeralSubject}
                    onChange={(event) => setEphemeralSubject(event.target.value)}
                    placeholder="ci/deploy-preview"
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">Scopes</span>
                  <textarea
                    className="min-h-24 rounded-md border border-input bg-background px-3 py-2"
                    value={ephemeralScopes}
                    onChange={(event) => setEphemeralScopes(event.target.value)}
                    placeholder="repo:payments:read, deploy:staging:write"
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">TTL seconds</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    type="number"
                    min="60"
                    value={ephemeralTTL}
                    onChange={(event) => setEphemeralTTL(event.target.value)}
                    required
                  />
                </label>
                <Button type="submit" disabled={ephemeralBusy || Boolean(loadError)}>
                  {ephemeralBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                  Issue API key
                </Button>
                {ephemeralError && <ErrorState title="Ephemeral API-key issue failed">{ephemeralError}</ErrorState>}
              </form>
              <div className="ui-panel grid content-start gap-2 p-comfortable text-sm">
                <h3 className="text-title font-semibold">Reveal-once key issuance</h3>
                <p className="text-muted-foreground">
                  Send the subject, scopes, and TTL to issue a short-lived token. Copy the returned token from the reveal panel, then dismiss it so browser
                  memory drops the raw key.
                </p>
              </div>
            </div>
            {ephemeralKey && (
              <RevealPanel title="Ephemeral API key" onDismiss={() => setEphemeralKey(null)} value={ephemeralKey.token}>
                Key <span className="font-mono text-xs">{ephemeralKey.id}</span> for {ephemeralKey.subject} expires {formatDate(ephemeralKey.expires_at)}.
                Scopes: {ephemeralKey.scopes.join(", ")}.
              </RevealPanel>
            )}
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
                  Attestation method
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
                    placeholder="-----BEGIN PUBLIC KEY-----"
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
                  Request credential
                </Button>
                {credentialError && <ErrorState title={t("parity.ephemeralCredentialRequestFailed_12be63")}>{credentialError}</ErrorState>}
              </form>
              <div className="ui-panel grid content-start gap-2 p-comfortable text-sm">
                <h3 className="text-title font-semibold">{t("parity.attestationGatedCredentials_2887bd")}</h3>
                <p className="text-muted-foreground">
                  Submit workload attestation and a public key to mint a just-in-time credential. When approval quorum applies, the request waits for approvers;
                  share the request ID with an approver to finish issuance.
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
                    Subject <span className="font-medium text-foreground">{credential.subject}</span> · expires {formatDate(credential.expires_at)}
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
        </div>
      )}

      {tab === "scanning" && (
        <div {...tabPanelProps("secrets", "scanning")} className="grid gap-6">
          <section aria-labelledby="secret-scanning-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="secret-scanning-heading" className="text-title font-semibold">
                Code and CI secret scanning bridge
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.scan.description")}</p>
              {/* CAP-SCAN-01 source anchor: repository secret scanning is served by REST, CLI, outbox, and Gitleaks worker paths */}
            </div>
            {repoScanPosture && <RepositoryScanPosture posture={repoScanPosture} />}
            {thirdPartyPosture && <ThirdPartyScanPosture posture={thirdPartyPosture} />}
            <form
              aria-label={t("secrets.thirdPartyScan.form")}
              onSubmit={(event) => void submitThirdPartySecretScan(event)}
              className="grid gap-3 md:grid-cols-[12rem_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.thirdPartyScan.provider")}</span>
                <select
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={thirdPartyProvider}
                  onChange={(event) => setThirdPartyProvider(event.target.value)}
                >
                  {(thirdPartyPosture?.providers ?? defaultThirdPartyProviders()).map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.thirdPartyScan.source")}</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={thirdPartySource}
                  onChange={(event) => setThirdPartySource(event.target.value)}
                  placeholder={t("secrets.thirdPartyScan.sourcePlaceholder")}
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.thirdPartyScan.artifactPath")}</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={thirdPartyArtifactPath}
                  onChange={(event) => setThirdPartyArtifactPath(event.target.value)}
                  placeholder={t("secrets.thirdPartyScan.artifactPlaceholder")}
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.thirdPartyScan.event")}</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={thirdPartyEvent}
                  onChange={(event) => setThirdPartyEvent(event.target.value)}
                  placeholder={t("secrets.thirdPartyScan.eventPlaceholder")}
                />
              </label>
              <Button type="submit" className="self-end" disabled={thirdPartyBusy || Boolean(loadError)}>
                {thirdPartyBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                {thirdPartyBusy ? t("secrets.thirdPartyScan.queueing") : t("secrets.thirdPartyScan.queue")}
              </Button>
            </form>
            {thirdPartyError && <ErrorState title={t("secrets.thirdPartyScan.errorTitle")}>{thirdPartyError}</ErrorState>}
            {thirdPartyReceipt && (
              <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
                {t("secrets.thirdPartyScan.accepted", { provider: thirdPartyReceipt.provider, run: thirdPartyReceipt.run_id })}
              </p>
            )}
            {/* TRACE-005 source anchor: secret-scanning triage is library-only while repository ingestion and scan execution are served */}
            <UnavailableState title={t("secrets.scan.triageLibraryOnlyTitle")}>{t("secrets.scan.triageLibraryOnlyBody")}</UnavailableState>
            <form
              aria-label="Run secret scan"
              onSubmit={(event) => void submitSecretScan(event)}
              className="grid gap-3 md:grid-cols-[minmax(0,1fr)_12rem_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Path</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={scanPath}
                  onChange={(event) => setScanPath(event.target.value)}
                  placeholder="github.com/example/payments"
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.scan.mode")}</span>
                <select
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={scanMode}
                  onChange={(event) => setScanMode(event.target.value as "workspace" | "git_history")}
                >
                  <option value="workspace">{t("secrets.scan.modeWorkspace")}</option>
                  <option value="git_history">{t("secrets.scan.modeGitHistory")}</option>
                </select>
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.scan.customRules")}</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={scanCustomRulesPath}
                  onChange={(event) => setScanCustomRulesPath(event.target.value)}
                  placeholder={t("secrets.scan.customRulesPlaceholder")}
                />
              </label>
              <Button type="submit" className="self-end" disabled={scanBusy || Boolean(loadError)}>
                {scanBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                Run scan
              </Button>
            </form>
            {scanError && <ErrorState title="Secret scan failed">{scanError}</ErrorState>}
            {scanResult && (
              <div className="ui-panel grid gap-3 p-comfortable text-sm">
                <dl className="grid gap-2 md:grid-cols-6">
                  <div>
                    <dt className="font-medium text-muted-foreground">Run ID</dt>
                    <dd className="break-all font-mono text-xs">{scanResult.run_id}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Scanner</dt>
                    <dd>{scanResult.scanner}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("secrets.scan.mode")}</dt>
                    <dd>{scanResult.mode}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("secrets.scan.customRules")}</dt>
                    <dd>{scanResult.custom_rules ? t("secrets.scan.customRulesYes") : t("secrets.scan.customRulesNo")}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Rules</dt>
                    <dd>{scanResult.rules_active}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">Findings</dt>
                    <dd>{scanResult.findings_count}</dd>
                  </div>
                </dl>
                {scanResult.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {scanResult.capabilities.map((capability) => (
                      <span key={capability} className="rounded-control border border-border px-2 py-1 text-xs text-muted-foreground">
                        {capability}
                      </span>
                    ))}
                  </div>
                )}
                <div className="overflow-x-auto">
                  <table className="ui-table min-w-[48rem]">
                    <caption className="sr-only">Secret scan findings</caption>
                    <thead>
                      <tr>
                        <th scope="col">Rule</th>
                        <th scope="col">File</th>
                        <th scope="col">Line</th>
                        <th scope="col">Redacted reference</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResult.findings.map((finding) => (
                        <tr key={`${finding.rule_id}-${finding.file}-${finding.line}`} className="align-top">
                          <td>{finding.rule_id}</td>
                          <td>{finding.file}</td>
                          <td className="font-mono text-xs">{finding.line}</td>
                          <td className="font-mono text-xs">{finding.credential_ref}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        </div>
      )}

      {tab === "engines" && (
        <div className="grid gap-6">
          <section aria-labelledby="dynamic-secrets-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="dynamic-secrets-heading" className="text-title font-semibold">
                Dynamic secrets
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Issue a lease-scoped credential from a configured provider, renew its expiry when needed, or revoke it immediately. Generated credentials are
                shown once and then cleared from the page.
              </p>
              {/* TRACE-005 source anchor: dynamic secret leases are served; POST /api/v1/secrets/leases; secrets:read */}
            </div>
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(22rem,0.8fr)]">
              <form aria-label="Issue dynamic secret lease" onSubmit={(event) => void submitDynamicLease(event)} className="grid content-start gap-3">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">Provider</span>
                  <select
                    className="rounded-md border border-input bg-background px-3 py-2"
                    value={leaseProvider}
                    onChange={(event) => setLeaseProvider(event.target.value)}
                  >
                    <option value="postgresql">PostgreSQL</option>
                    <option value="aws-iam">AWS IAM</option>
                    <option value="kubernetes">Kubernetes</option>
                    <option value="redis">Redis</option>
                  </select>
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">Role</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    value={leaseRole}
                    onChange={(event) => setLeaseRole(event.target.value)}
                    placeholder="readonly-reporting"
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">TTL seconds</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    type="number"
                    min="60"
                    value={leaseTTL}
                    onChange={(event) => setLeaseTTL(event.target.value)}
                    required
                  />
                </label>
                <Button type="submit" disabled={leaseBusy === "issue" || Boolean(loadError)}>
                  {leaseBusy === "issue" ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <KeyRound className="h-4 w-4" aria-hidden="true" />
                  )}
                  Issue lease
                </Button>
              </form>
              <div className="ui-panel grid content-start gap-3 p-comfortable text-sm">
                <h3 className="text-title font-semibold">Lease state</h3>
                {lease ? (
                  <>
                    <DynamicLeaseMetadata lease={lease} />
                    <label className="grid gap-1">
                      <span className="font-medium">Extend seconds</span>
                      <input
                        className="rounded-md border border-input bg-background px-3 py-2"
                        type="number"
                        min="60"
                        value={leaseExtendSeconds}
                        onChange={(event) => setLeaseExtendSeconds(event.target.value)}
                      />
                    </label>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => void renewDynamicLease()}
                        disabled={leaseBusy === "renew" || lease.state === "revoked"}
                      >
                        {leaseBusy === "renew" ? (
                          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                        ) : (
                          <RotateCw className="h-4 w-4" aria-hidden="true" />
                        )}
                        Renew lease
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => void revokeDynamicLease()}
                        disabled={leaseBusy === "revoke" || lease.state === "revoked"}
                      >
                        {leaseBusy === "revoke" ? (
                          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                        ) : (
                          <Trash2 className="h-4 w-4" aria-hidden="true" />
                        )}
                        Revoke lease
                      </Button>
                    </div>
                  </>
                ) : (
                  <p className="text-muted-foreground">No dynamic lease issued yet.</p>
                )}
              </div>
            </div>
            {leaseError && <ErrorState title="Dynamic lease operation failed">{leaseError}</ErrorState>}
            {leaseCredential && (
              <RevealPanel
                title={`Generated credential for lease ${leaseCredential.id}`}
                onDismiss={() => setLeaseCredential(null)}
                value={leaseCredential.credential}
              >
                Copy this generated credential now. Renew and revoke actions keep only lease metadata.
              </RevealPanel>
            )}
          </section>

          <section aria-labelledby="transit-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="transit-heading" className="text-title font-semibold">
                Transit and KMIP
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Transit operations keep key material server-side. This page base64-encodes local plaintext for the API, clears plaintext inputs after encrypt,
                and shows decrypted values only in a reveal panel.
              </p>
            </div>
            <form
              aria-label="Transit encrypt and decrypt"
              onSubmit={(event) => void encryptTransit(event)}
              className="grid gap-3 xl:grid-cols-[14rem_minmax(0,1fr)]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Key name</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={transitKey}
                  onChange={(event) => setTransitKey(event.target.value)}
                  placeholder="payments-pii"
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">AAD</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={transitAAD}
                  onChange={(event) => setTransitAAD(event.target.value)}
                  placeholder="optional associated data"
                />
              </label>
              <label className="grid gap-1 text-sm xl:col-span-2">
                <span className="font-medium">Plaintext</span>
                <textarea
                  className="min-h-24 rounded-md border border-input bg-background px-3 py-2"
                  value={transitPlaintext}
                  onChange={(event) => setTransitPlaintext(event.target.value)}
                  placeholder="local plaintext to encrypt"
                />
              </label>
              <label className="grid gap-1 text-sm xl:col-span-2">
                <span className="font-medium">Ciphertext</span>
                <textarea
                  className="min-h-24 rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
                  value={transitCiphertextInput}
                  onChange={(event) => setTransitCiphertextInput(event.target.value)}
                  placeholder="encrypted result or ciphertext to decrypt"
                />
              </label>
              <div className="flex flex-wrap gap-2 xl:col-span-2">
                <Button type="submit" disabled={transitBusy === "encrypt" || !transitPlaintext.trim() || Boolean(loadError)}>
                  {transitBusy === "encrypt" ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <KeyRound className="h-4 w-4" aria-hidden="true" />
                  )}
                  Encrypt
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void decryptTransit()}
                  disabled={transitBusy === "decrypt" || !transitCiphertextInput.trim() || Boolean(loadError)}
                >
                  {transitBusy === "decrypt" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  Decrypt
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void rewrapTransit()}
                  disabled={transitBusy === "rewrap" || !transitCiphertextInput.trim() || Boolean(loadError)}
                >
                  {transitBusy === "rewrap" ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <RotateCw className="h-4 w-4" aria-hidden="true" />
                  )}
                  Rewrap
                </Button>
              </div>
            </form>
            <div className="grid gap-4 xl:grid-cols-2">
              <div className="ui-panel grid gap-3 p-comfortable text-sm">
                <h3 className="text-title font-semibold">Transit result</h3>
                {transitCiphertext ? (
                  <dl className="grid gap-2">
                    <div>
                      <dt className="font-medium text-muted-foreground">Ciphertext</dt>
                      <dd className="break-all font-mono text-xs">{transitCiphertext.ciphertext}</dd>
                    </div>
                    <div>
                      <dt className="font-medium text-muted-foreground">Key version</dt>
                      <dd className="font-mono text-xs">v{transitCiphertext.version}</dd>
                    </div>
                  </dl>
                ) : (
                  <p className="text-muted-foreground">No transit ciphertext yet.</p>
                )}
              </div>
              <div className="ui-panel grid gap-3 p-comfortable text-sm">
                <h3 className="text-title font-semibold">HMAC and signing</h3>
                <label className="grid gap-1">
                  <span className="font-medium">Message</span>
                  <textarea
                    className="min-h-20 rounded-md border border-input bg-background px-3 py-2"
                    value={transitMessage}
                    onChange={(event) => setTransitMessage(event.target.value)}
                    placeholder="message bytes to MAC or sign"
                  />
                </label>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void hmacTransit()}
                    disabled={transitBusy === "hmac" || !transitMessage.trim() || Boolean(loadError)}
                  >
                    {transitBusy === "hmac" ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <KeyRound className="h-4 w-4" aria-hidden="true" />
                    )}
                    Compute HMAC
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void signTransit()}
                    disabled={transitBusy === "sign" || !transitMessage.trim() || Boolean(loadError)}
                  >
                    {transitBusy === "sign" ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <KeyRound className="h-4 w-4" aria-hidden="true" />
                    )}
                    Sign message
                  </Button>
                </div>
                {transitHMACResult && <Snippet title="HMAC" text={transitHMACResult.hmac} />}
                {transitSignature && <Snippet title="Signature" text={`${transitSignature.signature}\npublic_der: ${transitSignature.public_der}`} />}
              </div>
            </div>
            {transitError && <ErrorState title="Transit operation failed">{transitError}</ErrorState>}
            {transitPlaintextResult && (
              <RevealPanel title="Decrypted plaintext" onDismiss={() => setTransitPlaintextResult(null)} value={transitPlaintextResult}>
                This plaintext was decoded locally from the transit response. Dismiss clears it from the page.
              </RevealPanel>
            )}
          </section>
        </div>
      )}

      {tab === "sync" && (
        <div {...tabPanelProps("secrets", "sync")} className="grid gap-6">
          <section aria-labelledby="secret-sync-heading" className="grid gap-4 border-y border-border py-4">
            <div>
              <h2 id="secret-sync-heading" className="text-title font-semibold">
                Secret sync and platform integrations
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                Push a stored secret to a configured target. The browser sends the secret name and remote key only; the stored value is never rendered here.
              </p>
            </div>
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
                  <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">{operatorPosture.capability}</span>
                  <span className="text-muted-foreground">{t("secrets.sync.operatorCoverage")}</span>
                </div>
                <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                  <div className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.operatorCRDs")}</span>
                    <div className="flex flex-wrap gap-2">
                      {operatorPosture.crds.map((crd) => (
                        <span key={crd.kind} className="rounded-control border border-border px-2 py-1 font-mono text-xs">
                          {crd.kind} - {crd.status}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.operatorReloadWorkloads")}</span>
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
                  <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">{workloadInjection.capability}</span>
                  <span className="text-muted-foreground">{t("secrets.sync.injectionCoverage")}</span>
                </div>
                <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
                  <div className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.injectionCRD")}</span>
                    <span className="rounded-control border border-border px-2 py-1 font-mono text-xs">
                      {workloadInjection.crd.kind} - {workloadInjection.crd.status}
                    </span>
                  </div>
                  <div className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.injectionModes")}</span>
                    <div className="flex flex-wrap gap-2">
                      {workloadInjection.modes.map((mode) => (
                        <span key={mode.id} className="rounded-control border border-border px-2 py-1 text-xs">
                          {mode.name}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.injectionWorkloads")}</span>
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
                  <span className="rounded-control border border-border px-2 py-1 font-mono text-xs text-muted-foreground">{unvaultedPosture.capability}</span>
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
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.unvaultedDetection")}</span>
                    <div className="flex flex-wrap gap-2">
                      {unvaultedPosture.detection_sources.map((source) => (
                        <span key={source.id} className="rounded-control border border-border px-2 py-1 text-xs">
                          {source.name}: {source.configured_count}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.unvaultedVaults")}</span>
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
                    <span className="text-xs font-semibold uppercase tracking-normal text-muted-foreground">{t("secrets.sync.unvaultedSyncTargets")}</span>
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
            <form
              aria-label="Sync stored secret"
              onSubmit={(event) => void submitSecretSync(event)}
              className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_14rem_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Secret name</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={syncName}
                  onChange={(event) => setSyncName(event.target.value)}
                  placeholder={selectedMeta?.name ?? "app/db/password"}
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Target</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  list="secret-sync-target-options"
                  value={syncTarget}
                  onChange={(event) => setSyncTarget(event.target.value)}
                  placeholder="kubernetes/prod"
                  required
                />
              </label>
              <datalist id="secret-sync-target-options">
                {configuredSyncTargets.map((target) => (
                  <option key={target.id} value={target.id} label={target.name} />
                ))}
              </datalist>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Remote key</span>
                <input
                  className="rounded-md border border-input bg-background px-3 py-2"
                  value={syncRemoteKey}
                  onChange={(event) => setSyncRemoteKey(event.target.value)}
                  placeholder="Secret/payments-db/password"
                />
              </label>
              <Button type="submit" className="self-end" disabled={syncBusy || Boolean(loadError)}>
                {syncBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
                Sync secret
              </Button>
            </form>
            {syncError && <ErrorState title="Secret sync failed">{syncError}</ErrorState>}
            {syncResult && (
              <dl className="ui-panel grid gap-3 p-comfortable text-sm md:grid-cols-2 xl:grid-cols-5">
                <div>
                  <dt className="font-medium text-muted-foreground">Secret</dt>
                  <dd>{syncResult.name}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Target</dt>
                  <dd>{syncResult.target}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Remote key</dt>
                  <dd className="break-all font-mono text-xs">{syncResult.remote_key}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Queue</dt>
                  <dd>{syncResult.enqueued ? "Queued" : "Not queued"}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Delivery</dt>
                  <dd>{syncResult.delivered ? "Delivered" : "Not delivered"}</dd>
                </div>
              </dl>
            )}
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
              Schedule a rollback-safe rotation to repeat on an interval. Only key and reference metadata are stored; no secret values pass through this form.
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
              Key
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
              Provider
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                list="secret-rotation-provider-options"
                value={scheduleProvider}
                onChange={(event) => setScheduleProvider(event.target.value)}
                placeholder={t("parity.postgresql_519968")}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              Interval seconds
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
              Enabled
            </label>
            {scheduleError && (
              <p role="alert" className="text-sm text-destructive">
                {scheduleError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={closeScheduleDialog}>
                Cancel
              </Button>
              <Button type="submit" disabled={scheduleBusy}>
                {scheduleBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                Create schedule
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
