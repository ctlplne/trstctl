import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Eyebrow } from "@/components/typography";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { Copy, Eye, KeyRound, Loader2, LogIn, MoreHorizontal, RefreshCw, RotateCw, Share2, Trash2 } from "lucide-react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { ProgressiveTaskList } from "@/components/ProgressiveTaskList";
import { ScrollableTableRegion } from "@/components/ScrollableTableRegion";
import { IdentityPicker } from "@/components/IdentityPicker";
import { ModuleKpiStrip } from "@/components/ModuleKpiStrip";
import { useCan } from "@/components/rbac";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { SecretTree, ReferenceResolver, EnvDiffPanel, VersionHistory, SecretImport } from "@/components/secrets";
import { formatDateTime as formatDate } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
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
  type Owner,
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
  parseSecretRotationPartialReceipt,
  RepositoryScanPosture,
  RevealPanel,
  RotationHealthBadges,
  SecretApprovalQueue,
  Snippet,
  ThirdPartyScanPosture,
  decodeTransitBytes,
  defaultThirdPartyProviders,
  encodeTransitBytes,
  leaseMetadataOnly,
  mergeMeta,
  parseScopeList,
  secretApprovalActionLabel,
  secretApprovalQueueID,
  secretRotationDeferredReasonKeys,
  secretRotationDueEvidenceHasClosedErrors,
  type SecretApprovalQueueItem,
  type SecretRotationDeferredEvidence,
  type SecretRotationDueEvidence,
} from "./secrets/SecretsPageParts";
import { apiProblemMessage } from "@/lib/apiProblem";
import { SecretSyncWorkloadIdentityPanel } from "./secrets/SecretSyncWorkloadIdentityPanel";

/** The store (tree + table + lifecycle) renders at /secrets; every other
 * workflow is its own route in the Secrets space sidebar (S-C2) instead of
 * stacking into a ~6,800px scroll (audit P0: mega-page pattern) or hiding
 * behind an in-page tab strip. The historical `?tab=` deep links redirect
 * permanently to the routes, mirroring the C-A1 /platform precedent. */
type SecretsTab = "store" | "access" | "sharing" | "engines" | "scanning" | "sync";
const secretsTabIds: readonly SecretsTab[] = ["store", "access", "sharing", "engines", "scanning", "sync"];

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

export function Secrets() {
  const { t } = useTranslation();
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
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

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
  const [accessResult, setAccessResult] = useState<{ name: string; version?: number } | null>(null);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  const [pkiName, setPkiName] = useState("");
  const [pkiMode, setPkiMode] = useState<"csr" | "legacy">("csr");
  const [pkiCSR, setPkiCSR] = useState("");
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

  const [shareValueInput, setShareValueInput] = useState("");
  const [shareTTL, setShareTTL] = useState("300");
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareToken, setShareToken] = useState<ShareToken | null>(null);
  const [redeemToken, setRedeemToken] = useState("");
  const [redeemBusy, setRedeemBusy] = useState(false);
  const [redeemError, setRedeemError] = useState<string | null>(null);
  const [redeemed, setRedeemed] = useState<ShareValue | null>(null);
  const [sharingTask, setSharingTask] = useState<"share" | "machine" | null>(null);
  const [engineTask, setEngineTask] = useState<"dynamic" | "transit" | "pki" | null>(null);

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
      const [page, posture, thirdParty, catalog, cloudManagerPosture, operator, injection, unvaulted, ownerRows] = await Promise.all([
        api.secretPage({ limit: 20, cursor }),
        posturePromise,
        thirdPartyPosturePromise,
        syncCatalogPromise,
        cloudManagersPromise,
        operatorPosturePromise,
        workloadInjectionPromise,
        unvaultedPosturePromise,
        ownersPromise,
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
      if (ownerRows) {
        const orderedOwners = [...ownerRows].sort((left, right) => left.name.localeCompare(right.name));
        setOwners(orderedOwners);
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
  const configuredSyncTargets = useMemo(() => syncCatalog?.targets.filter((target) => target.configured) ?? [], [syncCatalog]);

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

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreateError(null);
    setNotice(null);
    setCreateBusy(true);
    try {
      const meta = await api.createSecret({ name: createName, owner_id: createOwnerID || undefined, value: createValue });
      setItems((current) => mergeMeta(current, [meta]));
      setCreateName("");
      setCreateValue("");
      setCreateOwnerID("");
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
      const ttlSeconds = Number.isFinite(ttl) ? ttl : undefined;
      if (pkiMode === "csr") {
        setPkiBundle(await api.issuePKISecret({ csr_pem: pkiCSR, ttl_seconds: ttlSeconds }));
        setPkiCSR("");
      } else {
        setPkiBundle(await api.issuePKISecret({ common_name: pkiName, ttl_seconds: ttlSeconds }));
        setPkiName("");
      }
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
      if (!provider.startsWith("connector:") || provider.slice("connector:".length).trim() === "") {
        throw new Error(t("secrets.rotation.connectorOnly"));
      }
      setRotationRun(
        await api.runSecretRotation({
          key,
          old_ref: oldRef,
          provider,
          ...(rotationRunTarget.trim() ? { target: rotationRunTarget.trim() } : {}),
          ...(rotationRunRemoteKey.trim() ? { remote_key: rotationRunRemoteKey.trim() } : {}),
        }),
      );
    } catch (err) {
      setRotationRunError(apiProblemMessage(err, "Could not run secret rotation"));
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
          {translateNow("source.secret.operations.are.fail.closed.until.th.09b52b9f62")}
        </UnavailableState>
      )}

      {tab === "store" && (
        <div className="grid gap-6">
          <ModuleKpiStrip
            ariaLabel="Secrets module metrics"
            kpis={[
              { id: "stored", label: t("moduleKpi.secrets.stored"), value: items.length, to: "/secrets" },
              { id: "engines", label: t("moduleKpi.secrets.engines"), value: t("moduleKpi.view"), to: "/secrets/engines" },
              { id: "sync", label: t("moduleKpi.secrets.sync"), value: t("moduleKpi.view"), to: "/secrets/sync" },
            ]}
          />
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
              <form
                aria-label={translateNow("source.create.secret.b72a982613")}
                onSubmit={(event) => void submitCreate(event)}
                className="grid gap-3 rounded-panel border border-border bg-card p-comfortable md:grid-cols-2 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto]"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.secret.name.5cdf573b89")}</span>
                  <input
                    ref={createNameRef}
                    id="secret-create-name"
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={createName}
                    onChange={(event) => setCreateName(event.target.value)}
                    placeholder={translateNow("source.app.db.password.917cb98f9d")}
                    required
                  />
                </label>
                <div className="grid gap-1 text-sm">
                  <label className="font-medium" htmlFor="secret-create-owner">
                    {translateNow("source.owner.4b1b8aa360")}
                  </label>
                  <Select
                    id="secret-create-owner"
                    aria-describedby="secret-create-owner-help"
                    value={createOwnerID}
                    onChange={(event) => setCreateOwnerID(event.target.value)}
                    required={owners.length > 0}
                  >
                    <option value="">{owners.length > 0 ? t("secrets.store.chooseOwner") : t("secrets.store.unassignedOwner")}</option>
                    {owners.map((owner) => (
                      <option key={owner.id} value={owner.id}>
                        {owner.environment ? t("secrets.store.ownerOption", { name: owner.name, environment: owner.environment }) : owner.name}
                      </option>
                    ))}
                  </Select>
                  <span id="secret-create-owner-help" className="text-xs text-muted-foreground">
                    {owners.length > 0 ? t("secrets.store.ownerHelp") : t("secrets.store.noOwnersHelp")}
                  </span>
                </div>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.secret.value.6ef47d9880")}</span>
                  <input
                    id="secret-create-value"
                    aria-label={translateNow("source.secret.value.6ef47d9880")}
                    aria-describedby="secret-create-value-help"
                    className="rounded-md border border-border bg-background px-3 py-2"
                    type="password"
                    value={createValue}
                    onChange={(event) => setCreateValue(event.target.value)}
                    required
                  />
                  <span id="secret-create-value-help" className="text-xs text-muted-foreground">
                    {t("secrets.store.valueHelp")}
                  </span>
                </label>
                <div className="flex flex-wrap items-center gap-2 self-end">
                  <Button type="button" variant="ghost" onClick={closeCreateForm} disabled={createBusy}>
                    {translateNow("source.cancel.19766ed6cc")}
                  </Button>
                  <Button type="submit" disabled={createBusy || Boolean(loadError) || (owners.length > 0 && !createOwnerID)}>
                    {createBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                    {translateNow("source.create.secret.b72a982613")}
                  </Button>
                </div>
              </form>
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
                      {rotationRunBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RotateCw className="h-4 w-4" aria-hidden="true" />}
                      {translateNow("source.run.rotation.399dcb292b")}
                    </Button>
                  </div>
                </form>
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
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.secret.to.rotate.4e6aab975e")}</span>
                  <input
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
                <form
                  aria-label={translateNow("source.machine.login.test.7f62ed2b92")}
                  onSubmit={(event) => void submitLogin(event)}
                  className="grid gap-3 md:grid-cols-[12rem_minmax(0,1fr)_auto]"
                >
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.method.52a0f9b65b")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={loginMethod}
                      onChange={(event) => setLoginMethod(event.target.value)}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.credential.b1c42b3ce1")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      type="password"
                      value={loginCredential}
                      onChange={(event) => setLoginCredential(event.target.value)}
                      required
                    />
                  </label>
                  <Button type="submit" className="self-end" disabled={loginBusy || Boolean(loadError)}>
                    {loginBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <LogIn className="h-4 w-4" aria-hidden="true" />}
                    {translateNow("source.test.login.c5e0ad20c3")}
                  </Button>
                </form>
                {loginError && <ErrorState title={translateNow("source.machine.login.failed.01826fdfc8")}>{loginError}</ErrorState>}
                {session && <MachineSession session={session} />}
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
                  <p className="text-sm text-muted-foreground">{t("secrets.methods.unavailable")}</p>
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
                  <p className="text-sm text-muted-foreground">{t("secrets.sessions.unavailable")}</p>
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

      {tab === "access" && (
        <div className="grid gap-6">
          <details className="group border-y border-border py-4">
            <summary className="cursor-pointer text-title font-semibold text-foreground">{t("secrets.access.developerTools")}</summary>
            <section aria-labelledby="developer-heading" className="grid gap-4 pt-4">
              <div>
                <h2 id="developer-heading" className="text-title font-semibold">
                  {translateNow("source.developer.access.e62e23a3a2")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.sdk.and.cli.examples.contain.only.names.te.f056ba97a8")}</p>
              </div>
              <div className="grid gap-3 lg:grid-cols-2">
                <Snippet
                  title={translateNow("source.cli.injector.1f36b02aea")}
                  text={`trstctl secrets get ${selectedMeta?.name ?? "app/db/password"} --tenant current --format env --exec ./service`}
                />
                <Snippet
                  title={translateNow("source.typescript.sdk.40e0532135")}
                  text={`const secret = await client.secrets.get("${selectedMeta?.name ?? "app/db/password"}");\nprocess.env.DB_PASSWORD = secret.value; // keep in process memory only`}
                />
              </div>
              <form
                aria-label={translateNow("source.secret.access.test.e467205dc5")}
                onSubmit={(event) => void runAccessTest(event)}
                className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.secret.name.5cdf573b89")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={accessName}
                    onChange={(event) => setAccessName(event.target.value)}
                    placeholder={translateNow("source.app.db.password.917cb98f9d")}
                    required
                  />
                </label>
                <Button type="submit" className="self-end" variant="outline" disabled={accessBusy || Boolean(loadError)}>
                  {accessBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                  {translateNow("source.run.access.test.0a1ca1e976")}
                </Button>
              </form>
              {accessError && <ErrorState title={translateNow("source.access.test.failed.e280577658")}>{accessError}</ErrorState>}
              {accessResult && (
                <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
                  {translateNow("source.access.test.passed.for.e4a15ad68a")} {accessResult.name}; version{" "}
                  {accessResult.version ?? translateNow("source.latest.5e1e2bcac3")}{" "}
                  {translateNow("source.was.reachable.and.the.value.was.not.render.830c77edbc")}
                </p>
              )}
            </section>
          </details>
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
            <section id="task-panel-share" aria-labelledby="share-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="share-heading" className="text-title font-semibold">
                  {translateNow("source.one.time.sharing.9db928cd78")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                  Create returns a bearer token once. Redeem returns the value once; a later redeem is expected to fail closed.
                </p>
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <form
                  aria-label={translateNow("source.create.one.time.share.fd95a197d6")}
                  onSubmit={(event) => void submitShare(event)}
                  className="grid content-start gap-3"
                >
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.value.to.share.fa56b0a913")}</span>
                    <input
                      id="share-value"
                      className="rounded-md border border-border bg-background px-3 py-2"
                      type="password"
                      value={shareValueInput}
                      onChange={(event) => setShareValueInput(event.target.value)}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.ttl.seconds.862d08de5a")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      type="number"
                      min="60"
                      value={shareTTL}
                      onChange={(event) => setShareTTL(event.target.value)}
                    />
                  </label>
                  <Button type="submit" disabled={shareBusy || Boolean(loadError)}>
                    {shareBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
                    {translateNow("source.create.share.bb7a8c7b6e")}
                  </Button>
                  {shareError && <ErrorState title={translateNow("source.share.create.failed.9078694d49")}>{shareError}</ErrorState>}
                </form>
                <form
                  aria-label={translateNow("source.redeem.one.time.share.2294329e1f")}
                  onSubmit={(event) => void submitRedeem(event)}
                  className="grid content-start gap-3"
                >
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.share.token.f3310a3b89")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={redeemToken}
                      onChange={(event) => setRedeemToken(event.target.value)}
                      required
                    />
                  </label>
                  <Button type="submit" variant="outline" disabled={redeemBusy || Boolean(loadError)}>
                    {redeemBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                    {translateNow("source.redeem.share.1b54732322")}
                  </Button>
                  {redeemError && <ErrorState title={translateNow("source.share.redeem.failed.674fa95c57")}>{redeemError}</ErrorState>}
                </form>
              </div>
              {shareToken && (
                <RevealPanel title={translateNow("source.one.time.share.token.20234cd9a0")} onDismiss={() => setShareToken(null)} value={shareToken.token}>
                  {translateNow("source.expires.f6725f3af0")} {formatDate(shareToken.expires_at)}. The token is bearer material; copy it now, then dismiss.
                </RevealPanel>
              )}
              {redeemed && (
                <RevealPanel title={translateNow("source.redeemed.share.value.1455d94a16")} onDismiss={() => setRedeemed(null)} value={redeemed.value}>
                  {translateNow("source.this.value.is.the.exact.once.redeem.result.ed19b63953")}
                </RevealPanel>
              )}
            </section>
          )}

          {sharingTask === "machine" && (
            <section id="task-panel-machine" aria-labelledby="ephemeral-api-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="ephemeral-api-heading" className="text-title font-semibold">
                  {translateNow("source.ephemeral.api.keys.6c8f7c6a2c")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
                  Issue a scoped, short-lived key for a machine task. The server returns the raw token once; after dismissal this page keeps no copy.
                </p>
                {/* TRACE-005 source anchor: ephemeral API-key issuance is served; POST /api/v1/ephemeral/api-keys; trstctl-cli ephemeral api-keys issue; api_token.revoked */}
              </div>
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.7fr)]">
                <form
                  aria-label={translateNow("source.issue.ephemeral.api.key.d864784cc7")}
                  onSubmit={(event) => void submitEphemeralAPIKey(event)}
                  className="grid content-start gap-3"
                >
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.subject.6897128384")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={ephemeralSubject}
                      onChange={(event) => setEphemeralSubject(event.target.value)}
                      placeholder={translateNow("source.ci.deploy.preview.d2c6100222")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.scopes.0d5644ff52")}</span>
                    <textarea
                      className="min-h-24 rounded-md border border-border bg-background px-3 py-2"
                      value={ephemeralScopes}
                      onChange={(event) => setEphemeralScopes(event.target.value)}
                      placeholder={translateNow("source.repo.payments.read.deploy.staging.write.169aa8250e")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.ttl.seconds.862d08de5a")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      type="number"
                      min="60"
                      value={ephemeralTTL}
                      onChange={(event) => setEphemeralTTL(event.target.value)}
                      required
                    />
                  </label>
                  <Button type="submit" disabled={ephemeralBusy || Boolean(loadError)}>
                    {ephemeralBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                    {translateNow("source.issue.api.key.3cdf19cbb9")}
                  </Button>
                  {ephemeralError && <ErrorState title={translateNow("source.ephemeral.api.key.issue.failed.b91df9889a")}>{ephemeralError}</ErrorState>}
                </form>
                <div className="ui-panel grid content-start gap-2 p-comfortable text-sm">
                  <h3 className="text-title font-semibold">{translateNow("source.reveal.once.key.issuance.61c20133fa")}</h3>
                  <p className="text-muted-foreground">{translateNow("source.send.the.subject.scopes.and.ttl.to.issue.a.9854a77221")}</p>
                </div>
              </div>
              {ephemeralKey && (
                <RevealPanel title={translateNow("source.ephemeral.api.key.59757a0857")} onDismiss={() => setEphemeralKey(null)} value={ephemeralKey.token}>
                  {translateNow("source.key.99a52df3ff")} <span className="font-mono text-xs">{ephemeralKey.id}</span> {translateNow("source.for.10c22bcf4c")}{" "}
                  {ephemeralKey.subject} {translateNow("source.expires.ab8a2845f1")} {formatDate(ephemeralKey.expires_at)}
                  {translateNow("source.scopes.c7bcf9d686")} {ephemeralKey.scopes.join(", ")}.
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
          <section aria-labelledby="secret-scanning-heading" className="grid min-w-0 gap-4 border-y border-border py-4">
            <div className="-order-2">
              <h2 id="secret-scanning-heading" className="text-title font-semibold">
                {translateNow("source.code.and.ci.secret.scanning.bridge.27c18d763b")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.scan.description")}</p>
              {/* CAP-SCAN-01 source anchor: repository secret scanning is served by REST, CLI, outbox, and Gitleaks worker paths */}
            </div>
            <details className="ui-panel group order-1 p-comfortable">
              <summary className="cursor-pointer font-medium text-foreground">
                {t("secrets.scan.advancedSummary")}
                <span className="ms-2 text-sm font-normal text-muted-foreground">{t("secrets.scan.advancedSummaryHelp")}</span>
              </summary>
              <div className="mt-4 grid gap-4">
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
                      className="rounded-md border border-border bg-background px-3 py-2"
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
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={thirdPartySource}
                      onChange={(event) => setThirdPartySource(event.target.value)}
                      placeholder={t("secrets.thirdPartyScan.sourcePlaceholder")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{t("secrets.thirdPartyScan.artifactPath")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={thirdPartyArtifactPath}
                      onChange={(event) => setThirdPartyArtifactPath(event.target.value)}
                      placeholder={t("secrets.thirdPartyScan.artifactPlaceholder")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{t("secrets.thirdPartyScan.event")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
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
              </div>
            </details>
            <form
              aria-label={translateNow("source.run.secret.scan.89f2ed7a1b")}
              onSubmit={(event) => void submitSecretScan(event)}
              className="-order-1 grid gap-3 md:grid-cols-[minmax(0,1fr)_12rem_minmax(0,1fr)_auto]"
            >
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{translateNow("source.path.62fa5a5b0d")}</span>
                <input
                  id="secret-scan-path"
                  className="rounded-md border border-border bg-background px-3 py-2"
                  value={scanPath}
                  onChange={(event) => setScanPath(event.target.value)}
                  placeholder={translateNow("source.github.com.example.payments.8d7be8211f")}
                  required
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium">{t("secrets.scan.mode")}</span>
                <select
                  className="rounded-md border border-border bg-background px-3 py-2"
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
                  className="rounded-md border border-border bg-background px-3 py-2"
                  value={scanCustomRulesPath}
                  onChange={(event) => setScanCustomRulesPath(event.target.value)}
                  placeholder={t("secrets.scan.customRulesPlaceholder")}
                />
              </label>
              <Button type="submit" className="self-end" disabled={scanBusy || Boolean(loadError)}>
                {scanBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                {translateNow("source.run.scan.68ac7da5df")}
              </Button>
            </form>
            {scanError && <ErrorState title={translateNow("source.secret.scan.failed.61f13676c4")}>{scanError}</ErrorState>}
            {scanResult && (
              <div className="ui-panel grid gap-3 p-comfortable text-sm">
                <dl className="grid gap-2 md:grid-cols-6">
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.run.id.26d3e7aaac")}</dt>
                    <dd className="break-all font-mono text-xs">{scanResult.run_id}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.scanner.71d4cf953e")}</dt>
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
                    <dt className="font-medium text-muted-foreground">{translateNow("source.rules.4228aeb07c")}</dt>
                    <dd>{scanResult.rules_active}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{translateNow("source.findings.e171c2ff25")}</dt>
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
                    <caption className="sr-only">{translateNow("source.secret.scan.findings.3462f78805")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{translateNow("source.rule.62845f31a2")}</th>
                        <th scope="col">{translateNow("source.file.50009ce1da")}</th>
                        <th scope="col">{translateNow("source.line.d7852cd0d2")}</th>
                        <th scope="col">{translateNow("source.redacted.reference.f904f7809b")}</th>
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
            <section id="task-panel-dynamic" aria-labelledby="dynamic-secrets-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="dynamic-secrets-heading" className="text-title font-semibold">
                  {translateNow("source.dynamic.secrets.70f2c5b95c")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.issue.a.lease.scoped.credential.from.a.con.9d8b9440ef")}</p>
                {/* TRACE-005 source anchor: dynamic secret leases are served; POST /api/v1/secrets/leases; secrets:read */}
              </div>
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(22rem,0.8fr)]">
                <form
                  aria-label={translateNow("source.issue.dynamic.secret.lease.e14a6cc2e8")}
                  onSubmit={(event) => void submitDynamicLease(event)}
                  className="grid content-start gap-3"
                >
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.provider.472590ae97")}</span>
                    <select
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={leaseProvider}
                      onChange={(event) => setLeaseProvider(event.target.value)}
                    >
                      <option value="postgresql">{translateNow("source.postgresql.cc52d03280")}</option>
                      <option value="aws-iam">{translateNow("source.aws.iam.c37b8156ed")}</option>
                      <option value="kubernetes">{translateNow("source.kubernetes.a37d07fe30")}</option>
                      <option value="redis">{translateNow("source.redis.a7f6415749")}</option>
                    </select>
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.role.14736a2eb9")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={leaseRole}
                      onChange={(event) => setLeaseRole(event.target.value)}
                      placeholder={translateNow("source.readonly.reporting.ddf5aecb22")}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.ttl.seconds.862d08de5a")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
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
                    {translateNow("source.issue.lease.96a70e0f64")}
                  </Button>
                </form>
                <div className="ui-panel grid content-start gap-3 p-comfortable text-sm">
                  <h3 className="text-title font-semibold">{translateNow("source.lease.state.70d08ad3df")}</h3>
                  {lease ? (
                    <>
                      <DynamicLeaseMetadata lease={lease} />
                      <label className="grid gap-1">
                        <span className="font-medium">{translateNow("source.extend.seconds.ff4a8186f0")}</span>
                        <input
                          className="rounded-md border border-border bg-background px-3 py-2"
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
                          {translateNow("source.renew.lease.b730aa5628")}
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
                          {translateNow("source.revoke.lease.a04f91a939")}
                        </Button>
                      </div>
                    </>
                  ) : (
                    <p className="text-muted-foreground">{translateNow("source.no.dynamic.lease.issued.yet.da6fd9c373")}</p>
                  )}
                </div>
              </div>
              {leaseError && <ErrorState title={translateNow("source.dynamic.lease.operation.failed.115f5893e7")}>{leaseError}</ErrorState>}
              {leaseCredential && (
                <RevealPanel
                  title={translateNow("source.generated.credential.for.lease.value1.814b0bc937", { value1: leaseCredential.id })}
                  onDismiss={() => setLeaseCredential(null)}
                  value={leaseCredential.credential}
                >
                  {translateNow("source.copy.this.generated.credential.now.renew.a.811264cbb9")}
                </RevealPanel>
              )}
            </section>
          )}

          {engineTask === "transit" && (
            <section id="task-panel-transit" aria-labelledby="transit-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="transit-heading" className="text-title font-semibold">
                  {translateNow("source.transit.and.kmip.bbf61786e0")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.transit.operations.keep.key.material.serve.be62c8b11a")}</p>
              </div>
              <form
                aria-label={translateNow("source.transit.encrypt.and.decrypt.f3ae0fd83f")}
                onSubmit={(event) => void encryptTransit(event)}
                className="grid gap-3 xl:grid-cols-[14rem_minmax(0,1fr)]"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.key.name.6f245e973f")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={transitKey}
                    onChange={(event) => setTransitKey(event.target.value)}
                    placeholder={translateNow("source.payments.pii.643f35ba95")}
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.aad.9adbaf62d8")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={transitAAD}
                    onChange={(event) => setTransitAAD(event.target.value)}
                    placeholder={translateNow("source.optional.associated.data.52eba643ce")}
                  />
                </label>
                <label className="grid gap-1 text-sm xl:col-span-2">
                  <span className="font-medium">{translateNow("source.plaintext.0707c5d972")}</span>
                  <textarea
                    className="min-h-24 rounded-md border border-border bg-background px-3 py-2"
                    value={transitPlaintext}
                    onChange={(event) => setTransitPlaintext(event.target.value)}
                    placeholder={translateNow("source.local.plaintext.to.encrypt.a67b9e7b54")}
                  />
                </label>
                <label className="grid gap-1 text-sm xl:col-span-2">
                  <span className="font-medium">{translateNow("source.ciphertext.47955e6673")}</span>
                  <textarea
                    className="min-h-24 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                    value={transitCiphertextInput}
                    onChange={(event) => setTransitCiphertextInput(event.target.value)}
                    placeholder={translateNow("source.encrypted.result.or.ciphertext.to.decrypt.88441adfe9")}
                  />
                </label>
                <div className="flex flex-wrap gap-2 xl:col-span-2">
                  <Button type="submit" disabled={transitBusy === "encrypt" || !transitPlaintext.trim() || Boolean(loadError)}>
                    {transitBusy === "encrypt" ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <KeyRound className="h-4 w-4" aria-hidden="true" />
                    )}
                    {translateNow("source.encrypt.4f03bf1cdf")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void decryptTransit()}
                    disabled={transitBusy === "decrypt" || !transitCiphertextInput.trim() || Boolean(loadError)}
                  >
                    {transitBusy === "decrypt" ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <Eye className="h-4 w-4" aria-hidden="true" />
                    )}
                    {translateNow("source.decrypt.2e4629449b")}
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
                    {translateNow("source.rewrap.49c8c07065")}
                  </Button>
                </div>
              </form>
              <div className="grid gap-4 xl:grid-cols-2">
                <div className="ui-panel grid gap-3 p-comfortable text-sm">
                  <h3 className="text-title font-semibold">{translateNow("source.transit.result.7a54cd2a67")}</h3>
                  {transitCiphertext ? (
                    <dl className="grid gap-2">
                      <div>
                        <dt className="font-medium text-muted-foreground">{translateNow("source.ciphertext.47955e6673")}</dt>
                        <dd className="break-all font-mono text-xs">{transitCiphertext.ciphertext}</dd>
                      </div>
                      <div>
                        <dt className="font-medium text-muted-foreground">{translateNow("source.key.version.aa5d87c789")}</dt>
                        <dd className="font-mono text-xs">v{transitCiphertext.version}</dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="text-muted-foreground">{translateNow("source.no.transit.ciphertext.yet.f9d6c9870b")}</p>
                  )}
                </div>
                <div className="ui-panel grid gap-3 p-comfortable text-sm">
                  <h3 className="text-title font-semibold">{translateNow("source.hmac.and.signing.a21f893b5b")}</h3>
                  <label className="grid gap-1">
                    <span className="font-medium">{translateNow("source.message.2f77668a9d")}</span>
                    <textarea
                      className="min-h-20 rounded-md border border-border bg-background px-3 py-2"
                      value={transitMessage}
                      onChange={(event) => setTransitMessage(event.target.value)}
                      placeholder={translateNow("source.message.bytes.to.mac.or.sign.1400a97072")}
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
                      {translateNow("source.compute.hmac.4809a2f350")}
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
                      {translateNow("source.sign.message.516e35c2fc")}
                    </Button>
                  </div>
                  {transitHMACResult && <Snippet title={translateNow("source.hmac.32fd6f051c")} text={transitHMACResult.hmac} />}
                  {transitSignature && (
                    <Snippet
                      title={translateNow("source.signature.f1a73e2204")}
                      text={`${transitSignature.signature}\npublic_der: ${transitSignature.public_der}`}
                    />
                  )}
                </div>
              </div>
              {transitError && <ErrorState title={translateNow("source.transit.operation.failed.22502fa40b")}>{transitError}</ErrorState>}
              {transitPlaintextResult && (
                <RevealPanel
                  title={translateNow("source.decrypted.plaintext.675dd9b983")}
                  onDismiss={() => setTransitPlaintextResult(null)}
                  value={transitPlaintextResult}
                >
                  {translateNow("source.this.plaintext.was.decoded.locally.from.th.fbd3275222")}
                </RevealPanel>
              )}
            </section>
          )}

          {engineTask === "pki" && (
            <section id="task-panel-pki" aria-labelledby="pki-heading" className="grid gap-4 border-y border-border py-4">
              <div>
                <h2 id="pki-heading" className="text-title font-semibold">
                  {translateNow("source.pki.as.a.secret.e349ae9d0f")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.issue.a.short.lived.certificate.bundle.and.68b22cee4d")}</p>
              </div>
              <form
                aria-label={translateNow("source.issue.pki.secret.692ee4b6e2")}
                onSubmit={(event) => void submitPKI(event)}
                className="grid gap-3 md:grid-cols-2"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.pki.custodyLabel")}</span>
                  <Select
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={pkiMode}
                    onChange={(event) => setPkiMode(event.target.value as "csr" | "legacy")}
                  >
                    <option value="csr">{t("secrets.pki.csrMode")}</option>
                    <option value="legacy">{t("secrets.pki.legacyMode")}</option>
                  </Select>
                </label>
                {pkiMode === "csr" ? (
                  <label className="grid gap-1 text-sm md:col-span-2">
                    <span className="font-medium">{t("request.csr.label")}</span>
                    <Textarea
                      className="min-h-36 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                      aria-label={t("request.csr.label")}
                      value={pkiCSR}
                      onChange={(event) => setPkiCSR(event.target.value)}
                      placeholder={t("secrets.pki.csrPlaceholder")}
                      required
                    />
                    <span className="text-xs text-muted-foreground">{t("secrets.pki.csrHelp")}</span>
                  </label>
                ) : (
                  <label className="grid gap-1 text-sm">
                    <span className="font-medium">{translateNow("source.common.name.2d129020eb")}</span>
                    <input
                      className="rounded-md border border-border bg-background px-3 py-2"
                      value={pkiName}
                      onChange={(event) => setPkiName(event.target.value)}
                      placeholder={translateNow("source.svc.internal.e50a91019d")}
                      required
                    />
                  </label>
                )}
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.ttl.seconds.862d08de5a")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    type="number"
                    min="60"
                    value={pkiTTL}
                    onChange={(event) => setPkiTTL(event.target.value)}
                  />
                </label>
                <Button type="submit" className="self-end md:justify-self-start" disabled={pkiBusy || Boolean(loadError)}>
                  {pkiBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                  {translateNow("source.issue.pki.secret.692ee4b6e2")}
                </Button>
                {pkiMode === "legacy" && (
                  <p className="text-xs text-status-warning md:col-span-2">
                    {t("secrets.pki.legacyWarning")}{" "}
                    <Link className="underline" to="/audit?type=issuance.server_side_keygen">
                      {t("secrets.pki.auditLink")}
                    </Link>
                  </p>
                )}
              </form>
              {pkiError && <ErrorState title={translateNow("source.pki.issue.failed.cb50a25278")}>{pkiError}</ErrorState>}
              {pkiBundle && (
                <RevealPanel
                  title={translateNow("source.pki.bundle.value1.18184942ea", { value1: pkiBundle.serial })}
                  onDismiss={() => setPkiBundle(null)}
                  value={pkiBundle.private_key ? `${pkiBundle.certificate}\n${pkiBundle.private_key}` : pkiBundle.certificate}
                >
                  {pkiBundle.private_key ? t("secrets.pki.legacyResult") : t("secrets.pki.csrResult")}
                </RevealPanel>
              )}
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
            {syncCatalog && configuredSyncTargets.length === 0 ? (
              <UnavailableState title={t("secrets.sync.noDestinationTitle")}>{t("secrets.sync.noDestinationBody")}</UnavailableState>
            ) : (
              <form
                aria-label={translateNow("source.sync.stored.secret.b83b2d0767")}
                onSubmit={(event) => void submitSecretSync(event)}
                className="-order-1 grid gap-3 xl:grid-cols-[minmax(0,1fr)_14rem_minmax(0,1fr)_auto]"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.secret.name.5cdf573b89")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={syncName}
                    onChange={(event) => setSyncName(event.target.value)}
                    placeholder={selectedMeta?.name ?? translateNow("source.app.db.password.917cb98f9d")}
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.target.978354db0c")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    list="secret-sync-target-options"
                    value={syncTarget}
                    onChange={(event) => setSyncTarget(event.target.value)}
                    placeholder={translateNow("source.kubernetes.prod.16a7f7e17a")}
                    required
                  />
                </label>
                <datalist id="secret-sync-target-options">
                  {configuredSyncTargets.map((target) => (
                    <option key={target.id} value={target.id} label={target.name} />
                  ))}
                </datalist>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{translateNow("source.remote.key.b698762058")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={syncRemoteKey}
                    onChange={(event) => setSyncRemoteKey(event.target.value)}
                    placeholder={translateNow("source.secret.payments.db.password.cf46ca15a9")}
                  />
                </label>
                <Button type="submit" className="self-end" disabled={syncBusy || Boolean(loadError)}>
                  {syncBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
                  {translateNow("source.sync.secret.4d3ab1c075")}
                </Button>
              </form>
            )}
            {syncError && <ErrorState title={translateNow("source.secret.sync.failed.b901ae57d8")}>{syncError}</ErrorState>}
            {syncResult && (
              <dl className="ui-panel grid gap-3 p-comfortable text-sm md:grid-cols-2 xl:grid-cols-5">
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.secret.7e32a729b1")}</dt>
                  <dd>{syncResult.name}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.target.978354db0c")}</dt>
                  <dd>{syncResult.target}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.remote.key.b698762058")}</dt>
                  <dd className="break-all font-mono text-xs">{syncResult.remote_key}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.queue.3b2fe03e36")}</dt>
                  <dd>{syncResult.enqueued ? translateNow("source.queued.661ff40a07") : translateNow("source.not.queued.7e52b62ffb")}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.delivery.52bfe584a5")}</dt>
                  <dd>{syncResult.delivered ? translateNow("source.delivered.9061156573") : translateNow("source.not.delivered.f498742c19")}</dd>
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
