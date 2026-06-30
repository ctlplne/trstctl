import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Copy, Eye, KeyRound, Loader2, LogIn, PlayCircle, RefreshCw, RotateCw, Share2, ShieldCheck, Trash2, X } from "lucide-react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { SecretTree, ReferenceResolver, EnvDiffPanel, VersionHistory, SecretImport } from "@/components/secrets";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type CloudSecretManagerIntegration,
  type DynamicLease,
  type EphemeralAPIKey,
  type KubernetesSecretOperator,
  type MachineLoginResponse,
  type PKISecret,
  type SecretApprovalAction,
  type SecretMeta,
  type SecretRepositoryScanPosture,
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
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

type SecretApprovalQueueItem = {
  id: string;
  name: string;
  action: SecretApprovalAction;
  openedAt: string;
  status: "pending" | "approved" | "completed";
  approvals?: number;
  approver?: string;
  error?: string;
};

type Translate = ReturnType<typeof useTranslation>["t"];

export function Secrets() {
  const { t } = useTranslation();
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
        typeof api.cloudSecretManagers === "function" ? api.cloudSecretManagers().catch(() => null) : Promise.resolve<CloudSecretManagerIntegration | null>(null);
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

        <form aria-label="Create secret" onSubmit={(event) => void submitCreate(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
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
            Manual native-store rotation replaces one stored value at a time. Scheduled rotation and downstream sync controls aren't in the console yet.
          </p>
        </div>
        <UnavailableState title="Scheduled rotation and downstream sync aren't in the console yet">
          Rollback-safe static rotation is available for configured backends. Scheduled rotation, downstream sync, and delivery receipts are not yet exposed in
          this console, so this page offers only per-secret rotate/delete controls.
        </UnavailableState>
        <form aria-label="Rotate secret" onSubmit={(event) => void submitRotate(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret to rotate</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={rotateName}
              onChange={(event) => setRotateName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
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
          <Button type="submit" className="self-end" disabled={rotateBusy || Boolean(loadError)}>
            {rotateBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Rotate secret
          </Button>
        </form>
        {rotateError && <ErrorState title="Rotation failed">{rotateError}</ErrorState>}

        <form aria-label="Delete secret" onSubmit={(event) => void submitDelete(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret to delete</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={deleteName}
              onChange={(event) => setDeleteName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
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
          <Button type="submit" className="self-end" disabled={deleteBusy || !deleteName || deleteConfirm !== deleteName || Boolean(loadError)}>
            {deleteBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
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
        <UnavailableState title="Auth-method administration isn't in the console yet">
          Configured token methods, audience rules, issued-session ledger, and revoked methods are not available in the console yet. This page exposes only the
          login exchange.
        </UnavailableState>
      </section>

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
              Send the subject, scopes, and TTL to issue a short-lived token. Copy the returned token from the reveal panel, then dismiss it so browser memory
              drops the raw key.
            </p>
          </div>
        </div>
        {ephemeralKey && (
          <RevealPanel title="Ephemeral API key" onDismiss={() => setEphemeralKey(null)} value={ephemeralKey.token}>
            Key <span className="font-mono text-xs">{ephemeralKey.id}</span> for {ephemeralKey.subject} expires {formatDate(ephemeralKey.expires_at)}. Scopes:{" "}
            {ephemeralKey.scopes.join(", ")}.
          </RevealPanel>
        )}
      </section>

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

      <section aria-labelledby="dynamic-secrets-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="dynamic-secrets-heading" className="text-title font-semibold">
            Dynamic secrets
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Issue a lease-scoped credential from a configured provider, renew its expiry when needed, or revoke it immediately. Generated credentials are shown
            once and then cleared from the page.
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
              {leaseBusy === "issue" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
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
            Transit operations keep key material server-side. This page base64-encodes local plaintext for the API, clears plaintext inputs after encrypt, and
            shows decrypted values only in a reveal panel.
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
              {transitBusy === "rewrap" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RotateCw className="h-4 w-4" aria-hidden="true" />}
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
                {transitBusy === "hmac" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                Compute HMAC
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => void signTransit()}
                disabled={transitBusy === "sign" || !transitMessage.trim() || Boolean(loadError)}
              >
                {transitBusy === "sign" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
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
    </section>
  );
}

function RevealPanel({ title, value, children, onDismiss }: { title: string; value: string; children: ReactNode; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copyValue() {
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(true);
    } catch {
      setCopied(true);
    }
  }
  return (
    <div className="ui-panel grid gap-3 p-3 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium">{title}</p>
          <p className="mt-1 text-muted-foreground">{children}</p>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
          <X className="h-4 w-4" aria-hidden="true" />
          Dismiss
        </Button>
      </div>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-muted px-3 py-2 font-mono text-xs">{value}</pre>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant="outline" onClick={() => void copyValue()}>
          <Copy className="h-4 w-4" aria-hidden="true" />
          Copy once
        </Button>
        {copied && <span className="text-xs text-muted-foreground">Copied from this reveal panel.</span>}
      </div>
    </div>
  );
}

function Snippet({ title, text }: { title: string; text: string }) {
  return (
    <div className="ui-panel grid gap-2 p-3 text-sm">
      <p className="font-medium">{title}</p>
      <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-muted px-3 py-2 font-mono text-xs">{text}</pre>
    </div>
  );
}

function MachineSession({ session }: { session: MachineLoginResponse }) {
  return (
    <dl className="ui-panel grid gap-2 p-3 text-sm md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">Session ID</dt>
        <dd className="break-all font-mono text-xs">{session.session_id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Principal</dt>
        <dd>{session.principal}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Method</dt>
        <dd>{session.method}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Expires</dt>
        <dd>{formatDate(session.expires_at)}</dd>
      </div>
      <div className="md:col-span-2">
        <dt className="font-medium text-muted-foreground">Scopes</dt>
        <dd>{session.scopes.join(", ") || "No scopes"}</dd>
      </div>
    </dl>
  );
}

function DynamicLeaseMetadata({ lease }: { lease: DynamicLease }) {
  return (
    <dl className="grid gap-2 md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">Lease ID</dt>
        <dd className="break-all font-mono text-xs">{lease.id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">State</dt>
        <dd>{lease.state}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Provider</dt>
        <dd>{lease.provider}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Role</dt>
        <dd>{lease.role}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Issued</dt>
        <dd>{formatDate(lease.issued_at)}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Expires</dt>
        <dd>{formatDate(lease.expires_at)}</dd>
      </div>
    </dl>
  );
}

function RepositoryScanPosture({ posture }: { posture: SecretRepositoryScanPosture }) {
  const { t } = useTranslation();
  return (
    <div className="ui-panel grid gap-3 p-comfortable text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md bg-status-success/10 px-2 py-1 font-mono text-xs text-status-success">{posture.capability}</span>
        <span className="font-medium">{posture.served ? t("secrets.repoScan.active") : t("secrets.repoScan.unavailable")}</span>
        <span className="text-muted-foreground">{t("secrets.repoScan.ruleFloor", { scanner: posture.scanner, rules: posture.minimum_rules_active })}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="ui-table min-w-[52rem]">
          <caption className="sr-only">{t("secrets.repoScan.providerCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("secrets.repoScan.provider")}</th>
              <th scope="col">{t("secrets.repoScan.triggers")}</th>
              <th scope="col">{t("secrets.repoScan.ingress")}</th>
              <th scope="col">{t("secrets.repoScan.outbox")}</th>
            </tr>
          </thead>
          <tbody>
            {posture.providers.map((provider) => (
              <tr key={provider.id} className="align-top">
                <td className="font-medium">{provider.name}</td>
                <td>{provider.realtime_triggers.join(", ")}</td>
                <td>{provider.ingest_mode}</td>
                <td>{provider.outbox_mode}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl className="grid gap-3 md:grid-cols-2">
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.webhookPaths")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.webhook_paths.map((path) => (
              <span key={path}>{path}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.eventFlow")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.event_flow.map((event) => (
              <span key={event}>{event}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.releaseGates")}</dt>
          <dd className="mt-1">{posture.release_gates.map((gate) => gate.id).join(", ")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.residuals")}</dt>
          <dd className="mt-1">{posture.residuals.join(" ")}</dd>
        </div>
      </dl>
    </div>
  );
}

function ThirdPartyScanPosture({ posture }: { posture: ThirdPartySecretScanPosture }) {
  const { t } = useTranslation();
  return (
    <div className="ui-panel grid gap-3 p-comfortable text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md bg-status-success/10 px-2 py-1 font-mono text-xs text-status-success">{posture.capability}</span>
        <span className="font-medium">{posture.served ? t("secrets.thirdPartyScan.active") : t("secrets.thirdPartyScan.unavailable")}</span>
        <span className="text-muted-foreground">{t("secrets.repoScan.ruleFloor", { scanner: posture.scanner, rules: posture.minimum_rules_active })}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="ui-table min-w-[52rem]">
          <caption className="sr-only">{t("secrets.thirdPartyScan.providerCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("secrets.repoScan.provider")}</th>
              <th scope="col">{t("secrets.thirdPartyScan.artifactKinds")}</th>
              <th scope="col">{t("secrets.repoScan.ingress")}</th>
              <th scope="col">{t("secrets.repoScan.outbox")}</th>
            </tr>
          </thead>
          <tbody>
            {posture.providers.map((provider) => (
              <tr key={provider.id} className="align-top">
                <td className="font-medium">{provider.name}</td>
                <td>{provider.artifact_kinds.join(", ")}</td>
                <td>{provider.ingest_mode}</td>
                <td>{provider.outbox_mode}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <dl className="grid gap-3 md:grid-cols-2">
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.thirdPartyScan.ingestPaths")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.ingest_paths.map((path) => (
              <span key={path}>{path}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.eventFlow")}</dt>
          <dd className="mt-1 grid gap-1 font-mono text-xs">
            {posture.event_flow.map((event) => (
              <span key={event}>{event}</span>
            ))}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.releaseGates")}</dt>
          <dd className="mt-1">{posture.release_gates.map((gate) => gate.id).join(", ")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("secrets.repoScan.residuals")}</dt>
          <dd className="mt-1">{posture.residuals.join(" ")}</dd>
        </div>
      </dl>
    </div>
  );
}

function SecretApprovalQueue({
  items,
  busyKey,
  canRetry,
  onApprove,
  onRetry,
}: {
  items: SecretApprovalQueueItem[];
  busyKey: string | null;
  canRetry: (item: SecretApprovalQueueItem) => boolean;
  onApprove: (item: SecretApprovalQueueItem) => void;
  onRetry: (item: SecretApprovalQueueItem) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="ui-panel grid gap-3 p-comfortable">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-title font-semibold">{t("secrets.approvals.heading")}</h3>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.approvals.description")}</p>
        </div>
        <span className="rounded-control border border-border px-2.5 py-1 text-xs font-semibold text-muted-foreground">{t("secrets.approvals.badge")}</span>
      </div>
      {items.length === 0 ? (
        <p className="rounded-control border border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">{t("secrets.approvals.empty")}</p>
      ) : (
        <div className="grid gap-2" role="list" aria-label={t("secrets.approvals.listLabel")}>
          {items.map((item) => {
            const approveBusy = busyKey === `${item.id}:approve`;
            const retryBusy = busyKey === `${item.id}:retry`;
            const retryReady = canRetry(item);
            const actionLabel = secretApprovalActionLabel(item.action, t);
            return (
              <article key={item.id} role="listitem" className="grid gap-3 rounded-md border border-border bg-background p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="font-medium">
                      {actionLabel} - {item.name}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {t("secrets.approvals.openedStatus", { openedAt: formatDate(item.openedAt), status: secretApprovalStatusLabel(item, t) })}
                    </p>
                  </div>
                  <span className="rounded-control border border-border px-2 py-1 text-xs font-semibold text-muted-foreground">{item.status}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    aria-label={t("secrets.approvals.approveAction", { action: actionLabel, name: item.name })}
                    disabled={approveBusy || retryBusy || item.status === "completed"}
                    onClick={() => onApprove(item)}
                  >
                    {approveBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <ShieldCheck className="h-4 w-4" aria-hidden="true" />}
                    {t("secrets.approvals.approve")}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    disabled={approveBusy || retryBusy || !retryReady}
                    aria-label={t("secrets.approvals.retryAction", { action: actionLabel, name: item.name })}
                    onClick={() => onRetry(item)}
                  >
                    {retryBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <PlayCircle className="h-4 w-4" aria-hidden="true" />}
                    {t("secrets.approvals.retry")}
                  </Button>
                </div>
                {item.error && <ErrorState title={t("secrets.approvals.errorTitle")}>{item.error}</ErrorState>}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

function defaultThirdPartyProviders(): ThirdPartySecretScanPosture["providers"] {
  return [
    { id: "cicd_log", name: "CI/CD logs", artifact_kinds: ["ci_cd_log"], ingest_mode: "", secret_handling: "", outbox_mode: "" },
    {
      id: "container_registry",
      name: "Container registry exports",
      artifact_kinds: ["container_registry_export"],
      ingest_mode: "",
      secret_handling: "",
      outbox_mode: "",
    },
    { id: "slack", name: "Slack exports", artifact_kinds: ["slack_export"], ingest_mode: "", secret_handling: "", outbox_mode: "" },
    { id: "jira", name: "Jira exports", artifact_kinds: ["jira_export"], ingest_mode: "", secret_handling: "", outbox_mode: "" },
  ];
}

function secretApprovalQueueID(action: SecretApprovalAction, name: string): string {
  return `${action}:${name}`;
}

function secretApprovalActionLabel(action: SecretApprovalAction, t: Translate): string {
  switch (action) {
    case "rotate":
      return t("secrets.approvals.actionRotate");
    case "recover":
      return t("secrets.approvals.actionRecover");
    case "delete":
      return t("secrets.approvals.actionDelete");
  }
}

function secretApprovalStatusLabel(item: SecretApprovalQueueItem, t: Translate): string {
  if (item.status === "completed") return t("secrets.approvals.statusCompleted");
  if (item.status === "approved") {
    if (item.approver && item.approvals != null) return t("secrets.approvals.statusApprovedWithCount", { approver: item.approver, count: item.approvals });
    if (item.approver) return t("secrets.approvals.statusApprovedBy", { approver: item.approver });
    return t("secrets.approvals.statusApproved");
  }
  return item.approvals != null ? t("secrets.approvals.statusCount", { count: item.approvals }) : t("secrets.approvals.statusAwaiting");
}

function mergeMeta(current: SecretMeta[], incoming: SecretMeta[]): SecretMeta[] {
  const byName = new Map(current.map((item) => [item.name, item]));
  for (const item of incoming) byName.set(item.name, item);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function leaseMetadataOnly(lease: DynamicLease): DynamicLease {
  const metadata = { ...lease };
  delete metadata.credential;
  return metadata;
}

function formatDate(value?: string): string {
  if (!value) return "-";
  return formatDateTimePolicy(value);
}

function parseScopeList(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function encodeTransitBytes(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeTransitBytes(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s`;
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
